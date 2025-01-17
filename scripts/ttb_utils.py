# -*- mode: python; coding: utf-8 -*-
# Copyright 2020-2022 the Tectonic Project.
# Licensed under the MIT License.

"""
Utilities for the Tectonic bundler infrastructure.

Fixed characteristics of the environment:

- Source tree for the tools is in /source/
- Data/state directory is /state/
- TeXLive repository is in /state/repo/
- Bundle specification is in /bundle/
- The numeric UID and GID of the executing user in the host environment are
  stored in the environment variables $HOSTUID and $HOSTGID.

"""

__all__ = '''
Bundle
ZipMaker
chown_host
cpath2qhpath
die
get_repo_version
warn
'''.split()

import contextlib
import hashlib
import os.path
import toml
import shutil
import struct
import subprocess
import sys
import tempfile


def warn(text):
    print('warning:', text, file=sys.stderr)


def die(text):
    raise SystemExit(f'error: {text}')


def chown_host(path, recursive=True):
    uid = int(os.environ['HOSTUID'])
    gid = int(os.environ['HOSTGID'])

    os.chown(path, uid, gid)

    if not recursive:
        return

    for dirpath, dirnames, filenames in os.walk(path):
        for dname in dirnames:
            os.lchown(os.path.join(dirpath, dname), uid, gid)

        for fname in filenames:
            os.lchown(os.path.join(dirpath, fname), uid, gid)


def cpath2qhpath(container_path):
    "Container path to quoted host path."
    if container_path.startswith('/state/'):
        return f'`{container_path[1:]}`'

    return f'(container path) `{container_path}``'


def get_repo_version():
    """
    Returns (git-hash-as-hex-text, svn-revision)
    """

    subprocess.check_call(
        ['git', 'update-index', '-q', '--refresh'],
        cwd = '/state/repo',
    )

    output = subprocess.check_output(
        ['git', 'diff-index', '--name-only', 'HEAD', '--'],
        cwd = '/state/repo',
    )
    if len(output):
        raise Exception('refusing to work from a modified TeXLive Git checkout')

    output = subprocess.check_output(
        ['git', 'show-ref', '--head'],
        cwd = '/state/repo',
    )
    head_hash = output.split(b' ', 1)[0]
    head_hash = head_hash.decode('ascii')

    output = subprocess.check_output(
        ['git', 'show', '-s'],
        cwd = '/state/repo',
    )
    svn_rev = 'unknown'
    for line in output.splitlines():
        if b'git-svn-id:' in line:
            idx = line.index(b'@')
            line = line[idx+1:]
            svn_rev = line.split(b' ', 1)[0]
            svn_rev = svn_rev.decode('ascii')
            break

    return head_hash, svn_rev


class Bundle(object):
    cfg = None
    name = None
    version = None

    @classmethod
    def open_default(cls):
        inst = cls()

        with open('/bundle/bundle.toml', 'rt') as f:
            cfg = toml.load(f)

        inst.cfg = cfg
        inst.name = cfg['bundle']['name']
        inst.version = cfg['bundle']['version']

        return inst


    def path(self, *segments):
        return os.path.join('/bundle', *segments)


    def install_path(self, *segments):
        return os.path.join('/state/installs', f'{self.name}-{self.version}', *segments)


    def artifact_path(self, *segments):
        return os.path.join('/state/artifacts', f'{self.name}-{self.version}', *segments)


    def zip_path(self):
        return self.artifact_path(f'{self.name}-{self.version}.zip')


    def tar_path(self):
        return self.artifact_path(f'{self.name}-{self.version}.tar')


    def listing_path(self):
        return self.artifact_path(f'{self.name}-{self.version}.listing.txt')


    def digest_path(self):
        return self.artifact_path(f'{self.name}-{self.version}.sha256sum')


    def ensure_artfact_dir(self):
        path = self.artifact_path()
        os.makedirs(path, exist_ok=True)
        chown_host('/state/artifacts', recursive=False)
        chown_host(path)


    def vendor_pristine_path(self, basename):
        path = self.artifact_path('vendor-pristine')
        os.makedirs(path, exist_ok=True)
        chown_host('/state/artifacts', recursive=False)
        chown_host(path)
        return os.path.join(path, basename)


    @contextlib.contextmanager
    def create_texlive_profile(self):
        dest = self.install_path()

        with tempfile.NamedTemporaryFile(delete=False, mode='wt') as f:
            with open(self.path('tl-profile.txt'), 'rt') as template:
                for line in template:
                    line = line.replace('@dest@', dest)
                    print(line, file=f, end='')

            f.close()
            yield f.name


IGNORED_BASE_NAMES = set([
    '00readme.txt',
    'LICENSE.md',
    'Makefile',
    'README',
    'README.md',
    'ls-R',
])

IGNORED_EXTENSIONS = set([
    'fmt',
    'log',
    'lua',
    'mf',
    'pl',
    'ps',
])


class ZipMaker(object):
    def __init__(self, bundle, zip):
        self.bundle = bundle
        self.zip = zip
        self.item_shas = {}
        self.final_hexdigest = None
        self.clashes = {}  # basename => {digest => fullpath}

        self.ignored_tex_paths = set()

        with open(bundle.path('ignored-tex-paths.txt')) as f:
            for line in f:
                line = line.split('#')[0].strip()
                if len(line):
                    self.ignored_tex_paths.add(line)

        self.ignored_tex_path_prefixes = []

        with open(bundle.path('ignored-tex-path-prefixes.txt')) as f:
            for line in f:
                line = line.split('#')[0].strip()
                if len(line):
                    self.ignored_tex_path_prefixes.append(line)


    def consider_file(self, tex_path, base_name):
        """
        Consider adding the specified TeXLive file to the installation tree.
        This is where all the nasty hairy logic will accumulate that enables us
        to come out with a nice pretty tarball in the end.
        """

        if base_name in IGNORED_BASE_NAMES:
            return False

        ext_bits = base_name.split('.', 1)
        if len(ext_bits) > 1 and ext_bits[1] in IGNORED_EXTENSIONS:
            return False

        if tex_path in self.ignored_tex_paths:
            return False

        for pfx in self.ignored_tex_path_prefixes:
            if tex_path.startswith(pfx):
                return False

        return True


    def _walk_onerr(self, oserror):
        warn(f'error navigating installation tree: {oserror}')


    # Preliminaries: extracting any patched files. This helps us maintain the
    # vendor-pristine branch so that we can use Git's merging capabilities to
    # maintain long-lived patches against them.
    #
    # This is kind of a hack since we're not actually touching any Zip file
    # here!

    def extract_vendor_pristine(self):
        install_dir = self.bundle.install_path()

        # Figure out what we need to check for.

        patched_dir = self.bundle.path('patched')
        patched_basenames = frozenset(os.listdir(patched_dir))

        # Now walk the main tree, using the same logic as go(), but extracting
        # only the patched files.

        p = os.path.join(install_dir, 'texmf-dist')
        n = len(p) + 1
        done_basenames = set()
        print(f'Scanning {cpath2qhpath(p)} ...')

        for dirpath, _, filenames in os.walk(p, onerror=self._walk_onerr):
            for fn in filenames:
                if fn not in patched_basenames:
                    continue

                full = os.path.join(dirpath, fn)
                tex = full[n:]
                if not self.consider_file(tex, fn):
                    continue

                if fn in done_basenames:
                    warn(f'duplicated patched file `{fn}`; sticking with the first instance')
                    continue

                vp = self.bundle.vendor_pristine_path(fn)
                shutil.copy(full, vp)
                done_basenames.add(fn)

        print(f'Extracted {len(done_basenames)} files.')


    # Actually building the full Zip

    def add_file(self, full_path):
        base = os.path.basename(full_path)

        # Get the digest

        with open(full_path, 'rb') as f:
            contents = f.read()

        s = hashlib.sha256()
        s.update(contents)
        digest = s.digest()

        # OK, have we seen this before?

        prev_tuple = self.item_shas.get(base)

        if prev_tuple is None:
            # New basename, yay
            self.zip.writestr(base, contents)
            self.item_shas[base] = (digest, full_path)
        elif prev_tuple[0] != digest:
            # Already seen basename, and new contents :-(
            bydigest = self.clashes.setdefault(base, {})

            if not len(bydigest):
                # If this is the first duplicate, don't forget that we've seen
                # the file at least once before.
                bydigest[prev_tuple[0]] = [prev_tuple[1]]

            pathlist = bydigest.setdefault(digest, [])
            pathlist.append(full_path)


    def go(self):
        install_dir = self.bundle.install_path()

        # Add a couple of version files from the builder.

        p = os.path.join(install_dir, 'SVNREV')
        if os.path.exists(p):
            self.add_file(p)
        else:
            warn(f'expected but did not see the file `{p}`')

        p = os.path.join(install_dir, 'GITHASH')
        if os.path.exists(p):
            self.add_file(p)
        else:
            warn(f'expected but did not see the file `{p}`')

        # Add the extra files preloaded in the bundle

        extras_dir = self.bundle.path('extras')

        for name in os.listdir(extras_dir):
            self.add_file(os.path.join(extras_dir, name))

        # Add the patched files, and make sure not to overwrite them later.

        patched_dir = self.bundle.path('patched')
        patched_basenames = set()

        for name in os.listdir(patched_dir):
            self.add_file(os.path.join(patched_dir, name))
            patched_basenames.add(name)

        # Add the main tree.

        p = os.path.join(install_dir, 'texmf-dist')
        n = len(p) + 1
        print(f'Scanning {cpath2qhpath(p)} ...')

        for dirpath, _, filenames in os.walk(p, onerror=self._walk_onerr):
            for fn in filenames:
                if fn in patched_basenames:
                    continue

                full = os.path.join(dirpath, fn)
                tex = full[n:]
                if self.consider_file(tex, fn):
                    self.add_file(full)

        # Compute a hash of it all.

        print('Computing final hash ...')
        s = hashlib.sha256()
        s.update(struct.pack('>I', len(self.item_shas)))
        s.update(b'\0')

        for name in sorted(self.item_shas.keys()):
            s.update(name.encode('utf8'))
            s.update(b'\0')
            s.update(self.item_shas[name][0])

        self.final_hexdigest = s.hexdigest()
        self.zip.writestr('SHA256SUM', self.final_hexdigest)

        # Report clashes if needed

        if len(self.clashes):
            warn(f'{len(self.clashes)} clashing basenames were observed')

            report_path = self.bundle.artifact_path('clash-report.txt')
            warn(f'logging clash report to {cpath2qhpath(report_path)}')

            with open(report_path, 'wt') as f:
                for base in sorted(self.clashes.keys()):
                    print(f'{base}:', file=f)
                    bydigest = self.clashes[base]

                    for digest in sorted(bydigest.keys()):
                        print(f'  {digest.hex()[:8]}:', file=f)

                        for full in sorted(bydigest[digest]):
                            print(f'     {full[n:]}', file=f)

            chown_host(report_path)


    def write_listing(self, stream):
        for base in sorted(self.item_shas.keys()):
            print(base, file=stream)