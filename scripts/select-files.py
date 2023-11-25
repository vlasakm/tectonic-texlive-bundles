# -*- mode: python; coding: utf-8 -*-

"""
This script creates a tectonic zip bundle using a finished
texlive install and a bundle specification.
"""


# Tested with Python 3.11.5
#
# You shouldn't need a venv,
# these are all in stdlib
import sys
import zipfile
import hashlib
import struct
from pathlib import Path
import subprocess
import re
import shutil
from collections import defaultdict


# Bundle parameters
PATH_bundle = Path(sys.argv[1])


def get_var(varname):
    bundle_meta = PATH_bundle / "bundle.sh"
    p = subprocess.Popen(
        f"echo $(source {bundle_meta}; echo ${varname})",
        stdout=subprocess.PIPE,
        shell=True,
        executable="bash"
    )
    return p.stdout.readlines()[0].strip().decode("utf-8")

VAR_bundlename = get_var('bundle_name')


# Input paths
PATH_ignore  = PATH_bundle / "ignore"
PATH_extra   = PATH_bundle / "include"
PATH_install = Path(f"build/install/{VAR_bundlename}")
PATH_texlive = PATH_install / "texmf-dist"
PATH_kpsewhich = PATH_install / "bin/x86_64-linux/kpsewhich"

# Output paths
PATH_output  = Path(f"build/output/{VAR_bundlename}")
PATH_content = PATH_output / "content"


def file_digest(full_path: Path):
    with open(full_path, "rb") as f:
        return hashlib.sha256(f.read()).digest()


class FilePicker(object):
    def __init__(self):
        # Statistics for summary
        self.extra_count = 0 # Extra files added
        self.extra_conflict_count = 0 # Number of conflicting extra files (0, ideally)
        self.texlive_count = 0 # Number of files from texlive
        self.ignored_count = 0 # Number of texlive files ignored
        self.replaced_count = 0 # Number of texlive files replaced with extra files
        self.kpse_count = 0 # Number of texlive files found with kpsewhich
        self.kpse_tex_count = 0 # Number of texlive files found with kpsewhich with tex filetype
        self.omitted_count = 0 # Number of texlive files not found with kpsewhich and thus omitted

        # Keeps track of conflicting file names
        # { "basename": {
        #       b"digest": Path(fullpath)
        # }}
        self.clashes = {}

        self.output_paths = {}

        # Array of diff file paths in include dir.
        # Scanned at start of run, applied while running.
        # Map of "filename": Path(filename.diff)
        self.diffs = {}
        self.patch_applied_count = 0 # How many diffs we've applied

        # Length of "Patching (n)" string,
        # used only for pretty printing.
        self.print_len = 0

        # Load ignore patterns
        self.ignore_patterns = set()
        if PATH_ignore.is_file():
            with PATH_ignore.open("r") as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if len(line):
                        self.ignore_patterns.add(line)


    # Print and pad with spaces.
    # Used when printing info while adding files.
    def clearprint(self, string):
        l = len(string)
        if l < self.print_len:
            string += " "*l
        print(string)


    def consider_file(self, file):
        """
        Consider adding the specified TeXLive file to the installation tree.
        This is where all the nasty hairy logic will accumulate that enables us
        to come out with a nice pretty tarball in the end.
        """

        f = "/" / file.relative_to(PATH_texlive)

        for pattern in self.ignore_patterns:
            if re.fullmatch(pattern, str(f)):
                return False

        return True


    def find_with_kpse(self, file_name: str):
        try:
            p = subprocess.run([PATH_kpsewhich, "--engine=xetex", "--progname=xelatex", file_name], capture_output=True, check=True)
            self.kpse_count += 1
        except subprocess.CalledProcessError:
            # e.g. ibycus4.map was autodeduced as map file, but is in fact a tex file
            try:
                p = subprocess.run([PATH_kpsewhich, "--engine=xetex", "--progname=xelatex", "--format=tex", file_name], capture_output=True, check=True)
                self.kpse_tex_count += 1
            except subprocess.CalledProcessError:
                self.omitted_count += 1
                raise FileNotFoundError
        full_path = Path(p.stdout.decode('utf-8').rstrip())
        return full_path.relative_to(Path.cwd()) # .relative_to(PATH_texlive)


    def get_file_paths(self):
        # For each (base)name get the list of paths
        name_paths = defaultdict(list)
        for f in PATH_texlive.rglob("*"):
            if not f.is_file():
                continue

            if not self.consider_file(f):
                self.ignored_count += 1
                continue

            name_paths[f.name].append(f)

        return dict(name_paths)

    def resolve_paths(self, name_paths):
        # For each name choose the path we will use
        # Map of "filename": Path
        index = {}

        i = 0
        for name, paths in name_paths.items():
            if len(paths) == 1:
                path = paths[0]
            else:
                self.clashes[name] = paths
                try:
                    path = self.find_with_kpse(name)
                    if not self.consider_file(path):
                        continue
                except FileNotFoundError:
                    continue

            index[name] = path

        return index

    def add_file(self, full_path: Path):
        target_path = PATH_content
        if self.has_patch(full_path):
            target_path /= "patched" / Path(full_path.name)
        elif full_path.is_relative_to(PATH_texlive):
            target_path /= "texlive" / full_path.relative_to(PATH_texlive)
            self.texlive_count += 1
        elif full_path.is_relative_to(PATH_extra):
            target_path /= "include" / full_path.relative_to(PATH_extra)
        else:
            target_path /= "unknown" / Path(full_path.name)

        self.output_paths[full_path.name] = target_path.relative_to(PATH_content)
        target_path.parent.mkdir(parents = True, exist_ok=True)
        shutil.copyfile(full_path, target_path)

        # Apply patches and compute new hash
        if self.has_patch(target_path):
            self.apply_patch(target_path)
            pass

        return file_digest(target_path)


    def has_patch(self, file):
        return file.name in self.diffs

    # Apply a patch to `file`, if one is provided.
    # We need to copy `file` first, since patching to stdout is tricky.
    def apply_patch(self, file):
        if not self.has_patch(file):
            return False

        self.clearprint(f"Patching {file.name}")
        self.patch_applied_count += 1
        subprocess.run([
            "patch",
            "--quiet",
            "--no-backup",
            file,
            self.diffs[file.name]
        ])

        return True

    def add_extra_files(self, name_paths):
        extra_basenames = set()
        if PATH_extra.is_dir():
            for f in PATH_extra.rglob("*"):
                if not f.is_file():
                    continue
                if f.suffix == ".diff":
                    n = f.name[:-5] # Cut off ".diff"
                    if n in self.diffs:
                        print(f"Warning: included diff {f.name} has conflicts, ignoring")
                        continue
                    self.diffs[n] = f
                    continue
                if f.name in extra_basenames:
                    print(f"Warning: included file {f.name} has conflicts, ignoring")
                    self.extra_conflict_count += 1
                    continue

                if len(name_paths.get(f.name, [])) > 0:
                    self.replaced_count += 1

                name_paths[f.name] = [f]
                self.extra_count += 1
                extra_basenames.add(f.name)

    def go(self):
        # Get map from name to all possible file paths
        name_paths = self.get_file_paths()

        # Add our extra flies to name paths
        self.add_extra_files(name_paths)

        # Get map from name to source path
        index = self.resolve_paths(name_paths)

        # Copy files and hash them, get map from name to hash
        hashes = { name: self.add_file(path) for name, path in index.items()}

        print("Selecting files... Done! Summary is below.")
        print(f"\textra file conflicts: {self.extra_conflict_count}")
        print(f"\ttl files ignored:     {self.ignored_count}")
        print(f"\ttl files replaced:    {self.replaced_count}")
        print(f"\ttl filename clashes:  {len(self.clashes)}")
        print(f"\tresolved with kpse:   {self.kpse_count}")
        print(f"\tresolved with tex:    {self.kpse_tex_count}")
        print(f"\tunresolved:           {self.omitted_count}")
        print(f"\tdiffs applied/found:  {self.patch_applied_count}/{len(self.diffs)}")
        print( "\t===============================")
        print(f"\textra files added:    {self.extra_count}")
        print(f"\ttotal files:          {self.texlive_count+self.extra_count}")
        print("")

        if len(self.diffs) != self.patch_applied_count:
            print("Warning: not all diffs were applied")

        # Compute content hash
        s = hashlib.sha256()
        s.update(struct.pack(">I", len(hashes)))
        s.update(b"\0")
        for name, hash in sorted(hashes.items()):
            s.update(name.encode("utf8"))
            s.update(b"\0")
            s.update(hash)
        final_hexdigest = s.hexdigest()

        # Write bundle metadata
        with (PATH_content / "SHA256SUM").open("w") as f:
            f.write(final_hexdigest)
        if (PATH_install / "TEXLIVE-SHA256SUM").is_file():
            shutil.copyfile(
                PATH_install / "TEXLIVE-SHA256SUM",
                PATH_content / "TEXLIVE-SHA256SUM"
            )
        with (PATH_content / "INDEX").open("w") as f:
            for name, output_path in sorted(self.output_paths.items()):
                f.write(f"{name} {output_path}\n")



        # Write debug files

        # This is essentially a detailed version of SHA256SUM,
        # Good for detecting file differences between bundles
        with (PATH_output / "file-hashes").open("w") as f:
            f.write(f"{len(hashes)}\n")
            for name, hash in sorted(hashes.items()):
                f.write(name)
                f.write("\t")
                f.write(hash.hex())
                f.write("\n")


        with (PATH_output / "listing").open("w") as f:
            for name in sorted(index.keys()):
                f.write(name)
                f.write("\n")

        if len(self.clashes):
            print(f"Warning: {len(self.clashes)} file clashes were found.")
            print(f"Logging clash report to {PATH_output}/clash-report")

            with (PATH_output / "clash-report").open("w") as f:
                for name, paths in sorted(self.clashes.items()):
                    f.write(f"{name}:\n")

                    for path in paths:
                        f.write(f"    {path}\n")

                    chosen_path = index.get(name, "OMITTED")
                    f.write(f" -> {chosen_path}\n\n")




if __name__ == "__main__":
    b = FilePicker()
    b.go()