#!/usr/bin/env python3
"""Unpack the pinned OpenClaw npm closure into an offline ``node_modules`` tree.

This runs inside the build container with ``--network none``. It never invokes
npm/pnpm and never resolves a registry: every tarball is one of the
``metadata.toml`` build inputs, already fetched and SHA-256 verified by the
runner, and this script re-verifies each digest before extracting it.

The layout follows npm's own resolution rules (hoist to the root when the name
is still free, otherwise nest below the conflicting level) so the tree is
correct without pnpm's symlink store. Package versions and edges are copied
verbatim from the pinned ``pnpm-lock.yaml`` snapshot graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_tarball(archive: Path, destination: Path) -> None:
    """Extract an npm tarball (whose members live under ``package/``)."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            # npm tarballs only use links for bin shims; the JS entrypoints this
            # build needs are regular files, so every link is skipped.
            if not member.isfile():
                continue
            parts = member.name.split("/")
            if len(parts) < 2 or parts[0] != "package":
                continue
            relative = Path(*parts[1:])
            if not str(relative) or relative.is_absolute():
                continue
            target = (destination / relative).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"archive member escapes destination: {member.name}")
            stream = tar.extractfile(member)
            if stream is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with stream, target.open("wb") as handle:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    handle.write(chunk)
            # No package lifecycle script runs, so the archive's own mode is
            # what keeps prebuilt binaries (esbuild, sharp) executable.
            os.chmod(target, member.mode & 0o777)


class Installer:
    def __init__(self, manifest: dict, inputs: Path, node_modules: Path) -> None:
        self.packages: dict[str, dict] = manifest["packages"]
        self.inputs = inputs
        self.root = node_modules
        self.extracted: set[tuple[str, str]] = set()
        # node_modules directory -> {package name: version placed there}
        self.placements: dict[Path, dict[str, str]] = {}
        # (node_modules directory, name) -> version, i.e. created package dirs
        self.created: set[tuple[Path, str]] = set()
        self.bytes = 0

    def archive_for(self, name: str, version: str) -> Path:
        key = f"{name}@{version}"
        if key not in self.packages:
            raise KeyError(f"package not in pinned closure: {key}")
        entry = self.packages[key]
        path = self.inputs / entry["archive"]
        if not path.is_file():
            raise FileNotFoundError(f"missing build input: {path}")
        digest = sha256_file(path)
        if digest != entry["sha256"]:
            raise ValueError(
                f"build input hash mismatch for {entry['archive']}: "
                f"expected {entry['sha256']}, got {digest}"
            )
        return path

    def place(self, import_name: str, package_name: str, version: str,
              chain: list[Path]) -> None:
        """Ensure ``import_name`` resolves to ``package_name@version`` for a
        dependent whose visible node_modules chain is ``chain`` (shallowest
        first). The two names differ only for npm alias dependencies."""
        found_index = None
        found_version = None
        for index in range(len(chain) - 1, -1, -1):
            placed = self.placements.get(chain[index], {})
            if import_name in placed:
                found_index = index
                found_version = placed[import_name]
                break
        if found_version == version:
            return
        if found_index is None:
            location = chain[0]
            new_chain = [location, location / import_name / "node_modules"]
        else:
            # A conflicting version sits at chain[found_index]; the only place
            # deeper than it that this dependent controls is its own
            # node_modules (the tail of the chain).
            location = chain[-1]
            new_chain = chain + [location / import_name / "node_modules"]
        self.placements.setdefault(location, {})[import_name] = version
        package_dir = location / import_name
        if (location, import_name) in self.created:
            return
        self.created.add((location, import_name))
        entry = self.packages[f"{package_name}@{version}"]
        # Extraction is per destination directory: the same version can be
        # needed at several nesting levels and each location needs real files.
        extract_tarball(self.archive_for(package_name, version), package_dir)
        self.extracted.add((package_name, version))
        for dep_name, dep in sorted(entry.get("dependencies", {}).items()):
            self.place(dep_name, dep["package"], dep["version"], new_chain)

    def run(self, seeds: list[dict]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            self.place(seed["name"], seed["name"], seed["version"], [self.root])
        # tsx is invoked by its JS entrypoint; expose the conventional bin too.
        bin_dir = self.root / ".bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        tsx_cli = self.root / "tsx" / "dist" / "cli.mjs"
        link = bin_dir / "tsx"
        if tsx_cli.is_file() and not link.exists():
            link.symlink_to(Path("..") / "tsx" / "dist" / "cli.mjs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--dest", required=True, type=Path,
                        help="node_modules directory to populate")
    parser.add_argument("--variant", required=True, choices=("vulnerable", "patched"))
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    installer = Installer(manifest, args.inputs, args.dest)
    installer.run(manifest["seeds"])
    print(
        f"installed {len(installer.created)} package directories "
        f"({len(installer.extracted)} tarballs) for variant {args.variant}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
