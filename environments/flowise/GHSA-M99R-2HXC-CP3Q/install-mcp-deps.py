#!/usr/bin/env python3
"""Materialize the locked npm closure of the MCP runtime with no network.

The published ``flowise-components`` build is installed straight from its
registry tarball, and every transitive dependency is unpacked into the exact
``node_modules`` path recorded by the pinned ``package-lock.json`` (lockfile
version 3 lists those paths verbatim), so npm itself never has to resolve or
fetch anything.  Every tarball is verified against the SHA-256 that
``metadata.toml`` pins before it is unpacked.

Usage (inside the image build):

    python3 install-mcp-deps.py --manifest mcp-deps-manifest.json \
        --inputs /inputs --dest /lab/mcp \
        --package-tarball /tmp/fc.tgz \
        --package-dir node_modules/flowise-components

``--package-dir`` is relative to ``--dest``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def extract_package(tarball: Path, destination: Path) -> None:
    """Unpack an npm tarball, dropping its leading ``package/`` component."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive:
            parts = member.name.split("/")
            if len(parts) < 2 or parts[0] != "package":
                continue
            rest = parts[1:]
            if not rest or ".." in rest:
                continue
            relative = "/".join(part for part in rest if part not in ("", "."))
            if not relative:
                continue
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink() or target.exists():
                    target.unlink()
                os.symlink(member.linkname, target)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise SystemExit(f"unreadable member: {member.name}")
                with target.open("wb") as out:
                    shutil.copyfileobj(source, out)
                os.chmod(target, member.mode & 0o777)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--dest", required=True, help="directory owning node_modules")
    parser.add_argument("--package-tarball", required=True,
                        help="the variant's published flowise-components tarball")
    parser.add_argument("--package-dir", required=True,
                        help="install path for the published package, relative to --dest")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    inputs = Path(args.inputs)
    dest = Path(args.dest)

    verified: set[str] = set()
    for entry in manifest["dependencies"]:
        tarball = inputs / entry["input"]
        if entry["input"] not in verified:
            if not tarball.is_file():
                raise SystemExit(f"missing build input: {tarball}")
            actual = sha256(tarball)
            if actual != entry["sha256"]:
                raise SystemExit(f"input hash mismatch: {entry['input']} {actual}")
            verified.add(entry["input"])
        target = dest / entry["path"]
        if (target / "package.json").is_file():
            continue
        extract_package(tarball, target)

    extract_package(Path(args.package_tarball), dest / args.package_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
