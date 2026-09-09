"""Explicit GHCR publication of locally built immutable images."""

import json
from pathlib import Path
import re

from .protocol import read_json, write_json
from .runtime import image_check, input_binding


def publish(root, directory, metadata, manifest_path, repository, commands):
    if not re.fullmatch(r"ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9/._-]*", repository):
        raise ValueError("Repository must be a lowercase ghcr.io/owner/package path without tag")
    manifest = read_json(Path(manifest_path))
    binding = input_binding(root, directory, metadata)
    if manifest.get("environment_id") != metadata["id"] or manifest.get("input_binding") != binding:
        raise ValueError("Build manifest is stale or belongs to another environment")
    published = {}
    for variant in ("vulnerable", "patched"):
        image = manifest["images"][variant]
        image_check(commands, image, directory, metadata, variant, binding)
        tag = f"{repository}:{variant}-{binding[:16]}"
        commands.run(["docker", "tag", image, tag], "tag")
        commands.run(["docker", "push", tag], "push")
        _, content = commands.run(["docker", "image", "inspect", tag], "image_inspect")
        digests = json.loads(content)[0].get("RepoDigests", [])
        matches = [value for value in digests if value.startswith(repository + "@sha256:")]
        if len(matches) != 1:
            raise ValueError("Cannot determine unambiguous published digest")
        published[variant] = matches[0]
        write_json(commands.output / "publication.json", {"environment_id": metadata["id"],
                   "input_binding": binding, "images": published})
    return published
