"""Remove untagged GHCR package versions left behind by publication.

A container push registers the manifest plus its attestation and provenance
manifests as separate package versions. Only the image manifest carries the
``{variant}-{binding[:16]}`` tag, so a single ``runner publish`` leaves several
untagged versions per environment. Left alone they accumulate linearly with the
number of environments, which matters once the registry holds hundreds of them.

Untagged versions are safe to remove: nothing references them, and deleting a
version does not remove blobs still shared with a tagged one. Tagged versions
are never touched, so the digests recorded in ``metadata.toml`` stay valid.
"""

import json
import re
import subprocess

REPOSITORY = re.compile(r"ghcr\.io/([a-z0-9][a-z0-9._-]*)/([a-z0-9][a-z0-9/._-]*)")


def _gh(args, timeout):
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)


def _endpoint(owner, package):
    """Users and organizations expose packages through different endpoints."""
    probe = _gh(["api", f"users/{owner}"], timeout=60)
    if probe.returncode == 0:
        try:
            kind = json.loads(probe.stdout).get("type")
        except json.JSONDecodeError:
            kind = None
        if kind == "User":
            return f"users/{owner}/packages/container/{package}"
    return f"orgs/{owner}/packages/container/{package}"


def prune(repository, apply_changes=False, timeout=120):
    """Delete untagged versions of ``repository`` and report what was found."""
    match = REPOSITORY.fullmatch(repository)
    if not match:
        raise ValueError("Repository must be a lowercase ghcr.io/owner/package path without tag")
    owner, package = match.groups()
    endpoint = _endpoint(owner, package)

    listed = _gh(["api", f"{endpoint}/versions?per_page=100"], timeout=timeout)
    if listed.returncode != 0:
        raise ValueError(f"Cannot list package versions: {listed.stderr.strip()}")
    try:
        versions = json.loads(listed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"Cannot parse package versions: {error}") from error

    tagged, untagged = [], []
    for version in versions:
        tags = ((version.get("metadata") or {}).get("container") or {}).get("tags") or []
        (tagged if tags else untagged).append(version)

    deleted, failures = [], []
    for version in untagged:
        if not apply_changes:
            deleted.append(version["id"])
            continue
        removed = _gh(["api", "--method", "DELETE", f"{endpoint}/versions/{version['id']}"], timeout=timeout)
        if removed.returncode == 0:
            deleted.append(version["id"])
        else:
            failures.append((version["id"], removed.stderr.strip()))

    return {"repository": repository, "endpoint": endpoint, "applied": apply_changes,
            "tagged": len(tagged), "untagged": len(untagged),
            "deleted": deleted, "failures": failures}
