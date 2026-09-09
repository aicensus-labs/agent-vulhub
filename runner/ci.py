"""Trusted-branch entry for the protected ephemeral-VM workflow."""

import os

from .cli import ROOT, load_registry, main, read_toml


def run():
    selected = os.environ.get("AVH_ENVIRONMENT", "")
    ids = []
    for entry in load_registry(ROOT):
        data = read_toml(ROOT / entry["path"] / "metadata.toml")
        if (selected and entry["id"] == selected) or (not selected and data["lifecycle"] == "ready"):
            ids.append(entry["id"])
    if selected and not ids:
        print(f"Unknown environment: {selected}")
        return 2
    if not ids:
        print("No ready environments selected; no containers started")
        return 0
    code = 0
    for identity in ids:
        args = ["reproduce", identity, "--rounds", "3", "--timeout", "600"]
        if os.environ.get("AVH_FROM_SOURCE", "true") == "true":
            args.append("--build")
        code = max(code, main(args))
    return code


if __name__ == "__main__":
    raise SystemExit(run())
