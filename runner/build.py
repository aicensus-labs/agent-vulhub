"""Hash-checked source cache and local immutable image builds."""

import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.parse
import urllib.request

from .protocol import HASH, IMAGE, check_fixtures, contained, digest, write_json
from .runtime import RunError, image_check, input_binding


def validate_sources(directory, metadata):
    build = metadata.get("build", {})
    if not IMAGE.fullmatch(build.get("base_image", "")):
        raise ValueError("build.base_image must include a digest")
    files = build.get("inputs", [])
    if not isinstance(files, list) or not files:
        raise ValueError("build.inputs must include source archives and dependencies")
    names = set()
    for item in files:
        if not isinstance(item, dict) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", item.get("name", "")):
            raise ValueError("Build input needs a simple filename")
        if item["name"] in names or not HASH.fullmatch(item.get("sha256", "")):
            raise ValueError("Duplicate input name or missing SHA-256")
        names.add(item["name"])
        if urllib.parse.urlparse(item.get("url", "")).scheme != "https":
            raise ValueError("Build inputs require HTTPS URLs")
    for variant in ("vulnerable", "patched"):
        entry = metadata[variant]
        if not re.fullmatch(r"[0-9a-f]{40}", entry.get("commit", "")):
            raise ValueError(f"{variant}: full source commit required")
        archive = entry.get("archive", "")
        if archive not in names:
            raise ValueError(f"{variant}: archive must name a build input")
    dockerfile = contained(directory, build.get("dockerfile", "Dockerfile"))
    text = dockerfile.read_text()
    for line in text.splitlines():
        match = re.match(r"\s*FROM\s+(\S+)", line, re.I)
        if match and match[1] != "${BASE_IMAGE}":
            raise ValueError("Build recipe must use FROM ${BASE_IMAGE}; one pinned base per recipe")
        if re.match(r"\s*(ADD|VOLUME)\s", line, re.I):
            raise ValueError("ADD and VOLUME are unsupported; use local COPY and managed volumes")
    if "FROM ${BASE_IMAGE}" not in text:
        raise ValueError("Missing pinned base image declaration")
    check_fixtures(directory)
    return files


def fetch_inputs(root, directory, metadata, offline=False):
    inputs = validate_sources(directory, metadata)
    cache = root / ".cache" / "sha256"
    cache.mkdir(parents=True, exist_ok=True)
    result = {}
    for item in inputs:
        path = cache / item["sha256"]
        if path.is_symlink():
            raise ValueError("Symlink cache entry")
        if not path.exists():
            if offline:
                raise RunError("fetch", f"Offline cache miss: {item['name']}", 2, "not_run")
            request = urllib.request.Request(item["url"], headers={"User-Agent": "agent-vulhub/1"})
            with urllib.request.urlopen(request, timeout=60) as response, tempfile.NamedTemporaryFile(dir=cache) as stream:
                if urllib.parse.urlparse(response.url).scheme != "https":
                    raise ValueError("Source redirect downgraded HTTPS")
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > 2 * 1024**3:
                        raise ValueError("Build input exceeds 2 GiB")
                    stream.write(chunk)
                stream.flush()
                if digest(stream.name) != item["sha256"]:
                    raise ValueError(f"Download hash mismatch: {item['name']}")
                shutil.copyfile(stream.name, path)
        if digest(path) != item["sha256"]:
            raise ValueError(f"Cache hash mismatch: {item['name']}")
        result[item["name"]] = path
    return result


def build_images(root, directory, metadata, commands, offline=False):
    inputs = fetch_inputs(root, directory, metadata, offline)
    binding = input_binding(root, directory, metadata)
    base = metadata["build"]["base_image"]
    if not offline:
        commands.run(["docker", "pull", "--platform", "linux/amd64", base], "pull")
    else:
        commands.run(["docker", "image", "inspect", base], "preflight")
    images = {}
    with tempfile.TemporaryDirectory(prefix="avh-build-") as temporary:
        context = Path(temporary)
        for source in directory.rglob("*"):
            relative = source.relative_to(directory)
            if relative.parts[0] in {"evidence", "results", "__pycache__", ".cache", ".git"}:
                continue
            if relative.parts[0] == ".env" or (relative.parts[0].startswith(".env.") and relative.parts[0] != ".env.example"):
                continue
            if source.is_symlink():
                raise ValueError("Build context cannot contain symlinks")
            if source.is_file() and not source.name.startswith("metadata.toml"):
                target = context / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        (context / "inputs").mkdir(exist_ok=True)
        for name, source in inputs.items():
            shutil.copyfile(source, context / "inputs" / name)
        for variant in ("vulnerable", "patched"):
            iid = commands.output / f"{variant}.iid"
            args = ["docker", "build", "--platform", "linux/amd64", "--network", "none", "--pull=false",
                    "--iidfile", str(iid), "-f", str(context / metadata["build"].get("dockerfile", "Dockerfile"))]
            for key, value in {"BASE_IMAGE": base, "VARIANT": variant,
                               "SOURCE_COMMIT": metadata[variant]["commit"],
                               "SOURCE_ARCHIVE": metadata[variant]["archive"]}.items():
                args += ["--build-arg", f"{key}={value}"]
            args += ["--label", f"org.opencontainers.image.revision={metadata[variant]['commit']}",
                     "--label", f"org.agent-vulhub.inputs={binding}", str(context)]
            commands.run(args, "build", timeout=commands.timeout)
            images[variant] = iid.read_text().strip()
            image_check(commands, images[variant], directory, metadata, variant, binding)
    write_json(commands.output / "build.json", {"schema_version": 1, "environment_id": metadata["id"],
               "input_binding": binding, "images": images,
               "inputs": {k: digest(v) for k, v in inputs.items()}})
    return images
