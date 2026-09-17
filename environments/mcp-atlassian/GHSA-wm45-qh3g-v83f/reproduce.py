"""Exercise the real MCP Atlassian upload method with a local Jira double."""

import builtins
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

from lab_support import parser, read_context, record


class _Jira:
    def __init__(self):
        self.calls = []

    def add_attachment(self, **kwargs):
        self.calls.append(kwargs)
        return {"id": "synthetic-attachment"}


def _load_module(source: Path):
    """Import the complete attachment module with protocol collaborators."""
    package_root = source.parents[2]
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

    # Load only the target module from the complete source tree. Its base
    # client, API model, and protocol are dependency boundaries for this
    # mechanism and are represented by narrow protocol doubles; the target
    # upload implementation and the upstream path validator remain real.
    for name, path in (
        ("mcp_atlassian", package_root / "mcp_atlassian"),
        ("mcp_atlassian.jira", package_root / "mcp_atlassian" / "jira"),
        ("mcp_atlassian.models", package_root / "mcp_atlassian" / "models"),
        ("mcp_atlassian.utils", package_root / "mcp_atlassian" / "utils"),
    ):
        package = types.ModuleType(name)
        package.__path__ = [str(path)]
        package.__package__ = name
        sys.modules[name] = package

    client_module = types.ModuleType("mcp_atlassian.jira.client")
    client_module.JiraClient = type("JiraClient", (), {})
    sys.modules[client_module.__name__] = client_module

    protocols_module = types.ModuleType("mcp_atlassian.jira.protocols")
    protocols_module.AttachmentsOperationsProto = type(
        "AttachmentsOperationsProto", (), {}
    )
    sys.modules[protocols_module.__name__] = protocols_module

    models_module = types.ModuleType("mcp_atlassian.models.jira")
    models_module.JiraAttachment = type("JiraAttachment", (), {})
    sys.modules[models_module.__name__] = models_module

    env_module = types.ModuleType("mcp_atlassian.utils.env")
    env_module.is_env_extended_truthy = lambda _name, default: default.lower() == "true"
    sys.modules[env_module.__name__] = env_module
    io_source = source.parents[1] / "utils" / "io.py"
    io_spec = importlib.util.spec_from_file_location(
        "mcp_atlassian.utils.io", io_source
    )
    if io_spec is None or io_spec.loader is None:
        raise ImportError(f"unable to load {io_source}")
    io_module = importlib.util.module_from_spec(io_spec)
    sys.modules[io_spec.name] = io_module
    io_spec.loader.exec_module(io_module)

    media_module = types.ModuleType("mcp_atlassian.utils.media")
    media_module.ATTACHMENT_MAX_BYTES = 8 * 1024 * 1024
    sys.modules[media_module.__name__] = media_module

    spec = importlib.util.spec_from_file_location(
        "mcp_atlassian.jira.attachments", source
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    fixture = json.loads(
        (Path("/lab/fixtures") / ("attack.json" if context["scenario"] == "attack" else "benign.json"))
        .read_text(encoding="utf-8")
    )
    workspace = Path("/lab/workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "allowed.txt").write_text("safe attachment canary\n", encoding="utf-8")
    os.chdir(workspace)
    opened = []
    original_open = builtins.open

    def tracking_open(file, *open_args, **open_kwargs):
        opened.append(str(Path(file).resolve()))
        return original_open(file, *open_args, **open_kwargs)

    source = Path("/lab/app/src/mcp_atlassian/jira/attachments.py")
    module = _load_module(source)
    module.open = tracking_open
    upload = module.AttachmentsMixin.upload_attachment
    jira = _Jira()
    client = object.__new__(module.AttachmentsMixin)
    client.jira = jira
    result = None
    error = None
    try:
        result = upload(client, "DEMO-1", fixture["file_path"])
    except Exception as exc:
        # A patched rejection is a completed product call, not an infrastructure failure.
        error = f"{type(exc).__name__}: {exc}"
    observation = {
        "execution_status": "completed",
        "target_ready": True,
        "cve": "GHSA-wm45-qh3g-v83f",
        "source": str(source),
        "requested_path": fixture["file_path"],
        "opened_paths": opened,
        "upload_calls": jira.calls,
        "result": result,
        "error": error,
    }
    return record(context, args.output, observation, {"jira_effect.json": json.dumps(observation, indent=2) + "\n"})


class _Logger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


if __name__ == "__main__":
    raise SystemExit(main())
