"""Docker orchestration with bounded commands and per-case evidence directories."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import uuid

from .compose import validate_compose
from .protocol import (CASES, IMAGE, IMAGE_ID, SCHEMA, check_fixtures, fingerprint,
                       read_json, runner_fingerprint, validate_verdict, write_json)


class RunError(Exception):
    def __init__(self, phase, actual, code=3, status="infrastructure_error", expected="command completes successfully"):
        super().__init__(actual)
        self.phase, self.actual, self.code, self.status, self.expected = phase, actual, code, status, expected


def utc():
    return datetime.now(timezone.utc).isoformat()


class Commands:
    def __init__(self, output, timeout=120):
        self.output = output
        self.timeout = timeout
        self.sequence = 0
        self.deadline = None

    def run(self, args, phase, cwd=None, env=None, accepted=(0,), timeout=None):
        self.sequence += 1
        prefix = self.output / f"{self.sequence:04d}-{phase}"
        prefix.parent.mkdir(parents=True, exist_ok=True)
        seconds = timeout or self.timeout
        if self.deadline is not None:
            seconds = min(seconds, max(0.01, self.deadline - time.monotonic()))
        try:
            with prefix.with_suffix(".stdout.log").open("w") as stdout, prefix.with_suffix(".stderr.log").open("w") as stderr:
                result = subprocess.run(args, cwd=cwd, env=env, stdout=stdout, stderr=stderr, timeout=seconds, check=False)
        except FileNotFoundError as error:
            raise RunError(phase, str(error), 2, "not_run") from error
        except subprocess.TimeoutExpired as error:
            raise RunError(phase, f"Exceeded {seconds:.1f}s; see {prefix.name} logs", 3, "timeout") from error
        if result.returncode not in accepted:
            status = {"healthcheck": "healthcheck_failed", "compose_up": "startup_failed",
                      "preflight": "not_run", "cleanup": "cleanup_failed"}.get(phase, "infrastructure_error")
            raise RunError(phase, f"Exit {result.returncode}; see {prefix.name} logs",
                           2 if phase == "preflight" else 3, status)
        output = prefix.with_suffix(".stdout.log")
        if output.stat().st_size > 8 * 1024 * 1024:
            raise RunError(phase, "Command output exceeds 8 MiB")
        return result.returncode, output.read_text(errors="replace")


def compose_env(images):
    # Do not interpolate host secrets, COMPOSE_FILE, profiles or .env into experiments.
    env = {k: v for k, v in os.environ.items() if k in {
        "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "XDG_RUNTIME_DIR"}}
    env.update({"VULNERABLE_IMAGE": images["vulnerable"], "PATCHED_IMAGE": images["patched"],
                "COMPOSE_DISABLE_ENV_FILE": "true"})
    return env


def preflight(commands):
    _, version = commands.run(["docker", "version", "--format", "{{json .}}"], "preflight")
    data = json.loads(version)
    if not data.get("Server"):
        raise RunError("preflight", "Docker daemon unavailable", 2, "not_run")
    _, compose = commands.run(["docker", "compose", "version", "--short"], "preflight")
    _, info = commands.run(["docker", "info", "--format", "{{json .}}"], "preflight")
    info = json.loads(info)
    server = data["Server"]
    return {"docker_version": server["Version"], "compose_version": compose.strip(),
            "platform": f"{server['Os']}/{server['Arch']}", "host_system": platform.system(),
            "docker_operating_system": info.get("OperatingSystem", ""),
            "host_architecture": platform.machine()}


def image_check(commands, image, directory, metadata, variant, binding):
    try:
        _, content = commands.run(["docker", "image", "inspect", image], "image_inspect")
    except RunError as error:
        # An immutable metadata image that is not cached is a missing prerequisite.
        raise RunError("image_inspect", f"{variant}: immutable image is unavailable locally", 2, "not_run",
                       "immutable image is present and inspectable") from error
    data = json.loads(content)[0]
    labels = data.get("Config", {}).get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != metadata[variant]["commit"]:
        raise RunError("image_inspect", f"{variant}: source revision label mismatch", 2, "not_run")
    if labels.get("org.agent-vulhub.inputs") != binding:
        raise RunError("image_inspect", f"{variant}: build inputs fingerprint mismatch", 2, "not_run")
    if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
        raise RunError("image_inspect", "First release requires linux/amd64 images", 2, "not_run")
    return data["Id"]


def input_binding(root, directory, metadata):
    # Published image references are outputs, so cannot participate in their own build label.
    material = json.loads(json.dumps(metadata))
    for variant in ("vulnerable", "patched"):
        material[variant]["image"] = ""
    return fingerprint(root, directory, material)


def inspect_config(commands, directory, images, project, metadata, allow_exceptions):
    env = compose_env(images)
    base = ["docker", "compose", "--project-directory", str(directory), "--env-file", os.devnull,
            "-p", project, "-f", str(directory / "compose.yaml")]
    _, content = commands.run(base + ["--profile", "vulnerable", "--profile", "patched",
                                    "config", "--no-env-resolution", "--format", "json"], "compose_config", env=env)
    config = json.loads(content)
    validate_compose(config, images, metadata.get("runtime", {}).get("exceptions", []), allow_exceptions)
    return config


def run_case(commands, directory, metadata, images, report, number, variant, scenario, args):
    case_id = f"{number:02d}-{variant}-{scenario}"
    output = commands.output / case_id
    output.mkdir()
    project = "avh-" + uuid.uuid4().hex[:20]
    context = {"schema_version": SCHEMA, "run_id": report["run_id"], "case_id": case_id,
               "variant": variant, "scenario": scenario}
    result = {**context, "environment_id": metadata["id"], "round": number, "project": project,
              "layer": "mechanism", "source_commit": metadata[variant]["commit"],
              "image": images[variant], "started_at": utc(), "outcome": "not_run", "cleaned": False,
              "platform": report["platform"], "toolchain": {k: report[k] for k in
              ("runner_fingerprint", "docker_version", "compose_version")}, "exit_code": 0}
    write_json(output / "context.json", context)
    child = Commands(output, args.timeout)
    env = compose_env(images)
    created = False
    base = None
    try:
        config = inspect_config(child, directory, images, project, metadata, args.allow_exceptions)
        target = config["services"][variant]
        mode = metadata["runtime"].get("mode", "oneshot")
        if mode not in {"oneshot", "service"}:
            raise ValueError("runtime.mode must be oneshot or service")
        if mode == "service" and (not target.get("healthcheck", {}).get("test")
                                  or target["healthcheck"].get("disable")
                                  or target["healthcheck"]["test"][0] == "NONE"):
            raise ValueError("Service mode target requires healthcheck")
        # Persist normalized config: later commands never reinterpret host/environment files.
        config_path = output / "compose.json"
        write_json(config_path, config)
        base = ["docker", "compose", "-p", project, "-f", str(config_path), "--profile", variant]
        child.deadline = time.monotonic() + args.timeout
        created = True
        auxiliaries = [name for name, service in config["services"].items()
                       if name not in images and (not service.get("profiles") or variant in service["profiles"])]
        if auxiliaries:
            child.run(base + ["up", "-d", "--wait", "--wait-timeout", str(args.timeout),
                              "--pull", "never", "--no-build", *auxiliaries], "healthcheck", env=env)
        if mode == "service":
            child.run(base + ["up", "-d", "--wait", "--wait-timeout", str(args.timeout),
                              "--pull", "never", "--no-build", variant], "healthcheck", env=env)
        else:
            child.run(base + ["run", "-d", "--no-deps", "--pull", "never", "--name", project + "-target",
                              "--entrypoint", "python3", variant, "-c", "import time; time.sleep(86400)"], "compose_up", env=env)
        container = project + "-target"
        if mode == "service":
            _, container = child.run(base + ["ps", "-q", variant], "compose_up", env=env)
            container = container.strip()
            if not container or "\n" in container:
                raise RunError("compose_up", "Expected exactly one target container")
        _, state = child.run(["docker", "inspect", container], "compose_up")
        state = json.loads(state)[0]
        if state.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != project:
            raise RunError("compose_up", "Container project identity mismatch")
        child.run(["docker", "exec", container, "python3", "-c",
                   "from pathlib import Path; Path('/lab/results').mkdir(parents=True, exist_ok=True)"], "setup")
        child.run(["docker", "cp", str(output / "context.json"), container + ":/lab/results/context.json"], "setup")
        status, _ = child.run(["docker", "exec", container, "python3", "/lab/reproduce.py",
                               "--context", "/lab/results/context.json", "--output", "/lab/results"],
                              "reproduce", accepted=(0, 1, 2))
        if status:
            raise RunError("reproduce", f"PoC exited {status}; no verification claim", 1 if status == 1 else 2,
                           "execution_failed" if status == 1 else "not_run")
        # Separate invocation: verify only reads evidence and writes its verdict.
        status, _ = child.run(["docker", "exec", container, "python3", "/lab/verify.py",
                               "--context", "/lab/results/context.json", "--output", "/lab/results"],
                              "verify", accepted=(0, 1, 2))
        if status == 2:
            raise RunError("verify", "Verifier could not establish a verdict; see verify logs", 2, "not_run",
                           "verifier determines the outcome from collected evidence")
        child.run(["docker", "cp", container + ":/lab/results/.", str(output / "evidence")], "collect")
        verdict = validate_verdict(output / "evidence", context)
        if status != (0 if verdict["outcome"] == "passed" else 1):
            raise ValueError("Verifier exit status and verdict disagree")
        result.update(outcome=verdict["outcome"], checks=verdict["checks"],
                      exit_code=0 if verdict["outcome"] == "passed" else 1)
        if result["exit_code"]:
            result["failure"] = {"phase": "verify", "status": "assertion_failed",
                                 "expected": "all required checks pass", "actual": verdict["checks"]}
    except KeyboardInterrupt:
        result.update(outcome="interrupted", exit_code=3, failure={
            "phase": "execution", "status": "interrupted", "expected": "complete execution", "actual": "interrupted by user"})
    except RunError as error:
        result.update(outcome=error.status, exit_code=error.code, failure={
            "phase": error.phase, "status": error.status, "expected": error.expected, "actual": error.actual})
    except (ValueError, KeyError, TypeError, OSError) as error:
        result.update(outcome="invalid_evidence", exit_code=3, failure={
            "phase": "verify_or_config", "status": "invalid_evidence", "expected": "valid config and evidence",
            "actual": str(error)})
    finally:
        child.deadline = None
        if created and base:
            try:
                child.run(base + ["logs", "--no-color"], "collect", env=env, timeout=30)
                if result["outcome"] != "passed" and "container" in locals():
                    child.run(["docker", "cp", container + ":/lab/results/.", str(output / "failure-evidence")],
                              "collect", accepted=(0, 1), timeout=30)
            except RunError as error:
                result.setdefault("collection_errors", []).append(str(error))
                result.setdefault("failure", {"phase": "collect", "status": "infrastructure_error",
                                             "expected": "collect complete logs and evidence", "actual": str(error)})
                result["exit_code"] = 3
                result["outcome"] = "infrastructure_error"
            if result["outcome"] != "passed":
                result["failure_evidence"] = "failure-evidence"
            if args.keep_on_failure and result["outcome"] != "passed":
                result["retained_project"] = project
            else:
                try:
                    child.run(base + ["down", "--volumes", "--remove-orphans", "--timeout", "10"],
                              "cleanup", env=env, timeout=60)
                    result["cleaned"] = True
                except RunError as error:
                    result.update(outcome="cleanup_failed", exit_code=3)
                    result["cleanup_error"] = str(error)
                    result.setdefault("failure", {"phase": "cleanup", "status": "cleanup_failed",
                                                 "expected": "remove this project's resources", "actual": str(error)})
        else:
            result["cleaned"] = True
        result["finished_at"] = utc()
        result["logs"] = [p.name for p in sorted(output.glob("*.log"))]
        write_json(output / "result.json", result)
    return result


def reproduce(root, directory, metadata, args):
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
    output = root / "results" / metadata["id"] / run_id
    output.mkdir(parents=True)
    commands = Commands(output, args.timeout)
    report = {"schema_version": SCHEMA, "run_id": run_id, "environment_id": metadata["id"],
              "rounds": args.rounds, "started_at": utc(), "cases": [], "outcome": "not_run", "exit_code": 2}
    try:
        check_fixtures(directory)
        report["fingerprint"] = fingerprint(root, directory, metadata)
        binding = input_binding(root, directory, metadata)
        report["runner_fingerprint"] = runner_fingerprint(root)
        report.update(preflight(commands))
        if report["platform"] != "linux/amd64" or platform.machine() not in {"x86_64", "AMD64"}:
            raise RunError("preflight", "First release supports native linux/amd64", 2, "not_run")
        images = {v: metadata[v].get("image", "") for v in ("vulnerable", "patched")}
        if args.build:
            from .build import build_images
            images = build_images(root, directory, metadata, commands, args.offline)
        elif args.images:
            build = read_json(Path(args.images))
            if build.get("input_binding") != binding or build.get("environment_id") != metadata["id"]:
                raise ValueError("Build manifest belongs to different inputs")
            images = build["images"]
        for variant, image in images.items():
            if not isinstance(image, str) or not (IMAGE.fullmatch(image) or IMAGE_ID.fullmatch(image)):
                raise RunError("preflight", f"Missing immutable {variant} image", 2, "not_run")
            if not metadata[variant].get("commit"):
                raise RunError("preflight", f"Missing {variant} revision", 2, "not_run")
        preview = inspect_config(commands, directory, images, "avh-preflight", metadata, args.allow_exceptions)
        if not args.offline:
            for image in set(s["image"] for s in preview["services"].values()):
                if IMAGE.fullmatch(image):
                    commands.run(["docker", "pull", "--platform", "linux/amd64", image], "pull")
        for variant in images:
            image_check(commands, images[variant], directory, metadata, variant, binding)
        report["images"] = images
        for number in range(1, args.rounds + 1):
            for variant, scenario in CASES:
                if args.scenario != "all" and args.scenario != ("benign" if scenario == "benign" else variant):
                    continue
                result = run_case(commands, directory, metadata, images, report, number, variant, scenario, args)
                report["cases"].append(result)
                write_json(output / "report.json", report)
                if result["outcome"] == "interrupted":
                    raise KeyboardInterrupt
        report["exit_code"] = max((case["exit_code"] for case in report["cases"]), default=2)
        report["outcome"] = "passed" if report["exit_code"] == 0 else "failed"
        if fingerprint(root, directory, metadata) != report["fingerprint"]:
            raise RunError("finalize", "Inputs changed during experiment")
    except KeyboardInterrupt:
        report.update(exit_code=3, outcome="interrupted", failure={
            "phase": "execution", "expected": "complete execution", "actual": "interrupted by user"})
    except RunError as error:
        report.update(exit_code=error.code, outcome=error.status, failure={
            "phase": error.phase, "status": error.status, "expected": error.expected, "actual": error.actual})
    except (ValueError, KeyError, TypeError, OSError) as error:
        report.update(exit_code=3, outcome="infrastructure_error", failure={
            "phase": "protocol", "status": "invalid_evidence", "expected": "complete valid environment",
            "actual": str(error)})
    finally:
        report["finished_at"] = utc()
        write_json(output / "report.json", report)
    print(f"{report['outcome']}: {output / 'report.json'}")
    return report["exit_code"]
