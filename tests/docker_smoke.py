"""Opt-in real Docker smoke test using a synthetic marker, never a real CVE.

Run: python3 -m tests.docker_smoke --base-image python@sha256:...
Requires the base image to be cached; network downloads are disabled.
"""

import argparse
from argparse import Namespace
import hashlib
from pathlib import Path
import shutil
import uuid

from runner.cli import ROOT, read_toml, scaffold
from runner.protocol import read_json, validate_report, write_json, write_metadata
from runner.runtime import reproduce

POC = '''import argparse, json, hashlib
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--context'); p.add_argument('--output')
a = p.parse_args()
c = json.loads(Path(a.context).read_text())
out = Path(a.output)
variant = Path('/lab/variant').read_text().strip()
# Synthetic function stands in for a product only to test runner plumbing.
def synthetic_target(task):
    return 'normal' if task == 'benign' else ('marker' if variant == 'vulnerable' else 'blocked')
observed = synthetic_target(c['scenario'])
effect = out / 'observation.json'
effect.write_text(json.dumps({'ready': True, 'observed': observed}))
(out / 'facts.json').write_text(json.dumps({**c, 'execution_status': 'completed',
    'evidence': [{'path': effect.name, 'sha256': hashlib.sha256(effect.read_bytes()).hexdigest()}]}))
'''

VERIFIER = '''import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--context'); p.add_argument('--output')
a = p.parse_args()
c = json.loads(Path(a.context).read_text()); out = Path(a.output)
observation = json.loads((out / 'observation.json').read_text())
expected = 'normal' if c['scenario'] == 'benign' else ('marker' if c['variant'] == 'vulnerable' else 'blocked')
key = 'benign_task_passed' if c['scenario'] == 'benign' else ('vulnerable_effect_observed' if c['variant'] == 'vulnerable' else 'patched_effect_blocked')
checks = [dict(id='target_ready', passed=observation['ready'] is True, expected=True,
    actual=observation['ready'], reason='Observed synthetic target response', evidence=['observation.json']),
    dict(id=key, passed=observation['observed'] == expected, expected=expected,
    actual=observation['observed'], reason='Independent observation comparison', evidence=['observation.json'])]
passed = all(x['passed'] for x in checks)
(out / 'verdict.json').write_text(json.dumps({**c, 'outcome': 'passed' if passed else 'failed', 'checks': checks}))
raise SystemExit(0 if passed else 1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--exercise-failures", action="store_true")
    args = parser.parse_args()
    root = ROOT / "results" / "tooling-smoke" / uuid.uuid4().hex[:12]
    root.mkdir(parents=True)
    (root / "environments").mkdir()
    (root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
    shutil.copytree(ROOT / "templates", root / "templates")
    shutil.copytree(ROOT / "runner", root / "runner")
    directory = scaffold(root, "synthetic-tooling-only", "CVE-2099-99999")
    (directory / "reproduce.py").write_text(POC)
    (directory / "verify.py").write_text(VERIFIER)
    (directory / "Dockerfile").write_text('''ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
WORKDIR /lab
COPY reproduce.py verify.py /lab/
COPY fixtures /lab/fixtures
RUN printf '%s' "$VARIANT" > /lab/variant
''')
    content = b"synthetic source input; not a vulnerability\n"
    sha = hashlib.sha256(content).hexdigest()
    cache = root / ".cache/sha256"
    cache.mkdir(parents=True)
    (cache / sha).write_bytes(content)
    metadata = read_toml(directory / "metadata.toml")
    metadata["build"].update(base_image=args.base_image, inputs=[
        {"name": "synthetic.txt", "url": "https://example.invalid/synthetic.txt", "sha256": sha}])
    for variant in ("vulnerable", "patched"):
        metadata[variant].update(commit="1" * 40, archive="synthetic.txt")
    write_metadata(directory / "metadata.toml", metadata)
    settings = Namespace(rounds=3, timeout=120, offline=True, build=True, images=None,
                         scenario="all", keep_on_failure=False, allow_exceptions=False)
    code = reproduce(root, directory, metadata, settings)
    report_path = next((root / "results").rglob("report.json"))
    report = read_json(report_path)
    if code == 0:
        validate_report(report, report["fingerprint"])
    if code == 0 and args.exercise_failures:
        settings.rounds = 1
        settings.scenario = "vulnerable"
        (directory / "verify.py").write_text("raise SystemExit(0)\n")
        failed = reproduce(root, directory, metadata, settings)
        if failed != 3:
            raise AssertionError(f"Missing verdict must fail with 3, got {failed}")
        (directory / "verify.py").write_text(VERIFIER)
        (directory / "reproduce.py").write_text("import time; time.sleep(60)\n")
        settings.timeout = 10
        failed = reproduce(root, directory, metadata, settings)
        if failed != 3:
            raise AssertionError(f"Timeout must fail with 3, got {failed}")
        (directory / "reproduce.py").write_text(POC)
        metadata["runtime"]["mode"] = "service"
        write_metadata(directory / "metadata.toml", metadata)
        config = read_json(report_path.parent / report["cases"][0]["case_id"] / "compose.json")
        config.pop("name")
        for group in ("networks", "volumes"):
            for value in config[group].values():
                value.pop("name", None)
        for variant in ("vulnerable", "patched"):
            config["services"][variant].update(
                image="${" + variant.upper() + "_IMAGE}",
                command=["python3", "-m", "http.server", "8765"],
                healthcheck={"test": ["CMD", "python3", "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765', timeout=1)"],
                    "interval": "1s", "timeout": "2s", "retries": 3},
                depends_on={"helper": {"condition": "service_healthy"}})
        config["services"]["helper"] = dict(config["services"]["vulnerable"])
        config["services"]["helper"].update(image=args.base_image)
        for key in ("profiles", "depends_on", "volumes"):
            config["services"]["helper"].pop(key, None)
        write_json(directory / "compose.yaml", config)
        settings.timeout = 30
        if reproduce(root, directory, metadata, settings) != 0:
            raise AssertionError("Service mode with healthy auxiliary must pass")
        config["services"]["helper"]["healthcheck"] = {
            "test": ["CMD", "python3", "-c", "raise SystemExit(1)"],
            "interval": "1s", "timeout": "1s", "retries": 1}
        write_json(directory / "compose.yaml", config)
        settings.timeout = 10
        if reproduce(root, directory, metadata, settings) != 3:
            raise AssertionError("Unhealthy auxiliary must fail before PoC")
        reports = [read_json(p) for p in (root / "results").rglob("report.json")]
        if not all(c["cleaned"] for r in reports for c in r["cases"]):
            raise AssertionError("Smoke experiment leaked resources")
        print("Missing-verdict, timeout and unhealthy-service paths failed as expected; all projects cleaned")
    print(f"SYNTHETIC TOOLING ONLY; artifacts: {root}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
