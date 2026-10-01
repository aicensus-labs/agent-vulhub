"""Mechanism PoC for GHSA-XWMW-PRC4-V3CR: MCP OAuth audience confusion.

The affected revision mints an MCP OAuth access token whose ``aud`` is the MCP
connect resource and whose ``UserGroups`` claim is the victim's real role
groups, while the JWT validator only checks the issuer. The same token is then
accepted by the Obot API with the victim's groups as the request identity.

This script drives the pinned upstream code at the revision selected by the
execution context. It never copies, extracts or rewrites the vulnerable
functions: it adds one in-package Go test file to the pinned source tree, calls
``TokenService.NewToken`` / ``TokenService.DecodeToken`` verbatim, and removes
the file afterwards.

Image contract that the build recipe must provide (nothing in this file
reimplements it):

* the pinned upstream tree for this variant is installed at ``/lab/upstream``
  (module ``github.com/obot-platform/obot``, complete checkout of the pinned
  commit). ``AVH_UPSTREAM_SRC`` overrides that path; a few conventional
  locations are also probed;
* the Go module cache for that tree is populated, or the tree is vendored, so
  that ``go test ./pkg/jwt/persistent/`` builds with no network;
* the pinned Go toolchain is on ``PATH``.

If no installed tree is found, the script falls back to extracting the source
archive from ``/inputs`` and picks the archive whose
``pkg/jwt/persistent/persistent.go`` matches the revision required by the
context.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from lab_support import parser, read_context, record

SOURCE_ROOT_ENV = "AVH_UPSTREAM_SRC"
SOURCE_CANDIDATES = (
    "/lab/upstream",
    "/lab/src",
    "/src",
    "/opt/obot",
    "/obot",
    "/inputs/src",
)
FIXTURES_DEFAULT = "/lab/fixtures"
INPUTS_DIRECTORY = "/inputs"
PACKAGE_RELATIVE = "pkg/jwt/persistent"
SOURCE_MARKERS = ("go.mod", PACKAGE_RELATIVE + "/persistent.go")
DRIVER_NAME = "zz_avh_audience_confusion_test.go"
GO_TEST_FUNCTION = "TestAVHAudienceConfusionMechanism"
GO_TEST_TIMEOUT = 900
SCENARIO_FIXTURES = {"attack": "attack.json", "benign": "benign.json"}

# SHA-256 of pkg/jwt/persistent/persistent.go at the two pinned revisions. The
# guard keeps a mis-labelled image from producing a meaningless observation.
PINNED_SOURCE_SHA256 = {
    "vulnerable": "54e6e669427310f33748447ec78eec191b40d9ca54df764da3b68293d503db53",
    "patched": "84f8f7fc68deba99cd0a8716b671d65e5ddbeb2e566e37febf173a95d7ad3da7",
}
PINNED_COMMIT = {
    "vulnerable": "352570eb2a812e0e54419ba518949acdb3d8b315",
    "patched": "1d4b687e66fce41dd059e1005501623e021ac27f",
}

# In-package Go driver. Adding it to the upstream package is the only way to
# install a signing key without reaching for a database-backed TokenService;
# upstream's own persistent_test.go does the same via replaceKey.
DRIVER_SOURCE = r'''package persistent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type avhInput struct {
	Case       string   `json:"case"`
	ServerURL  string   `json:"server_url"`
	Audience   string   `json:"audience"`
	UserID     string   `json:"user_id"`
	UserName   string   `json:"user_name"`
	UserEmail  string   `json:"user_email"`
	UserGroups []string `json:"user_groups"`
}

type avhOutput struct {
	TargetReady       bool     `json:"target_ready"`
	ExecutionStatus   string   `json:"execution_status"`
	Case              string   `json:"case"`
	ServerURL         string   `json:"server_url"`
	RequestedAudience string   `json:"requested_audience"`
	TokenIssued       bool     `json:"token_issued"`
	AccessToken       string   `json:"access_token"`
	DecodeError       string   `json:"decode_error"`
	DecodedGroups     []string `json:"decoded_groups"`
	DecodedAudience   string   `json:"decoded_audience"`
	DecodedUserID     string   `json:"decoded_user_id"`
	DecodedUserName   string   `json:"decoded_user_name"`
	DecodedUserEmail  string   `json:"decoded_user_email"`
}

func avhWriteOutput(t *testing.T, path string, out avhOutput) {
	t.Helper()
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal mechanism output: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write mechanism output %s: %v", path, err)
	}
}

// TestAVHAudienceConfusionMechanism signs a token with the pinned upstream
// NewToken and decodes it with the pinned upstream DecodeToken.
func TestAVHAudienceConfusionMechanism(t *testing.T) {
	inputPath := os.Getenv("AVH_MECHANISM_INPUT")
	outputPath := os.Getenv("AVH_MECHANISM_OUTPUT")
	if inputPath == "" || outputPath == "" {
		t.Fatal("AVH_MECHANISM_INPUT and AVH_MECHANISM_OUTPUT must be set")
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read mechanism input: %v", err)
	}

	var in avhInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse mechanism input: %v", err)
	}

	out := avhOutput{
		ExecutionStatus:   "failed",
		Case:              in.Case,
		ServerURL:         in.ServerURL,
		RequestedAudience: in.Audience,
	}

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ephemeral signing key: %v", err)
	}

	service := &TokenService{serverURL: in.ServerURL}
	if err := service.replaceKey(context.Background(), privateKey); err != nil {
		t.Fatalf("install ephemeral signing key: %v", err)
	}
	out.TargetReady = true

	token, err := service.NewToken(context.Background(), TokenContext{
		Audience:   in.Audience,
		IssuedAt:   time.Now().Add(-time.Minute),
		ExpiresAt:  time.Now().Add(time.Hour),
		UserID:     in.UserID,
		UserName:   in.UserName,
		UserEmail:  in.UserEmail,
		UserGroups: in.UserGroups,
	})
	if err != nil {
		avhWriteOutput(t, outputPath, out)
		t.Fatalf("sign token with upstream NewToken: %v", err)
	}
	out.TokenIssued = true
	out.AccessToken = token

	decoded, err := service.DecodeToken(context.Background(), token)
	if err != nil {
		out.DecodeError = err.Error()
		out.ExecutionStatus = "completed"
		avhWriteOutput(t, outputPath, out)
		t.Logf("upstream DecodeToken rejected the token: %v", err)
		return
	}

	out.DecodedGroups = decoded.UserGroups
	out.DecodedAudience = decoded.Audience
	out.DecodedUserID = decoded.UserID
	out.DecodedUserName = decoded.UserName
	out.DecodedUserEmail = decoded.UserEmail
	out.ExecutionStatus = "completed"
	avhWriteOutput(t, outputPath, out)
	t.Logf("requested audience=%s decoded groups=%v", in.Audience, decoded.UserGroups)
}
'''


def _fixtures_directory() -> Path:
    return Path(os.environ.get("AVH_FIXTURES", FIXTURES_DEFAULT))


def _looks_like_source(root: Path) -> bool:
    if not root.is_dir() or not all((root / marker).is_file() for marker in SOURCE_MARKERS):
        return False
    try:
        return "github.com/obot-platform/obot" in (root / "go.mod").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _detect_revision(source: Path) -> tuple[str | None, str | None]:
    path = source / PACKAGE_RELATIVE / "persistent.go"
    if not path.is_file():
        return None, None
    digest = _sha256_file(path)
    for revision, expected in PINNED_SOURCE_SHA256.items():
        if digest == expected:
            return revision, digest
    return None, digest


def _extract_archive(archive: Path, workdir: Path) -> Path | None:
    target = workdir / ("archive-" + archive.name.replace(".", "_"))
    target.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:*") as handle:
            try:
                handle.extractall(target, filter="data")
            except TypeError:  # Python < 3.12 has no extraction filter.
                handle.extractall(target)
    except (tarfile.TarError, OSError, ValueError):
        return None
    for candidate in [target, *sorted(item for item in target.iterdir() if item.is_dir())]:
        if _looks_like_source(candidate):
            return candidate
    return None


def _find_source_tree(workdir: Path, variant: str) -> tuple[Path | None, str]:
    """Return the pinned tree for this variant plus a human-readable note."""
    roots = []
    override = os.environ.get(SOURCE_ROOT_ENV)
    if override:
        roots.append(Path(override))
    roots.extend(Path(item) for item in SOURCE_CANDIDATES)

    fallback = None
    for root in roots:
        if not _looks_like_source(root):
            continue
        revision, _ = _detect_revision(root)
        if revision == variant:
            return root, f"installed tree {root}"
        fallback = fallback or (root, f"installed tree {root} is revision {revision!r}")

    inputs = Path(INPUTS_DIRECTORY)
    if inputs.is_dir():
        archives = sorted(
            path for path in inputs.iterdir()
            if path.is_file() and path.name.endswith((".tar.gz", ".tgz", ".tar"))
        )
        # Prefer archives whose name names the variant, then any archive.
        archives.sort(key=lambda path: (variant not in path.name, path.name))
        for archive in archives:
            extracted = _extract_archive(archive, workdir)
            if extracted is None:
                continue
            revision, _ = _detect_revision(extracted)
            if revision == variant:
                return extracted, f"extracted {archive.name}"
            fallback = fallback or (extracted, f"{archive.name} is revision {revision!r}")

    if fallback is not None:
        return fallback
    return None, "no pinned upstream tree found"


def _upstream_marker(source: Path) -> str | None:
    for candidate in (
        source / "AVH_SOURCE_COMMIT",
        source / ".avh-source-commit",
        Path("/lab/SOURCE_COMMIT"),
    ):
        if not candidate.is_file():
            continue
        value = candidate.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        if value and len(value[0]) == 40:
            return value[0]
    return None


def _go_version(go: str) -> str | None:
    try:
        completed = subprocess.run(
            [go, "version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def _run_driver(source: Path, fixture: Path, workdir: Path) -> dict:
    """Add the in-package driver, run it against the pinned tree, remove it."""
    package_dir = source / PACKAGE_RELATIVE
    driver = package_dir / DRIVER_NAME

    result_path = workdir / "driver-output.json"
    env = dict(os.environ)
    env["AVH_MECHANISM_INPUT"] = str(fixture)
    env["AVH_MECHANISM_OUTPUT"] = str(result_path)
    env.setdefault("GOCACHE", str(workdir / "gocache"))
    env.setdefault("GOTMPDIR", str(workdir / "gotmp"))

    report: dict = {
        "driver_returncode": None,
        "driver_stdout": "",
        "driver_stderr": "",
        "driver_result": {},
        "go_version": None,
    }

    try:
        driver.write_text(DRIVER_SOURCE, encoding="utf-8")
    except OSError as error:
        report["driver_stderr"] = f"cannot write driver into the upstream tree: {error}"
        return report

    try:
        Path(env["GOCACHE"]).mkdir(parents=True, exist_ok=True)
        Path(env["GOTMPDIR"]).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    go = shutil.which("go")
    if go is None:
        for candidate in ("/usr/local/go/bin/go", "/usr/lib/go/bin/go", "/usr/bin/go"):
            if Path(candidate).is_file():
                go = candidate
                break

    if go is None:
        report["driver_stderr"] = "no go toolchain found on PATH"
        driver.unlink(missing_ok=True)
        return report
    report["go_version"] = _go_version(go)

    command = [
        go, "test", "-count=1", "-v", "-timeout", "300s",
        "-run", "^" + GO_TEST_FUNCTION + "$", "./" + PACKAGE_RELATIVE + "/",
    ]
    try:
        completed = subprocess.run(
            command, cwd=str(source), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=GO_TEST_TIMEOUT,
        )
        report["driver_returncode"] = completed.returncode
        report["driver_stdout"] = completed.stdout[-4000:]
        report["driver_stderr"] = completed.stderr[-4000:]
    except subprocess.TimeoutExpired as error:
        report["driver_returncode"] = "timeout"
        report["driver_stderr"] = f"go test exceeded {GO_TEST_TIMEOUT}s: {error}"
    except OSError as error:
        report["driver_stderr"] = f"failed to start go test: {error}"
    finally:
        driver.unlink(missing_ok=True)

    if result_path.is_file():
        try:
            report["driver_result"] = json.loads(result_path.read_text(encoding="utf-8"))
        except ValueError as error:
            report["driver_stderr"] += f"\ndriver output is not JSON: {error}"
    return report


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    variant = context["variant"]
    scenario = context["scenario"]
    output = Path(args.output)

    observation: dict = {
        "target_ready": False,
        "execution_status": "not_run",
        "variant": variant,
        "scenario": scenario,
        "expected_upstream_commit": PINNED_COMMIT.get(variant),
        "source_revision": None,
        "source_revision_matches_variant": False,
        "persistent_source_sha256": None,
    }
    effects: dict[str, str] = {}

    fixture_name = SCENARIO_FIXTURES.get(scenario)
    if fixture_name is None:
        observation["reason"] = f"unsupported scenario {scenario!r}"
        return record(context, output, observation, effects)

    fixture = _fixtures_directory() / fixture_name
    if not fixture.is_file():
        observation["reason"] = f"missing input {fixture}"
        return record(context, output, observation, effects)
    try:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        observation["reason"] = f"cannot read input {fixture}: {error}"
        return record(context, output, observation, effects)
    if not isinstance(payload, dict):
        observation["reason"] = f"input {fixture} must hold a JSON object"
        return record(context, output, observation, effects)
    observation["input"] = fixture.name
    # The API server the token is minted for; the verifier anchors the benign
    # audience (== server URL) and the MCP connect resource (server + path).
    observation["server_url"] = payload.get("server_url")

    with tempfile.TemporaryDirectory(prefix="avh-mechanism-") as temporary:
        workdir = Path(temporary)
        source, note = _find_source_tree(workdir, variant)
        observation["source_tree"] = note
        if source is None:
            observation["reason"] = "no pinned upstream tree available in the image"
            return record(context, output, observation, effects)

        revision, digest = _detect_revision(source)
        observation["source_revision"] = revision
        observation["persistent_source_sha256"] = digest
        observation["source_revision_matches_variant"] = revision == variant
        if revision != variant:
            observation["reason"] = (
                "source tree is revision "
                f"{revision!r} but the execution context asks for {variant!r}"
            )
            return record(context, output, observation, effects)

        observation["upstream_commit"] = _upstream_marker(source) or PINNED_COMMIT.get(variant)
        report = _run_driver(source, fixture, workdir)

    driver_result = report.get("driver_result") or {}
    observation.update({
        "go_version": report.get("go_version"),
        "driver_returncode": report.get("driver_returncode"),
        "driver_stdout": report.get("driver_stdout", ""),
        "driver_stderr": report.get("driver_stderr", ""),
        "token_issued": bool(driver_result.get("token_issued")),
        "decode_error": driver_result.get("decode_error") or "",
        "requested_audience": payload.get("audience"),
        "decoded_audience": driver_result.get("decoded_audience") or "",
        "decoded_groups": driver_result.get("decoded_groups") or [],
        "caller_groups": payload.get("user_groups") or [],
    })
    if driver_result.get("target_ready"):
        observation["target_ready"] = True
    completed = driver_result.get("execution_status") == "completed"
    observation["execution_status"] = "completed" if completed else "failed"
    if not completed:
        observation["reason"] = "the pinned upstream mechanism did not complete"

    claims = _decode_jwt_payload(driver_result.get("access_token") or "")
    mechanism = {
        "variant": variant,
        "scenario": scenario,
        "source_revision": observation["source_revision"],
        "persistent_source_sha256": observation["persistent_source_sha256"],
        "server_url": payload.get("server_url"),
        "requested_audience": payload.get("audience"),
        "raw_user_groups_claim": claims.get("UserGroups"),
        "decoded_groups": observation["decoded_groups"],
        "decode_error": observation["decode_error"],
        "token_issued": observation["token_issued"],
    }
    effects["mechanism.json"] = json.dumps(mechanism, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if claims:
        effects["jwt-claims.json"] = json.dumps(claims, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    return record(context, output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
