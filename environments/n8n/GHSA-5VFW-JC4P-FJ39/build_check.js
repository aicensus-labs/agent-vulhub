"use strict";
// Build-time verifier for n8n/GHSA-5VFW-JC4P-FJ39.
//
// Runs inside the image with no network. It proves four things about the bytes
// that were baked in:
//
//   1. the unpacked upstream release really is the pinned revision
//      (package.json version == the variant's pinned version);
//   2. every file vendored under fixtures/upstream/<version>/ is byte-for-byte
//      the same file inside that release tarball, so the mechanism cannot be
//      running a hand-written stand-in;
//   3. the complete import closure the pinned payloads need - the loader shims -
//      is present and matches fixtures/manifest.toml, the same pin reproduce.py
//      enforces at run time;
//   4. the side of the fix is the pinned one: the attack scenario executes in
//      the owner's context on 2.29.7 and is blocked on 2.29.8, and the
//      resource.authorize member exists only in 2.29.8.
//
// Any mismatch throws and fails `docker build`.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const VERSIONS = { vulnerable: "2.29.7", patched: "2.29.8" };

const variant = process.env.VARIANT;
const version = VERSIONS[variant];
if (!version) throw new Error(`unknown VARIANT ${variant}`);

const releaseRoot = "/lab/vendor/upstream";
const fixturesRoot = "/lab/fixtures";
const vendoredRoot = path.join(fixturesRoot, "upstream", version);
const shimRoot = path.join(fixturesRoot, "harness", "shims");
const harness = path.join(fixturesRoot, "harness", "runner.js");

const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

function walk(directory, base = directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(full, base));
    else if (entry.isFile()) files.push(path.relative(base, full));
  }
  return files;
}

// 1. the installed release is the pinned revision.
const manifest = JSON.parse(fs.readFileSync(path.join(releaseRoot, "package.json"), "utf8"));
if (manifest.version !== version) {
  throw new Error(`installed n8n ${manifest.version}, expected ${version}`);
}

// 2. the vendored payloads are byte-identical to the installed release.
const vendoredFiles = walk(vendoredRoot);
if (vendoredFiles.length === 0) throw new Error(`no vendored files under ${vendoredRoot}`);
for (const relative of vendoredFiles) {
  const installed = path.join(releaseRoot, relative);
  if (!fs.existsSync(installed)) {
    throw new Error(`vendored ${relative} is absent from the n8n@${version} release`);
  }
  const vendoredHash = sha256(fs.readFileSync(path.join(vendoredRoot, relative)));
  const installedHash = sha256(fs.readFileSync(installed));
  if (vendoredHash !== installedHash) {
    throw new Error(`vendored ${relative} differs from the n8n@${version} release`);
  }
}

// 3. the loader shim closure matches the manifest pin (mirrors reproduce.py).
const pinned = new Map();
for (const line of fs.readFileSync(path.join(fixturesRoot, "manifest.toml"), "utf8").split("\n")) {
  const match = /^"([^"]+)"\s*=\s*"([0-9a-f]{64})"$/.exec(line.trim());
  if (match) pinned.set(match[1], match[2]);
}
if (pinned.size === 0) throw new Error("fixtures/manifest.toml lists no files");
const actual = new Set(walk(fixturesRoot).map((entry) => entry.split(path.sep).join("/")));
actual.delete("manifest.toml");
actual.delete("README.md");
for (const name of actual) {
  if (!pinned.has(name)) throw new Error(`fixture not pinned in manifest.toml: ${name}`);
}
for (const name of pinned.keys()) {
  if (!actual.has(name)) throw new Error(`manifest.toml pins an absent fixture: ${name}`);
}
for (const [name, digest] of pinned.entries()) {
  const measured = sha256(fs.readFileSync(path.join(fixturesRoot, name)));
  if (measured !== digest) throw new Error(`fixture hash mismatch: ${name}`);
}
const loaderSource = fs.readFileSync(path.join(fixturesRoot, "harness", "loader.js"), "utf8");
const shimList = /const SHIM_NAMES = \[([\s\S]*?)\]/.exec(loaderSource);
if (shimList === null) throw new Error("loader.js has no SHIM_NAMES list");
for (const name of (shimList[1].match(/"([^"]+)"/g) || []).map((entry) => entry.replace(/"/g, ""))) {
  if (!fs.existsSync(path.join(shimRoot, name))) throw new Error(`loader shim missing: ${name}`);
}

// 4. the pinned side of the fix, at the source level and at run time.
const consent = fs.readFileSync(
  path.join(vendoredRoot, "dist/modules/oauth-server/oauth-consent.service.js"), "utf8");
const token = fs.readFileSync(
  path.join(vendoredRoot, "dist/modules/oauth-server/oauth-token.service.js"), "utf8");
const forbidden = path.join(vendoredRoot, "dist/errors/response-errors/forbidden.error.js");
const patched = variant === "patched";
if (consent.includes("resource.authorize(") !== patched) {
  throw new Error(`${variant} consent service authorize check is on the wrong side of the fix`);
}
if (token.includes("resource.authorize(") !== patched) {
  throw new Error(`${variant} token service authorize check is on the wrong side of the fix`);
}
if (fs.existsSync(forbidden) !== patched) {
  throw new Error(`${variant} forbidden.error.js is on the wrong side of the fix`);
}

const run = spawnSync(process.execPath, [
  harness,
  "--upstream", path.join(fixturesRoot, "upstream"),
  "--shims", shimRoot,
  "--fixture", path.join(fixturesRoot, "attack.json"),
  "--variant", version,
], { encoding: "utf8" });
if (run.status !== 0) {
  throw new Error(`harness exited ${run.status}: ${(run.stderr || run.stdout || "").trim()}`);
}
const artifact = JSON.parse(run.stdout);
const expect = patched
  ? { upstream_version: version, resource_authorize_present: true, resource_authorize_consulted: true,
      blocked: true, blocked_by: "consent", workflow_executed: false, executed_in_owner_context: false,
      token_accepted: false, token_reason: "insufficient_scope" }
  : { upstream_version: version, resource_authorize_present: false, blocked: false, blocked_by: null,
      workflow_executed: true, executed_in_owner_context: true, token_accepted: true, token_reason: null };
const observed = {
  upstream_version: artifact.upstream_version,
  resource_authorize_present: artifact.resource_authorize_present,
  resource_authorize_consulted: artifact.resource_authorize_consulted,
  blocked: artifact.blocked,
  blocked_by: artifact.blocked_by,
  workflow_executed: artifact.workflow_executed,
  executed_in_owner_context: artifact.executed_in_owner_context,
  token_accepted: artifact.token && artifact.token.accepted,
  token_reason: artifact.token && artifact.token.reason,
};
for (const [key, value] of Object.entries(expect)) {
  if (observed[key] !== value) {
    throw new Error(`attack scenario ${key}=${observed[key]}, expected ${value}`);
  }
}
if (patched && observed.resource_authorize_consulted !== true) {
  throw new Error("patched run did not consult resource.authorize");
}

process.stdout.write(
  `${variant} n8n@${version} installed offline: ${vendoredFiles.length} vendored upstream files ` +
  `match the release, ${pinned.size} pinned fixtures verified, attack outcome ` +
  `${patched ? "blocked(consent)" : "executed-in-owner-context"}\n`);
