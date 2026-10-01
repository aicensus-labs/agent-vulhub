// Node driver for the mechanism PoC of GHSA-5648-rgj9-v224.
//
// It loads the pin-named upstream TypeScript file (utils/graphql-query.ts) from the
// revision that the current image ships, calls the upstream classifier the
// execute_graphql guard uses, and records the per-query decisions plus two
// structural facts about the upstream execute_graphql branch of index.ts.
//
// It deliberately contains no copy of the vulnerable logic: every decision below
// is produced by the upstream module.
//
// usage: node --experimental-strip-types graphql-driver.mjs <cases.json> <repo> <variant> <module-sha256> <results.json>

import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const [, , casesPath, repo, variant, expectedSha, outPath] = process.argv;

function fail(message) {
  process.stderr.write(`graphql-driver: ${message}\n`);
  process.exit(2);
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

// Extract the statement or block that follows `marker`, brace-matched from its first '{'.
function extractBlock(source, marker) {
  const at = source.indexOf(marker);
  if (at < 0) {
    return null;
  }
  const start = source.indexOf("{", at);
  const end = source.indexOf("\n", at);
  if (start < 0 || (end >= 0 && end < start)) {
    return source.slice(at, end < 0 ? source.length : end);
  }
  let depth = 0;
  for (let i = start; i < source.length; i++) {
    if (source[i] === "{") {
      depth++;
    } else if (source[i] === "}") {
      depth--;
      if (depth === 0) {
        return source.slice(start, i + 1);
      }
    }
  }
  return null;
}

if (!casesPath || !repo || !variant || !expectedSha || !outPath) {
  fail("missing arguments");
}

const cases = JSON.parse(await readFile(casesPath, "utf8"));
const modulePath = `${repo}/utils/graphql-query.ts`;
const moduleSha = await sha256(modulePath);
const moduleUrl = pathToFileURL(modulePath).href;
const upstream = await import(moduleUrl);
if (typeof upstream.graphqlQueryContainsWriteOperation !== "function") {
  fail(`pinned module exports no graphqlQueryContainsWriteOperation: ${modulePath}`);
}

if (moduleSha !== expectedSha) {
  fail(`pinned module hash mismatch: ${moduleSha} != ${expectedSha}`);
}

const queries = {};
for (const item of [...cases.attack_queries, ...cases.benign_queries]) {
  queries[item.id] = upstream.graphqlQueryContainsWriteOperation(item.query);
}

const indexSource = await readFile(`${repo}/index.ts`, "utf8");
const branch = extractBlock(indexSource, 'case "execute_graphql"');
if (branch === null) {
  fail("pinned index.ts has no execute_graphql branch");
}
const guard = extractBlock(indexSource, "function rejectIfProjectScopedDeployment");
if (guard === null) {
  fail("pinned index.ts has no rejectIfProjectScopedDeployment helper");
}

const structure = {
  execute_graphql_branch_sha256: createHash("sha256").update(branch).digest("hex"),
  read_only_guard_present: branch.includes("graphqlQueryContainsWriteOperation"),
  project_scope_guard_present: branch.includes("rejectIfProjectScopedDeployment"),
  scope_guard_definition_sha256: createHash("sha256").update(guard).digest("hex"),
};

await writeFile(outPath, JSON.stringify({
  schema_version: 1,
  variant,
  complete: true,
  module: {
    path: modulePath,
    sha256: moduleSha,
    export: "graphqlQueryContainsWriteOperation",
  },
  results: { queries, structure },
}, null, 2) + "\n", "utf8");
