/**
 * ESM loader for the pinned n8n TypeScript tree.
 *
 * Two facts about the pinned sources force this loader to exist:
 *
 *   1. Node's type stripping refuses legacy decorators, and `@Service()` sits on
 *      the class under test, so `load` deletes decorator lines from the pinned
 *      source in memory. Only decorator syntax changes; every statement that
 *      decides the authorization outcome is the upstream one.
 *   2. The class imports type aliases (`CredentialProvider`, `ToolDescriptor`,
 *      `AgentJsonToolConfig`, ...) with plain import syntax rather than
 *      `import type`, which Node's stripper keeps in place. Each synthetic
 *      module therefore also exports every name the pinned sources request from
 *      that specifier. A name the stripper later erases is never dereferenced; a
 *      name the code really uses has to be a harness double.
 *
 * Relative specifiers keep resolving to the real pinned files under
 * `N8N_SOURCE_ROOT`, including n8n's extensionless sibling imports.
 */
import { readFile } from 'node:fs/promises';
import { accessSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = process.env.N8N_SOURCE_ROOT || '/lab/app';
const doublesUrl = pathToFileURL(process.env.N8N_DOUBLES || '/lab/fixtures/n8n_doubles.mjs').href;
const doublesModule = await import(doublesUrl);
const doubles = doublesModule.default ?? doublesModule;

const DECORATOR = /^[ \t]*@[A-Za-z_$][\w$]*(?:[ \t]*\([^)]*\))?[ \t]*$/gm;

// Only the files the harness imports take part in the decision. Their requested
// import names are collected eagerly because specifiers resolve before any
// source is parsed.
const SOURCES = [
  'packages/cli/src/modules/agents/agent-runtime-reconstruction.service.ts',
  'packages/cli/src/modules/agents/tools/node-tool-factory.ts',
];
const requested = new Map();
const cache = new Map();

for (const relative of SOURCES) {
  let source;
  try {
    source = await readFile(`${root}/${relative}`, 'utf8');
  } catch {
    continue;
  }
  for (const match of source.matchAll(
    /import\s+(?:type\s+)?(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g,
  )) {
    const names = requested.get(match[2]) ?? new Set();
    for (const item of match[1].split(',')) {
      const name = item.trim().replace(/^type\s+/, '').split(/\s+as\s+/)[0]?.trim();
      if (name) names.add(name);
    }
    requested.set(match[2], names);
  }
}

function syntheticUrl(specifier) {
  if (cache.has(specifier)) return cache.get(specifier);
  const configured = Object.hasOwn(doubles.modules, specifier) ? doubles.modules[specifier] : {};
  const names = new Set([...Object.keys(configured), ...(requested.get(specifier) ?? [])]);
  const lines = [...names].map((name) => (Object.hasOwn(configured, name)
    ? `export const ${name} = globalThis.__N8N_MODULES__[${JSON.stringify(specifier)}][${JSON.stringify(name)}];`
    : `export const ${name} = undefined;`));
  lines.push('export default undefined;');
  const url = 'data:text/javascript;base64,'
    + Buffer.from(lines.join('\n') + '\n').toString('base64');
  cache.set(specifier, url);
  return url;
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (Object.hasOwn(doubles.modules, specifier) || requested.has(specifier)) {
      return { url: syntheticUrl(specifier), shortCircuit: true };
    }
    if (specifier.startsWith('@/')) {
      return { url: syntheticUrl(specifier), shortCircuit: true };
    }
    // n8n resolves sibling modules without an extension (bundler resolution);
    // an ESM loader has to name the .ts path explicitly.
    if (specifier.startsWith('.') && context.parentURL?.startsWith('file:')) {
      const candidate = new URL(`${specifier}.ts`, context.parentURL);
      try {
        accessSync(candidate);
        return { url: candidate.href, shortCircuit: true };
      } catch {
        // fall through to the default resolver
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith('file:') && url.endsWith('.ts')) {
      const result = nextLoad(url, context);
      if (result.source) {
        return { ...result, source: String(result.source).replace(DECORATOR, '') };
      }
    }
    return nextLoad(url, context);
  },
});
