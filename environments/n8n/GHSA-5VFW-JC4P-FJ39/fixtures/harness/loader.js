"use strict";
// Module loader for the pinned upstream modules.
//
// The lab container has no network and installs no n8n workspace packages, so
// the pinned CommonJS payloads cannot reach `@n8n/*` or third-party packages
// through normal resolution. This loader installs a `Module._load` hook that:
//
//   * lets any request resolve inside `upstream/<version>/` through untouched,
//     so the authorization services run their original compiled bodies;
//   * resolves `@n8n/*`, `jsonwebtoken`, `n8n-workflow`, ... against `shims/`;
//   * resolves node builtins to node itself;
//   * refuses anything else, so a missing import fails loudly instead of
//     silently receiving an inert stand-in.
//
// `reproduce.py` hash-checks every file under `upstream/` and `harness/` before
// this loader runs.

const Module = require("node:module");
const fs = require("node:fs");
const path = require("node:path");

const SHIM_NAMES = [
  "reflect-metadata.js",
  "@modelcontextprotocol/sdk/server/auth/errors.js",
  "@n8n/backend-common.js",
  "@n8n/config.js",
  "@n8n/constants.js",
  "@n8n/db.js",
  "@n8n/di.js",
  "@n8n/permissions.js",
  "@n8n/typeorm.js",
  "jsonwebtoken.js",
  "n8n-core.js",
  "n8n-workflow.js",
  "zod.js",
  "inert-adapters.js",
];

function createLoader(upstreamDir, shimDir, inertSpecifiers) {
  const normalize = (specifier) => specifier.replace(/\.js$/, "");
  // Longest specifier first so `@n8n/db` never shadows a longer sibling.
  const shimBySpecifier = new Map(
    SHIM_NAMES.map((name) => [normalize(name), path.join(shimDir, name)]),
  );
  const inert = new Set(inertSpecifiers.map(normalize));
  const inertModule = require(path.join(shimDir, "inert-adapters.js"));
  const cache = new Map();

  // Register a loaded adapter under a synthetic filename so that tsc's
  // `__importDefault(require("jsonwebtoken"))` sees an `__esModule` module and
  // keeps it as-is instead of wrapping it in `{ default: ... }`.
  const adapter = (specifier) => {
    const key = normalize(specifier);
    if (!cache.has(key)) {
      const filename = path.join(shimDir, "__adapter__" + key.replace(/[^A-Za-z0-9_]/g, "_") + ".js");
      const loaded = require(shimBySpecifier.get(key));
      const record = new Module(filename, module);
      record.filename = filename;
      record.loaded = true;
      record.exports = loaded;
      require.cache[filename] = record;
      cache.set(key, loaded);
    }
    return cache.get(key);
  };

  Module._load = function load(request, parent, isMain) {
    let resolved = null;
    try {
      resolved = Module._resolveFilename(request, parent, isMain);
    } catch {
      resolved = null;
    }
    if (resolved && resolved.startsWith(shimDir + path.sep)) return Module._originalLoad(request, parent, isMain);
    if (resolved && resolved.startsWith(upstreamDir + path.sep)) return Module._originalLoad(request, parent, isMain);
    if (request.startsWith("node:")) return Module._originalLoad(request, parent, isMain);
    if (Module.builtinModules.includes(request)) return Module._originalLoad(request, parent, isMain);
    if (shimBySpecifier.has(normalize(request))) return adapter(request);
    if (inert.has(normalize(request))) return inertModule;
    throw new Error(`lab loader: refusing to resolve ${request} from ${parent && parent.filename}`);
  };
  return Module;
}

function loadUpstream(upstreamDir, shimDir, inertSpecifiers, version) {
  const versionDist = path.join(upstreamDir, version, "dist");
  createLoader(upstreamDir, shimDir, inertSpecifiers);
  const load = (relative) => require(path.join(versionDist, relative));
  const optional = (relative) => {
    if (!fs.existsSync(path.join(versionDist, relative))) return {};
    try {
      return load(relative);
    } catch (error) {
      if (error && error.code === "MODULE_NOT_FOUND") return {};
      throw error;
    }
  };
  return {
    version,
    OAuthTokenService: load("modules/oauth-server/oauth-token.service.js").OAuthTokenService,
    OAuthConsentService: load("modules/oauth-server/oauth-consent.service.js").OAuthConsentService,
    OAuthSessionService: load("modules/oauth-server/oauth-session.service.js").OAuthSessionService,
    OAuthAuthorizationCodeService: load("modules/oauth-server/oauth-authorization-code.service.js").OAuthAuthorizationCodeService,
    ProtectedResourceRegistry: load("services/protected-resource.registry.js").ProtectedResourceRegistry,
    JwtService: load("services/jwt.service.js").JwtService,
    UrlService: load("services/url.service.js").UrlService,
    // Added by the 2.29.8 patch; the vulnerable release has no such module.
    ForbiddenError: optional("errors/response-errors/forbidden.error.js").ForbiddenError || class ForbiddenError extends Error {},
    adapters: {
      GlobalConfig: require(path.join(shimDir, "@n8n/config.js")).GlobalConfig,
      Logger: require(path.join(shimDir, "@n8n/backend-common.js")).Logger,
      Container: require(path.join(shimDir, "@n8n/di.js")).Container,
      UserError: require(path.join(shimDir, "n8n-workflow.js")).UserError,
    },
  };
}

Module._originalLoad = Module._load;

module.exports = { createLoader, loadUpstream };
