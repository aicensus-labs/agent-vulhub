"use strict";
// Scenario harness for GHSA-5VFW-JC4P-FJ39.
//
// The harness runs the pinned upstream OAuth 2.1 consent and token services from
// `fixtures/upstream/<version>/dist/` with in-memory repositories. Everything
// that decides whether a member-level user may act on another user's protected
// MCP resource lives in those upstream bodies:
//
//   * `OAuthConsentService.getConsentDetails/handleConsentDecision`
//   * `OAuthTokenService.verifyOAuthAccessToken`
//
// The lab supplies only the environment those services run in: in-memory
// repositories, a local HS256 signer with the same shape as `jsonwebtoken`, and
// one protected-resource descriptor. The descriptor is the value the real
// workflow-MCP-trigger resolver would return for an active MCP Server Trigger
// with `authentication = n8nOAuth2`. It carries an `authorize` member only when
// the pinned release's resolver adds one, and this file records whether the
// upstream services consult it.

const fs = require("node:fs");
const path = require("node:path");

const { loadUpstream } = require("./loader.js");

const AUDIENCE = "http://127.0.0.1:5678/mcp/victim-mcp-path";

function memoryRepository(rows, target) {
  return {
    target: target || { name: "Stub" },
    rows,
    async findOne(options = {}) {
      const where = options.where || {};
      return rows.find((row) => Object.entries(where).every(([key, value]) => row[key] === value)) || null;
    },
    async find() {
      return rows.slice();
    },
    async insert(record) {
      rows.push(record);
      return { identifiers: [record] };
    },
    async upsert(record) {
      const index = rows.findIndex((row) => row.userId === record.userId && row.clientId === record.clientId);
      if (index >= 0) rows[index] = { ...rows[index], ...record };
      else rows.push(record);
      return { identifiers: [record] };
    },
    async delete(filter = {}) {
      const before = rows.length;
      const kept = rows.filter((row) => !Object.entries(filter).every(([key, value]) => row[key] === value));
      rows.length = 0;
      rows.push(...kept);
      return { affected: before - kept.length };
    },
    async remove(record) {
      const index = rows.indexOf(record);
      if (index >= 0) rows.splice(index, 1);
      return record;
    },
    manager: {
      async transaction(run) {
        return await run({
          insert: async (_target, record) => {
            rows.push(record);
          },
        });
      },
    },
  };
}

function descriptorFrom(scenario, release) {
  const resource = scenario.resource;
  const descriptor = {
    id: "workflow-mcp:" + resource.workflow_id,
    displayName: resource.workflow_name,
    getResourceUrl: () => resource.url,
    getAudiences: () => [resource.url],
    scopes: [],
    __authorizeConsulted: false,
  };
  // The patched resolver adds `authorize`; the vulnerable release returns a
  // descriptor with no such member, which is exactly the missing check this
  // environment reproduces. Inside, the lab stands in for n8n's permission query
  // (`WorkflowFinderService.findWorkflowIdsWithScopeForUser`) by answering from
  // the workflow:execute rows the scenario declares. Those rows are the fixture's
  // statement of n8n's project/workflow role facts; the query itself is not run.
  if (release.hasAuthorize) {
    descriptor.authorize = async (member) => {
      descriptor.__authorizeConsulted = true;
      return grantFor(scenario, member.id, resource.workflow_id);
    };
  }
  return descriptor;
}

function grantFor(scenario, userId, workflowId) {
  return scenario.access.some(
    (row) => row.user === userId && row.workflow === workflowId
      && row.scope === "workflow:execute" && row.granted === true,
  );
}

async function run(upstreamDir, shimDir, inertSpecifiers, fixture, variant) {
  const release = {
    "2.29.7": { hasAuthorize: false, name: "vulnerable" },
    "2.29.8": { hasAuthorize: true, name: "patched" },
  }[variant];
  if (!release) throw new Error(`unknown upstream variant ${variant}`);

  const upstream = loadUpstream(upstreamDir, shimDir, inertSpecifiers, variant);
  const { Container, GlobalConfig, Logger, UserError } = upstream.adapters;

  const globalConfig = new GlobalConfig();
  const logger = new Logger();
  const jwtService = new upstream.JwtService({ encryptionKey: "lab-synthetic-encryption-key" }, globalConfig);
  const urlService = new upstream.UrlService(globalConfig);

  const accessTokens = [];
  const refreshTokens = [];
  const consentRows = [];
  const authorizationCodes = [];
  const clientRows = [];
  const users = fixture.users.map((user) => ({ id: user.id, name: user.name, role: user.role }));

  const accessTokenRepository = memoryRepository(accessTokens, { name: "AccessToken" });
  const refreshTokenRepository = memoryRepository(refreshTokens, { name: "RefreshToken" });
  const consentRepository = memoryRepository(consentRows, { name: "UserConsent" });
  const authorizationCodeRepository = memoryRepository(authorizationCodes, { name: "AuthorizationCode" });
  const clientRepository = memoryRepository(clientRows, { name: "OAuthClient" });
  const userRepository = memoryRepository(users, { name: "User" });

  // The real registry is upstream code; only `register` is used, and that is the
  // same call n8n's OAuth module makes on init.
  const registry = new upstream.ProtectedResourceRegistry(logger);
  const descriptor = descriptorFrom(fixture, release);
  registry.register(descriptor);
  Container.set(upstream.ProtectedResourceRegistry, registry);

  const sessionService = new upstream.OAuthSessionService(jwtService);
  const authorizationCodeService = new upstream.OAuthAuthorizationCodeService(authorizationCodeRepository);
  const consentService = new upstream.OAuthConsentService(
    logger,
    sessionService,
    clientRepository,
    consentRepository,
    authorizationCodeService,
    registry,
    urlService,
  );
  const tokenService = new upstream.OAuthTokenService(
    logger,
    jwtService,
    userRepository,
    accessTokenRepository,
    refreshTokenRepository,
    registry,
  );

  const subject = fixture.subject;
  const attacker = fixture.attacker;
  const clientId = "lab-client-" + subject.id;
  clientRows.push({ id: clientId, name: "Caller Registered MCP Client", redirectUris: ["https://caller.example/callback"] });

  const sessionToken = jwtService.sign({
    clientId,
    redirectUri: "https://caller.example/callback",
    codeChallenge: "lab-code-challenge-value-long-enough",
    state: "lab-state",
    resource: fixture.resource.url,
  }, { expiresIn: "10m" });

  const artifact = {
    scenario: fixture.scenario,
    variant,
    upstream_version: upstream.version,
    subject: subject.id,
    resource: fixture.resource.url,
    resource_authorize_present: release.hasAuthorize,
    resource_authorize_consulted: false,
    consent: {},
    token: {},
  };

  // Stage 1: consent. `handleConsentDecision` takes a userId in 2.29.7 and a user
  // object in 2.29.8; both are the real compiled signatures, so the harness
  // dispatches on the loaded function's declared parameters.
  let consentCode = null;
  let consentRedirect = null;
  let consentBlocked = false;
  let consentError = null;
  // 2.29.7 declares (sessionToken, userId, approved); 2.29.8 declares
  // (sessionToken, user, approved). Both are the real compiled signatures, and
  // the harness dispatches on the parameter name rather than guessing.
  const consentTakesUser = /handleConsentDecision\s*\(\s*sessionToken\s*,\s*user\s*,/.test(
    String(consentService.handleConsentDecision),
  );
  const detailsTakeUser = /getConsentDetails\s*\(\s*sessionToken\s*,\s*user\s*[,)]/.test(
    String(consentService.getConsentDetails),
  );
  try {
    const details = detailsTakeUser
      ? await consentService.getConsentDetails(sessionToken, subject)
      : await consentService.getConsentDetails(sessionToken);
    artifact.consent.details = details === null ? null : {
      ok: details.ok,
      reason: details.reason === undefined ? null : details.reason,
      resourceName: details.resourceName === undefined ? null : details.resourceName,
    };
    try {
      const decision = consentTakesUser
        ? await consentService.handleConsentDecision(sessionToken, subject, true)
        : await consentService.handleConsentDecision(sessionToken, subject.id, true);
      consentRedirect = decision.redirectUrl;
      const match = /[?&]code=([^&]+)/.exec(consentRedirect || "");
      consentCode = match ? decodeURIComponent(match[1]) : null;
    } catch (error) {
      consentError = error.constructor && error.constructor.name;
      consentBlocked = error instanceof upstream.ForbiddenError || error instanceof UserError;
      if (!consentBlocked) throw error;
    }
  } catch (error) {
    artifact.fatal = `consent stage failed: ${error && error.message}`;
  }
  artifact.consent = {
    ...artifact.consent,
    approved: consentCode !== null,
    code_minted: consentCode !== null,
    blocked: consentBlocked,
    error: consentError,
    http_status: consentBlocked ? 403 : consentCode !== null ? 302 : 200,
  };

  // Stage 2: the runtime gate. The member presents a token minted for the
  // victim's resource and the upstream verifier decides whether it is honoured.
  let verifiedUser = null;
  let verifyReason = null;
  let verifyFatal = null;
  try {
    const pair = tokenService.generateTokenPair(attacker.id, clientId, fixture.resource.url);
    await tokenService.saveTokenPair(pair.accessToken, pair.refreshToken, clientId, attacker.id);
    const result = await tokenService.verifyOAuthAccessToken(pair.accessToken, fixture.resource.url);
    verifiedUser = result.user ? result.user.id : null;
    verifyReason = result.context && result.context.reason ? result.context.reason : null;
    artifact.token = {
      audience: fixture.resource.url,
      minted_for: attacker.id,
      accepted: result.user !== null,
      user: verifiedUser,
      reason: verifyReason,
      status: result.user !== null ? 200 : 403,
      code_present: Boolean(consentCode),
    };
  } catch (error) {
    verifyFatal = `token stage failed: ${error && error.message}`;
    artifact.fatal = artifact.fatal || verifyFatal;
    artifact.token = { audience: fixture.resource.url, minted_for: attacker.id, accepted: false, user: null, reason: "harness_error", status: 500, code_present: Boolean(consentCode) };
  }

  artifact.resource_authorize_consulted = Boolean(descriptor.__authorizeConsulted);
  const gatesPassed = consentCode !== null && verifiedUser === attacker.id;
  artifact.workflow_executed = gatesPassed;
  artifact.executed_in_owner_context = gatesPassed && fixture.resource.workflow_owner !== attacker.id;
  artifact.execution_owner = gatesPassed ? fixture.resource.workflow_owner : null;
  artifact.blocked = !gatesPassed;
  artifact.blocked_by = consentCode === null ? "consent" : verifiedUser === attacker.id ? null : "token_verification";
  const granted = grantFor(fixture, attacker.id, fixture.resource.workflow_id);
  artifact.subject_has_execute = granted;
  artifact.authorized_user_expected = granted;
  artifact.outcome = consentCode !== null && verifiedUser === attacker.id ? "authorized_flow_completed" : "blocked";
  return artifact;
}

function main(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    options[argv[index].replace(/^--/, "")] = argv[index + 1];
  }
  const fixture = JSON.parse(fs.readFileSync(options.fixture, "utf8"));
  const inert = JSON.parse(fs.readFileSync(path.join(options.shims, "inert-specifiers.json"), "utf8"));
  return run(options.upstream, options.shims, inert, fixture, options.variant);
}

if (require.main === module) {
  main(process.argv.slice(2)).then((artifact) => {
    process.stdout.write(JSON.stringify(artifact, null, 2) + "\n");
  }).catch((error) => {
    process.stderr.write(`harness failed: ${error && error.stack}\n`);
    process.exitCode = 1;
  });
}

module.exports = { run, main };
