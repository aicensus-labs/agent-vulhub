/**
 * Drives the pinned n8n agent runtime-reconstruction path for one case.
 *
 * Inputs come from the fixture selected by the caller. The real
 * `AgentRuntimeReconstructionService` is instantiated from the pinned source
 * tree under `N8N_SOURCE_ROOT`; it rebuilds the agent's tool list and resolves
 * every tool reference its own code path allows. Afterwards the resolved node
 * tool is invoked with the arguments a model would emit for it, which is where
 * the node executor sees the request.
 *
 * Every authorization decision is made by the upstream class body. This file
 * supplies storage/DI doubles and records what reached the executor; it does not
 * decide whether the node tool survives.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { makeDoubles } from './n8n_doubles.mjs';

const root = process.env.N8N_SOURCE_ROOT || '/lab/app';
const fixturePath = process.env.N8N_FIXTURE;
const outputPath = process.env.N8N_OUTPUT;

const config = JSON.parse(await readFile(fixturePath, 'utf8'));
const state = { marker: config.marker, credentials: {}, workflows: {}, registry: new Map() };
for (const credential of config.credentials ?? []) state.credentials[credential.id] = credential;
for (const workflow of config.workflows ?? []) state.workflows[workflow.id] = workflow;

const world = makeDoubles(state);
globalThis.__N8N_MODULES__ = world.modules;
console.error(`[harness] fixture ${fixturePath} against ${root}`);

const user = {
  id: config.user.id,
  role: config.user.role,
  scopes: config.user.scopes ?? [],
  projectScopes: config.user.projectScopes ?? [],
  isOwner: false,
};

// DI lookups the reconstruction path performs for the sub-agent delegation tool
// and the chat-integration registry. They are plumbing, not the decision under
// test.
for (const [specifier, name] of [
  ['./sub-agents/sub-agent-foreground-runner', 'SubAgentForegroundRunner'],
  ['./integrations/agent-chat-integration', 'ChatIntegrationRegistry'],
  ['./integrations/integration-message-context.service', 'IntegrationMessageContextService'],
  ['./integrations/integration-action-executor', 'ChatIntegrationActionExecutor'],
  ['./integrations/integration-context-query-executor', 'ChatIntegrationContextQueryExecutor'],
]) {
  const exported = world.modules[specifier]?.[name];
  if (exported) state.registry.set(exported, new exported());
}

state.registry.set(world.modules['@/node-types'].NodeTypes, {
  getByNameAndVersion(nodeType) {
    return {
      description: {
        name: nodeType,
        usableAsTool: true,
        group: ['transform'],
        properties: [],
        outputs: [{ type: 'ai_tool' }],
      },
      execute: async () => [[{ json: { marker: config.marker } }]],
    };
  },
});

const serviceModule = await import(pathToFileURL(
  `${root}/packages/cli/src/modules/agents/agent-runtime-reconstruction.service.ts`).href);
const Service = serviceModule.AgentRuntimeReconstructionService;
console.error('[harness] loaded upstream AgentRuntimeReconstructionService');

const secureRuntime = { createToolExecutor: () => ({ execute: async () => ({}) }) };
const service = new Service(
  new world.modules['@n8n/backend-common'].Logger(), // logger
  {},                                                // agentRepository
  { hasFilesForAgent: async () => false },           // agentFileRepository
  {},                                                // activeExecutions
  world.workflowRepository,                          // workflowRepository
  {},                                                // userRepository
  world.workflowFinderService,                       // workflowFinderService
  { getWebhookBaseUrl: () => 'http://localhost:5678' }, // urlService
  { getStorage: () => ({}) },                        // n8nCheckpointStorage
  secureRuntime,                                     // secureRuntime
  world.executor,                                    // ephemeralNodeExecutor
  { getImplementation: () => ({}) },                 // n8nMemory
  {},                                                // oauthService
  {},                                                // agentsConfig
  {},                                                // aiService
  {},                                                // outboundHttp
  {},                                                // agentKnowledgeSandboxService
  {},                                                // ssrfConfig
  {},                                                // ssrfProtectionService
  world.credentialsFinderService,                    // credentialsFinderService
);

const agentEntity = {
  id: config.agent.id,
  projectId: config.projectId,
  schema: {
    ...config.agent.schema,
    tools: (config.agent.schema.tools ?? []).map((tool) => ({ ...tool })),
  },
  tools: {},
  skills: {},
  integrations: [],
};

// The production chat controller passes `userId` on the released 2.29.7 tree and
// the full `user` on 2.29.8 and later; the fixture states which call it models.
const reconstructed = await service.reconstructFromAgentEntity(
  agentEntity,
  config.credentialProvider ?? {},
  config.user.id,
  undefined,
  ...(config.sendUserObject ? [user] : []),
);

const resolved = reconstructed.toolRegistry.tools ?? [];
const filterExported = typeof service.filterToolsForUser === 'function';
const filterKept = filterExported
  ? (await service.filterToolsForUser(agentEntity.schema.tools, config.projectId, user))
    .map((tool) => tool.name)
  : null;

const nodeTool = resolved.find((tool) => tool.metadata?.kind === 'node');
const invocations = [];
if (nodeTool) {
  invocations.push({ tool: nodeTool.name, result: await nodeTool._handler(config.invocation ?? {}) });
}

const observation = {
  scenario: process.env.N8N_SCENARIO,
  variant: process.env.N8N_VARIANT,
  mechanism_loaded: true,
  filter_tools_for_user_present: filterExported,
  filter_tools_for_user_kept: filterKept,
  resolved_tools: resolved.map((tool) => ({ name: tool.name, kind: tool.metadata?.kind ?? 'custom' })),
  executor_calls: world.calls,
  node_tool_invocations: invocations,
};
await writeFile(outputPath, JSON.stringify(observation, null, 2) + '\n', 'utf8');
console.error(`[harness] observation written to ${outputPath}`);
