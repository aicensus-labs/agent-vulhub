/**
 * Controlled dependency doubles for the n8n modules that cannot be loaded
 * outside a full deployment (TypeORM repositories, the NestJS DI container,
 * LangChain tool objects, the AI proxy services). The code under test is the
 * pinned upstream class; nothing here reimplements its authorization decision.
 * State (users' scopes, credentials, workflow shares) is attached by the
 * harness before the upstream module is imported.
 */

export function liveUser(user, projectId, scope) {
  if ((user.scopes ?? []).includes(scope)) return true;
  return (user.projectScopes ?? []).some(
    (entry) => entry.projectId === projectId && (entry.scopes ?? []).includes(scope),
  );
}

export function userCanReadCredential(state, user, credentialId, scope) {
  const record = state.credentials[credentialId];
  if (!record) return null;
  const allowed = record.owner === user.id
    ? liveUser(user, record.projectId, scope)
    : (record.sharedWith ?? []).includes(user.id);
  return allowed ? { id: record.id, name: record.name, type: record.type } : null;
}

export const modules = {
  '@n8n/di': {
    Container: {
      get(token) {
        const registry = modules.state.registry;
        if (registry.has(token)) return registry.get(token);
        throw new Error(`no provider registered for ${token?.name ?? String(token)}`);
      },
      set(token, value) { modules.state.registry.set(token, value); },
    },
    Service: () => (target) => target,
  },
  '@n8n/agents': { BuiltTool: class BuiltTool {}, createWriteTodosTool: () => ({}) },
  '@n8n/agents/tool': {
    Tool: class Tool {
      constructor(name) { this.name = name; this._handler = null; }
      description() { return this; }
      input() { return this; }
      handler(fn) { this._handler = fn; return this; }
      build() { return this; }
    },
  },
  '@n8n/ai-utilities/http-proxy-agent': { proxyFetch: async () => ({}) },
  '@n8n/ai-utilities/fromai-helpers': {
    createZodSchemaFromArgs: () => ({}),
    extractFromAIParameters: () => [],
  },
  '@langchain/core/tools': { Tool: class LangChainTool {} },
  '@n8n/backend-common': { Logger: class Logger { debug() {} warn() {} error() {} info() {} } },
  '@n8n/backend-network': {
    OutboundHttp: class OutboundHttp {}, SsrfProtectionService: class SsrfProtectionService {},
  },
  '@n8n/config': { AgentsConfig: class AgentsConfig {}, SsrfProtectionConfig: class SsrfProtectionConfig {} },
  '@n8n/db': { UserRepository: class UserRepository {}, WorkflowRepository: class WorkflowRepository {} },
  '@n8n/api-types': {
    N8N_CHAT_ACTION_TOOL_NAME: 'n8n_chat_action',
    N8N_CHAT_CONTEXT_TOOL_NAME: 'n8n_chat_context',
    N8N_CHAT_INTEGRATION_TYPE: 'chat',
    SUB_AGENT_MAX_CHILDREN_DEFAULT: 3,
    SUB_AGENT_TASK_DIFFICULTIES: [],
    buildProxyHeaders: () => ({}),
  },
  'n8n-workflow': {
    UserError: class UserError extends Error {},
    AI_VENDOR_NODE_TYPES: [],
    NodeConnectionTypes: { AiTool: 'ai_tool' },
    SEND_AND_WAIT_OPERATION: 'sendAndWait',
    createEmptyRunExecutionData: () => ({}),
    Workflow: class Workflow {},
    Node: class Node {},
    isToolType: (nodeType) => String(nodeType).endsWith('Tool'),
    nodeNameToToolName: (name) =>
      String(name).toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^_+|_+$/g, ''),
  },
  'zod': {
    z: {
      preprocess: () => ({}), object: () => ({}), string: () => ({}),
      record: () => ({}), unknown: () => ({}), any: () => ({}),
    },
  },
  'nanoid': { nanoid: () => 'V1StGXR8Z5jdHi6BmyT' },
  '@/permissions.ee/check-access': {
    userHasScopes: async (user, scopes, _global, options) =>
      scopes.some((scope) => liveUser(user, options?.projectId, scope)),
  },
  '@/node-types': { NodeTypes: class NodeTypes {} },
  '@/constants': { N8N_VERSION: '2.29.8' },
  '@/utils': { withExpressionIsolate: async (_workflow, fn) => await fn() },
  '@/workflow-execute-additional-data': { getBase: async () => ({}) },
  '@/node-execution': { EphemeralNodeExecutor: class EphemeralNodeExecutor {} },
  '@/active-executions': { ActiveExecutions: class ActiveExecutions {} },
  '@/oauth/oauth.service': { OauthService: class OauthService {} },
  '@/services/url.service': { UrlService: class UrlService {} },
  '@/services/ai.service': { AiService: class AiService {} },
  '@/services/proxy-token-manager': { ProxyTokenManager: class ProxyTokenManager {} },
  '@/utils/ai-proxy-fetch': { createAiMcpFetch: () => ({}), createAiProxyFetch: () => (() => {}) },
  '@/workflow-runner': { WorkflowRunner: class WorkflowRunner {} },
  '@/workflows/workflow-finder.service': { WorkflowFinderService: class WorkflowFinderService {} },
  './entities/agent.entity': { Agent: class Agent {} },
  './integrations/agent-chat-integration': { ChatIntegrationRegistry: class ChatIntegrationRegistry {} },
  './integrations/integration-tools': {
    createIntegrationActionTool: () => ({}),
    createIntegrationContextTool: () => ({}),
    getIntegrationToolConnectionDescriptors: () => [],
  },
  './integrations/n8n-checkpoint-storage': { N8NCheckpointStorage: class N8NCheckpointStorage {} },
  './integrations/n8n-memory': { N8nMemory: class N8nMemory {} },
  './agent-knowledge-gate': { isAgentKnowledgeBaseEnabled: () => false },
  './agent-knowledge-sandbox.service': {
    AgentKnowledgeSandboxService: class AgentKnowledgeSandboxService {},
  },
  './sub-agents/delegate-sub-agent-tool': { createN8nDelegateSubAgentTool: () => ({}) },
  './sub-agents/sub-agent-foreground-runner': {
    SubAgentForegroundRunner: class SubAgentForegroundRunner {},
  },
  './tool-registry': { buildToolRegistry: (tools) => ({ tools }) },
  './tools/environment-tool': { createGetEnvironmentTool: () => ({}) },
  './utils/sub-agent-resolver': { resolveUniqueSubAgents: async () => [] },
  './json-config/from-json-config': {
    buildFromJson: async (config, _descriptors, options) => {
      const resolved = [];
      for (const ref of config.tools ?? []) {
        const tool = await options.resolveTool(ref);
        if (tool) resolved.push(tool);
      }
      return { resolved, tool() {}, checkpoint() {}, hasCheckpointStorage: () => true };
    },
    buildProviderToolsForModel: () => [],
  },
  './json-config/mcp-client-factory': { buildMcpClientForServer: async () => ({}) },
  './json-config/model-config': { resolveCredentialAwareModelConfig: async () => ({}) },
  './repositories/agent-file.repository': { AgentFileRepository: class AgentFileRepository {} },
  './repositories/agent.repository': { AgentRepository: class AgentRepository {} },
  './runtime/agent-secure-runtime': {
    AgentSecureRuntime: class AgentSecureRuntime {
      createToolExecutor() { return { execute: async () => ({}) }; }
    },
  },
};

export function makeDoubles(state) {
  const calls = [];
  modules.state = state;
  const executor = {
    calls,
    async executeInline(request) {
      calls.push({
        nodeType: request.nodeType,
        projectId: request.projectId,
        credentialDetails: request.credentialDetails ?? null,
        nodeParameters: request.nodeParameters,
      });
      return { status: 'success', data: [{ json: { marker: state.marker } }] };
    },
    async introspectSupplyDataToolSchema() { return null; },
  };
  const credentialsFinderService = {
    async findCredentialForUser(id, user, scopes) {
      for (const scope of scopes) {
        const found = userCanReadCredential(state, user, id, scope);
        if (found) return found;
      }
      return null;
    },
  };
  const workflowFinderService = {
    async findWorkflowForUser(id, user, scopes) {
      const record = state.workflows[id];
      if (!record) return null;
      const shared = (record.sharedWith ?? []).includes(user.id);
      const scoped = scopes.some((scope) => liveUser(user, record.projectId, scope));
      return shared && scoped ? { id, name: record.name } : null;
    },
  };
  const workflowRepository = { async findOne() { return null; } };
  return { calls, executor, credentialsFinderService, workflowFinderService, workflowRepository, modules };
}
