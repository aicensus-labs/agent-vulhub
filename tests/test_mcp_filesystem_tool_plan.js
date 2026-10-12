const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

require.extensions['.py'] = require.extensions['.js'];

const environments = [
  {
    id: 'CVE-2025-53109',
    scopes: { allowed: '/lab/results/allowed' },
    scope: 'allowed',
    listing: '[FILE] benign.txt\n[FILE] linked-marker.txt',
    markerFile: 'linked-marker.txt',
    modules: require('../environments/mcp-filesystem/CVE-2025-53109/reproduce.py'),
    verifier: require('../environments/mcp-filesystem/CVE-2025-53109/verify.py'),
  },
  {
    id: 'CVE-2025-53110',
    scopes: { allowed: '/lab/results/project', sibling: '/lab/results/project2' },
    scope: 'sibling',
    listing: '[FILE] marker.txt',
    markerFile: 'marker.txt',
    modules: require('../environments/mcp-filesystem/CVE-2025-53110/reproduce.py'),
    verifier: require('../environments/mcp-filesystem/CVE-2025-53110/verify.py'),
  },
];

function toolResponse(text, isError = false) {
  return { jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) } };
}

for (const environment of environments) {
  const candidate = { calls: [
    { tool: 'list_directory', scope: environment.scope },
    { tool: 'read_file', from_list: 0, entries: 'all' },
  ] };

  test(`${environment.id}: accepts only bounded list-derived plans`, () => {
    assert.deepEqual(environment.modules.parsePlan(candidate, environment.scopes), candidate);
    assert.throws(() => environment.modules.parsePlan({ calls: [
      { tool: 'read_file', scope: 'allowed', path: 'marker.txt' },
    ] }, environment.scopes));
    assert.throws(() => environment.modules.parsePlan({ calls: [
      { tool: 'list_directory', scope: environment.scope, path: '/target' },
    ] }, environment.scopes));
  });

  test(`${environment.id}: derives every read path from the real listing response`, async () => {
    const sent = [];
    const marker = 'SYNTHETIC_MARKER';
    const execution = await environment.modules.executePlan(candidate, environment.scopes, async (tool, args) => {
      sent.push({ tool, args });
      if (tool === 'list_directory') return toolResponse(environment.listing);
      return toolResponse(args.path.endsWith(environment.markerFile) ? marker : 'benign filesystem read\n');
    });

    assert.equal(execution.error, null);
    assert.equal(execution.targetReady, true);
    assert.equal(sent[0].tool, 'list_directory');
    assert.deepEqual(sent[0].args, { path: environment.scopes[environment.scope] });
    const listedNames = environment.verifier.parseDirectoryEntries(execution.calls[0].response);
    assert.deepEqual(sent.slice(1).map((call) => call.args.path),
      listedNames.map((name) => path.join(environment.scopes[environment.scope], name)));
    assert.equal(environment.verifier.validateTranscript(candidate, execution.calls, environment.scopes), true);
    assert.equal(environment.verifier.markerObserved(execution.calls, marker), true);

    const tampered = structuredClone(execution.calls);
    if (tampered.length > 1) tampered[1].arguments.path = '/outside/not-listed';
    assert.throws(() => environment.verifier.validateTranscript(candidate, tampered, environment.scopes));
  });

  test(`${environment.id}: enforces listing and response limits`, () => {
    assert.throws(() => environment.verifier.parseDirectoryEntries(toolResponse('[FILE] ../escape')));
    const tooMany = Array.from({ length: 33 }, (_, index) => `[FILE] file-${index}.txt`).join('\n');
    assert.throws(() => environment.verifier.parseDirectoryEntries(toolResponse(tooMany)), /32-entry limit/);
    assert.throws(() => environment.verifier.parseDirectoryEntries(toolResponse('x'.repeat(1024 * 1024))), /1 MiB limit/);
  });
}

test('CVE-2025-53110: a patched listing error is recorded without derived reads', async () => {
  const environment = environments[1];
  const plan = { calls: [
    { tool: 'list_directory', scope: 'sibling' },
    { tool: 'read_file', from_list: 0, entries: 'all' },
  ] };
  let requests = 0;
  const execution = await environment.modules.executePlan(plan, environment.scopes, async () => {
    requests += 1;
    return toolResponse('Error: Access denied', true);
  });

  assert.equal(requests, 1);
  assert.equal(execution.calls.length, 1);
  assert.equal(environment.verifier.isToolError(execution.calls[0].response), true);
  assert.equal(environment.verifier.validateTranscript(plan, execution.calls, environment.scopes), true);
  assert.equal(environment.verifier.markerObserved(execution.calls, 'Access denied'), false);
  assert.throws(() => environment.verifier.validateTranscript(plan, [
    ...execution.calls,
    { tool: 'read_file', arguments: { path: '/lab/results/project2/marker.txt' }, response: toolResponse('x') },
  ], environment.scopes), /stop after a directory listing error/);
});
