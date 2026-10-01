// 正常任务里被 Custom MCP 节点加载的合法 MCP stdio server：按行读写 JSON-RPC，
// 支持 initialize / tools/list / tools/call 三个方法，暴露一个只做回显的工具。
// 两版校验都接受它的相对路径参数，且它本身不产生任何执行标记，用作负对照。
const readline = require('readline')

const rl = readline.createInterface({ input: process.stdin })
const TOOL = {
  name: 'ghsa_echo',
  description: 'Returns the supplied text unchanged.',
  inputSchema: {
    type: 'object',
    properties: { text: { type: 'string' } },
    required: ['text']
  }
}

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n')
}

rl.on('line', (line) => {
  if (!line.trim()) return
  let request
  try {
    request = JSON.parse(line)
  } catch {
    return
  }
  const { id, method } = request
  if (id === undefined) return
  if (method === 'initialize') {
    process.stderr.write('ghsa-benign-mcp-source: stdio child started\n')
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: (request.params && request.params.protocolVersion) || '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'ghsa-benign-mcp-source', version: '1.0.0' }
      }
    })
  } else if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: [TOOL] } })
  } else if (method === 'tools/call') {
    const args = (request.params && request.params.arguments) || {}
    send({
      jsonrpc: '2.0',
      id,
      result: { content: [{ type: 'text', text: String(args.text === undefined ? '' : args.text) }] }
    })
  } else {
    send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } })
  }
})
