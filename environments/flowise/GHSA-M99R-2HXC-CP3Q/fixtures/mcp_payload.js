// 攻击者预先落盘的服务端脚本。Custom MCP 节点配置通过校验后，这段代码由被
// spawn 的 node 子进程加载执行：它把一行执行标记写进继承来的工作目录，用来证明
// 服务器上确实发生了任意代码执行。除写标记外不做任何其他动作。
const fs = require('fs')
const marker = '.ghsa-mcp-child-effect.txt'
fs.writeFileSync(marker, 'ghsa-mcp-stdio-child-executed ' + process.argv[1] + '\n')
process.exit(0)
