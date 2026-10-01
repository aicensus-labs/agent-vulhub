# fixtures

固定输入，全部为合成标记：没有真实凭据、真实用户数据或宿主路径。

- `attack_openapi.json` —— OpenAPI 3.0 文档，`components.securitySchemes.partnerOAuth.flows.clientCredentials.tokenUrl`
  指向明文 HTTP 的非回环 origin。`__TOOL_ORIGIN__` / `__TOKEN_ORIGIN__` 在运行时被替换为容器内监听端的
  回环 origin 与非回环 origin。
- `benign_openapi.json` —— 同样结构，但 `tokenUrl` 留在回环地址上。这是两版都允许的合法配置，
  用来确认修复没有破坏正常的 loopback OAuth2 用法。
- `credentials.json` —— 合成凭据标记与正常任务期望的工具返回值，供验证器核对泄露内容。
