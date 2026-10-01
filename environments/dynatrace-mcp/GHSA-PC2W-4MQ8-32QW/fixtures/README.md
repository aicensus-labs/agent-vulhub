# fixtures

固定输入与无害效果载体，全部为合成内容，不含真实凭据或真实租户数据。

| 文件 | 作用 |
| --- | --- |
| `attack_tool_call.json` | 攻击场景的 `tools/call` 参数：含攻击者可控的 `name` / `description` / `content`，其中 `dql` 段的文本带 `ATTACK-PAYLOAD-MARKER-9c41d2`，用于在接收端确认攻击者内容确实被持久化。 |
| `benign_tool_call.json` | 正常场景的同结构参数。批准被授予时写工具必须照常工作，因此其 `dql` 段带 `BENIGN-NOTEBOOK-MARKER-3a77e1`。 |
| `client_policy.json` | 调用方的固定行为：`attack` 不声明 elicitation 能力（无人可批准，fail-closed），`benign` 声明 elicitation 能力并返回 `accept` + `approval = true`。 |
| `mock_document_response.json` | 受控接收端对 `POST /platform/document/v1/documents` 的最小响应（201 + 含 `id` 的文档对象），供上游 `DocumentsClient.createDocument` 正常返回。 |
| `tls/ca.crt` | 合成接收端的自签 CA，运行时通过 `NODE_EXTRA_CA_CERTS` 交给被测进程。 |
| `tls/server.crt` | 合成接收端证书，SAN = `abc12345.apps.dynatrace.com`（上游只接受以 `.apps.dynatrace.com` 结尾且含 `abc12345` 的 `DT_ENVIRONMENT`）。 |
| `tls/server.key` | 上述证书的私钥，只用于本地合成接收端，不是任何真实服务的密钥。 |

`manifest.toml` 记录除 `manifest.toml` 与 `README.md` 之外每个文件的 SHA-256；改动任何 fixture 都必须重算。
