# AgentSec 关联约定

目前没有自动读写 AgentSec 数据库，也没有设置远程同步。

建议未来单独维护环境关联：

| 字段 | 说明 |
| --- | --- |
| environment_id | 仓库内稳定身份，例如 product/CVE |
| cve / aliases | 与漏洞记录关联，不能用文章标题替代 |
| repository_url | 仓库正式地址，发布前不虚构 |
| commit / path | 固定版本的环境入口 |
| lifecycle | draft / ready |
| mechanism_status | not_run / passed / failed / not_applicable |
| end_to_end_status | 独立于机制验证结果 |
| verified_at / evidence | 验证时间及可复核证据 |

前端可展示“复现环境”和验证状态；环境更新不修改原漏洞披露日期，不增加重复漏洞记录。现有 `agent_unique` 标签只用于候选召回，实际收录需复核信任边界及官方证据。
