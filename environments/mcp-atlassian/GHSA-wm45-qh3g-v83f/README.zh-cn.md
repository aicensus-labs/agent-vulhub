# mcp-atlassian / GHSA-wm45-qh3g-v83f

状态：机制复现已完成，并通过四场景三轮容器验收；保持 `draft`，等待固定发布镜像和维护者审阅。

## 公告与机制

公告：GHSA-wm45-qh3g-v83f。远程 MCP attachment upload 接口接收服务器端
file_path 并直接打开该路径。旧版本没有把路径限制在工作区，远程调用者可
借助 ../ 读取服务器可读文件并把内容交给 Atlassian attachment API。修复版
在打开文件前执行工作区边界检查。

PoC 导入完整的 mcp_atlassian.jira.attachments 模块，调用真实
AttachmentsMixin.upload_attachment。Jira 客户端只是本地 recorder，用于记录
是否真的收到了打开的文件；它没有替换路径校验或上传方法。

## 前提

需要远程 MCP transport、attachment upload 工具和一个有 Jira 项目上传权限的
会话。测试输入中的 secret.txt 是仓库内 synthetic canary，工作区内的
allowed.txt 用于正常控制。PoC 不连接 Jira，也不需要模型。

## 版本与启动

漏洞版为 mcp-atlassian 0.21.0，修复版为 0.22.0；源码归档、完整 commit 和
SHA-256 在 metadata.toml 中固定。运行：

    python3 -m runner reproduce mcp-atlassian/GHSA-wm45-qh3g-v83f --build --rounds 3

Compose 只运行当前 profile，使用 runner 管理的结果 volume，不暴露宿主端口。

## 机制复现

攻击场景请求 ../fixtures/secret.txt。验证器要求漏洞版成功打开该文件并调用
Jira recorder；修复版必须在上传前拒绝 traversal，且 recorder 没有调用。benign
场景要求工作区内文件仍可上传。facts.json 与 jira_effect.json 均由 PoC
在真实方法返回后记录，verify.py 不重跑产品代码。

## 端到端复现

不适用。机制对照已经直接覆盖服务器端文件打开边界；真实 Atlassian 云服务和
模型调用会增加外部凭据与网络依赖，不能作为本环境的验收前提。

## 失败诊断

若漏洞版没有 secret.txt 的 opened path，检查工作目录和归档中的 attachment
模块；若修复版仍有 opened path 或 upload call，说明修复边界失败。Jira recorder
初始化失败、导入失败、服务启动失败和超时都不是修复阻断证据。

## 输入与隔离

所有文件都是 synthetic 内容。atlassian.Jira 仅作为未安装的外部 SDK 协作者
协议，真实 attachment mixin 和路径校验来自固定上游源码。Compose 无网络出口、
主机挂载、特权和隔离例外；引用代码与许可证来源见 metadata 的上游仓库。
