# Build and Reference Immutable Experiment Images

每个 CVE 环境必须从仓库内 Dockerfile 和构建上下文生成漏洞版、修复版实验镜像。**构建输入的固定是复现性的唯一必要条件**：源码使用完整 commit SHA，`build.inputs` 中每个输入记录 URL 与 SHA256，基础镜像使用 digest，并保证 `--offline` 构建可复现。Compose 与结果证据只引用不可变引用。

**已发布镜像的 digest 是可选的**：当环境把镜像推送到 registry 时，`metadata.toml` 的两版 `image` 必须写成 `repo@sha256:<64hex>` 形式的不可变 digest（`ready` 门禁强制）；未发布镜像的环境该字段留空，其复现性由构建输入保证，由使用者自行构建。

这样既保留了可追溯的构建来源，又避免把"必须运营 registry"变成每个环境的硬性要求。

**Status**: accepted

## Context

原版要求"最终镜像 digest 写入 `metadata.toml`"，即每个环境都必须发布镜像。实践中有两个问题：

1. **构建并非逐字节可复现**。实测：相同声明输入（`input_binding` 一致）两次构建产出不同 image ID，尽管 12 个层的 digest 完全相同、Config 的 Env/Cmd/Labels 也相同。因此 digest 只有在**由构建者固定并分发**时才有意义——否则它记录的是某一次本地构建的产物，使用者重建会得到不同的 digest，该字段无法被验证。
2. **强制发布把 registry 运营变成硬性门槛**。每个环境约 0.9GB，39 个环境约 34GB；可见性、配额、命名与清理都需要持续投入。实测 container package 的可见性没有 REST API，只能由 org admin 在网页逐次设置。

## Decision

把"构建可复现"与"镜像可分发"解耦：

- **必须**：固定源码 commit、固定每个构建输入的 SHA256 与 URL、固定基础镜像 digest、`--offline` 可构建。
- **可选**：发布镜像。发布时 `image` 必须是 digest 固定引用；不发布时留空，`ready` 门禁不因此拒绝。
- 未发布镜像的环境，`ready` 的含义是"构建输入固定且三轮验收在此输入上通过"，而不是"镜像已可下载"。

## Alternatives considered

**主流同类数据集的做法**（2026-09 调研）：

| 数据集 | 规模 | 分发方式 | 是否分发镜像 |
| --- | --- | --- | --- |
| ARVO | 6,100+ | Docker Hub 单仓库 `n132/arvo` | 是，tag `25402-vul`/`25402-fix` |
| CyberGym | 1,507 | HuggingFace 源码 tarball（`repo-vul.tar.gz`，约 240GB） | **否**，本地构建 |
| CVE-Factory | 3,181+ | HuggingFace 任务包（Dockerfile + compose + test） | **否**，用户构建 |
| Vulhub | 250+ CVE | GitHub + Docker Hub `vulhub/*` | 复杂应用是，简单用 `build: .` |

结论：**分发构建输入是主流**。CyberGym 与 CVE-Factory 两个基准都不分发镜像；只有 ARVO 分发，而 ARVO 是 OSS-Fuzz 谱系，其构建体积大、耗时长，自建不现实——我们的环境实测单个重建约 36 秒，自建完全可行。

**ARVO 的仓库组织**值得记录：它把 23,900 个 tag 放在**单个** Docker Hub 仓库里，tag 命名 `{bug_id}-{vul|fix}`，且每个 tag 都解析到 digest。这说明"单仓库 + 多 tag"能撑到几千规模，也说明业界普遍用 tag 寻址、需要时才取 digest。

被否决的方案：

1. **保持原版（强制发布）**——比主流更严，但代价是把 registry 运营变成每个环境的门槛，且与"构建不可逐字节复现"这一实测事实冲突。
2. **完全去掉 digest 要求**——会丢失"我们实际验证过的是哪个镜像"这一信息，对已发布的环境不可接受。
3. **改用 tag 寻址（如 ARVO）**——tag 可变，会让 `ready` 证据绑定的对象漂移；digest 更严格且不增加成本，故保留。

## Consequences

- 未发布镜像的环境也能达到 `ready`，其可复现性来自固定输入，使用者用 `runner reproduce <env> --build` 自行构建并验证。
- 已发布镜像的环境额外提供"免构建"路径，使用者可直接拉取 digest。
- `runner publish` 保持显式操作，不进入默认流程；`runner prune` 清理发布产生的无 tag 版本。
- 若日后需要把已 `ready` 但未发布的环境补上镜像，`publish` → 回填 digest → `reproduce --rounds 3` → `promote` 的顺序不变（digest 必须在生成验收报告之前写入，否则报告立即过期）。
