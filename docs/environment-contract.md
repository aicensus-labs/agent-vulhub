# 环境与执行协议 v1

已确认设计的执行规范。当前索引包含 6 个真实上游源码环境，均为 `draft`；模板和合成工具测试不代表漏洞已复现。

## 固定源码与构建

环境 ID 为 `<product>/<CVE-ID>`，目录和索引沿用原布局。两个变体分别记录完整上游 commit、版本、源码 URL、`archive`（build.inputs 的名称）和已发布镜像 digest。完整安装上游版本，允许直接调用内部函数，不能抽取或重写漏洞函数代替产品。

`build.base_image` 固定 digest；`build.inputs` 每项包含简单文件名 `name`、HTTPS `url`、`sha256`。源码归档、语言依赖和系统软件包通过清单校验，缓存到 `.cache/sha256/`。构建器把它们放进临时上下文 `inputs/`，Docker build 使用 `--network none`，配方必须离线安装。`--offline` 还禁止下载和拉取，缺缓存明确失败；基础镜像也必须已缓存。

Dockerfile 使用 `ARG BASE_IMAGE`、`FROM ${BASE_IMAGE}`，接收 `VARIANT`、`SOURCE_COMMIT`、`SOURCE_ARCHIVE`。首版配方使用同一固定基础镜像，拒绝 ADD 和匿名 VOLUME；依赖是否完整、安装是否忠于上游仍由维护者审阅。构建器写入 revision 和实验输入指纹 label，运行前核对。

GHCR 正式镜像用 `image@sha256:...`；本地源码构建用 Docker 返回的不可变 image ID `sha256:...`，保存在 build.json。这细化 ADR-0004：本地实验无需先上传，image ID 不冒充仓库摘要，相同输入也不承诺逐字节相同产物。ready 元数据仍要求提供固定的可分发镜像 digest。

## 标准入口

```sh
python3 -m runner new <product> <CVE-ID>
python3 -m runner check
python3 -m runner lint
python3 -m runner fetch <product>/<CVE-ID>
python3 -m runner build <product>/<CVE-ID> --offline
python3 -m runner reproduce <product>/<CVE-ID> --build --rounds 3
python3 -m runner reproduce <product>/<CVE-ID> --images <build.json> --offline
python3 -m runner reproduce <product>/<CVE-ID> --rounds 3
python3 -m runner publish <product>/<CVE-ID> --images <build.json> --repository ghcr.io/<owner>/<package>
python3 -m runner promote <product>/<CVE-ID> --report <report.json> --reviewer <login> --reviewed
python3 -m runner refresh
```

默认 reproduce 使用元数据镜像，`--build` 选择完整源码构建；两条路径均受支持。`--scenario vulnerable|patched|benign` 用于局部调试，局部通过不满足晋升。`--timeout` 为单测试执行总期限（秒），构建、拉取另有命令超时，清理独立限时。下载设 socket 超时和 2 GiB 单文件上限，无自动重试。

check 纯文件静态校验，不调用 Docker；lint 使用 Compose CLI 的 JSON 解析，不拉取、不构建、不运行环境。draft 模板可保留占位字段，不得宣称通过。

publish 仅在显式调用时上传 GHCR，要求维护者事先 docker login；输出 publication.json，维护者将两版 digest 填入 metadata 后重新验收。普通运行没有写仓库权限，也不会自动发布。

## 编排与隔离

目标服务固定命名 vulnerable、patched，各自同名 profile 和对应镜像变量。Compose 本身不保证 profile 互斥，由运行器选择；禁止依赖启动另一个变体。每轮四个独立测试：漏洞版 attack、修复版 attack、漏洞版 benign、修复版 benign。每个测试都创建唯一 project、网络、volume。

`runtime.mode = "oneshot"` 时，运行器创建保活进程后分别执行 PoC、验证器。`runtime.harness` 只能是 `python3` 或 `node`，并决定两脚本的解释器；镜像必须提供对应程序。`mode = "service"` 时先启动真实服务并等待 healthy，再通过独立 docker exec 进程执行两脚本。辅助数据库/队列/接收器必须固定镜像并声明 healthcheck。

入口为 /lab/reproduce.py、/lab/verify.py，fixtures 放在 /lab/fixtures，/lab/results 使用本项目命名 volume。默认内部网络、无端口/宿主目录/特权/额外 capability，必须 ALL cap_drop、no-new-privileges、正数 CPU/内存/PID 限制。拒绝外部 volume、固定资源名、自动 restart、env_file、secrets/configs 和未支持字段，避免静默绕过检查。

例外在 runtime.exceptions 逐条写明 `{rule = "network.lab.internal", reason = "具体理由"}`，使用校验错误给出的精确规则名，README 解释范围；执行需 --allow-exceptions，晋升需两位审阅者。未知配置依然拒绝。宿主逃逸相关实验必须使用独立可销毁 VM；不能满足无害效果要求的案例保持 draft。

## 证据协议

两脚本接受 `--context /lab/results/context.json --output /lab/results`。context 含 schema_version=1、run_id、case_id、variant、scenario（attack/benign）。两种文档都原样带上这些标识，拒绝跨运行复用。

PoC 运行真实代码后输出 facts.json 与效果文件。预期的修复拒绝也属于执行完成；PoC 0 只代表执行完成，1 执行失败，2 未实现/缺前提。攻击、正常输入、固定模型输出纳入 fixtures，在 fixtures/manifest.toml 的 [files] 中按相对路径记录 SHA-256（manifest 和 README 除外）。seed 和所需变量显式固定；替身不能替换被验证的漏洞代码。

```json
{
  "schema_version": 1,
  "run_id": "example-run",
  "case_id": "01-vulnerable-attack",
  "variant": "vulnerable",
  "scenario": "attack",
  "execution_status": "completed",
  "evidence": [{"path": "observation.json", "sha256": "<64位小写SHA-256>"}]
}
```

验证器只读事实和实际效果，不能重跑攻击，输出带相同标识的 verdict.json。outcome 为 passed/failed，checks 至少包含 target_ready 和对应的 vulnerable_effect_observed、patched_effect_blocked 或 benign_task_passed。每项必须有唯一 id、布尔 passed、reason、expected、actual、非空 evidence 路径列表。文件必须存在、无越界或符号链接，哈希匹配。示例失败检查：

```json
{
  "id": "patched_effect_blocked",
  "passed": false,
  "expected": "请求被产品拒绝且没有越界文件",
  "actual": "越界 canary 文件仍存在",
  "reason": "修复版依然产生受控越界效果",
  "evidence": ["observation.json"]
}
```

所有检查一致通过才能输出 passed；验证器 0/1 与结论一致，2 表示无法验证。缺证据、启动失败、超时不能算修复阻断。独立进程是职责边界，不是防恶意 PoC 的密码学保障；维护者必须检查采集逻辑，PoC 不得直接制造 canary 冒充产品效果。真实模型入口独立保留，首版 runner 只编排 mechanism。

## 报告与失败说明

results/<product>/<CVE-ID>/<run-id>/report.json 汇总结果。每测试目录有宿主生成的 result.json、normalized Compose 配置、命令 stdout/stderr、容器采集的 evidence/。脚本无法覆盖宿主报告的版本和阶段字段。

CLI 退出码为 0 所选测试通过、1 已执行但 PoC/断言失败、2 未运行/前提不足、3 基础设施/协议/清理错误；混合失败按 3 > 2 > 1 汇总。失败记录含阶段、预期、实际、分类及日志位置；启动前失败也有顶层报告。

| 情况 | 解释和处理 |
| --- | --- |
| healthy 等待失败 | 检查启动和依赖日志；尚未证明修复阻断 |
| 漏洞版缺少 canary | 检查前提和输入；不能据此说漏洞不存在 |
| 修复版仍有 canary | 修复对照失败；检查修复范围及版本 |
| 正常任务失败 | 无法排除服务整体不可用，整轮不通过 |
| facts 缺失/哈希错误 | 证据不可核查，PoC 退出 0 也无效 |
| 超时 | 保留阶段和日志，不隐藏重试 |
| cleanup 失败 | 整体失败，按报告中的唯一项目标识处理残留 |
| 缓存缺失 | 用 fetch/build 下载固定输入或提前搬运缓存 |

finally 清理仅限本次 Compose project 的容器、网络、volume。--keep-on-failure 保留失败项目并在结果中列出。SIGKILL/断电不能保证 finally，CI 必须销毁整台 VM。镜像及源码缓存保留以便后续复现。

## Ready 与审阅

晋升要求来源完整、可分发镜像 digest、Linux amd64 原生环境、同组固定镜像至少 3 轮完整验收且清理成功。promote 核对每个报告与 verdict、效果文件，并归档小型可复核证据、manifest 和报告；每个证据文件上限 8 MiB。原始日志留在 CI artifact。

--reviewer/--reviewed 是维护者本地审阅声明，身份授权依赖 Git 分支保护，不是密码学签名。涉及隔离例外要两位不同审阅者。先人工审阅来源、安全效果与脱敏，再执行晋升。永久证据放在环境 evidence/<run-id>/，错误/撤回降级并追加历史。CI artifact 保留 90 天，永久证据包不得依赖过期日志才能复核。

输入指纹覆盖材料性 metadata、执行文件、fixture、runner Python 文件和本规范。变化后 check 拒绝旧 ready；refresh 或下一次执行命令自动降 draft、重置 not_run，保留旧证据。check 本身保持只读。一般说明文档、review、验证状态不参与指纹；fixture 内容和本协议例外。metadata 序列化会移除注释，首次修改留 .before-update 备份。

报告记录 Docker、Compose、daemon 平台、宿主架构和 runner 指纹。Docker/Compose 发生影响语义的更新时需重新验收；首版无法仅凭版本号自动判断语义变化。

## CI 部署前提

PR CI 只静态校验和工具测试；Docker smoke 必须显式运行。隔离 workflow 只检出默认分支，可手动/每周运行，使用 vulhub-ephemeral 标签的一次性 Linux VM。管理员须配置受保护的 vulhub-lab environment，并为每次作业新建和销毁 VM，不能把标签绑定到持久开发机；未配置则作业排队。

GHCR 登录、仓库访问控制、分支保护和 VM 供应由维护者配置，代码不会自动创建这些外部资源。实验只使用假数据和受控效果。
