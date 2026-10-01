# fixtures

固定输入，供 `reproduce.py` 在镜像内读取。攻击与正常输入各一份。攻击命令是上游修复提交
`ccf3b30b08c5268c0c2c5b84e8e3d239deaf7d05`（release `b19d2629…`，`safeinstall-cli@0.10.2`）
新增回归语料 `tests/fixtures/bypass-corpus/*.json` 里 `input` 字段的**逐字**取值，另加一条最简
安装作为正对照、一条 path-qualified 调用覆盖公告里的改写一致性要求。

- `attack.json`：coding agent 可能被诱导执行的原始包管理命令文本。
  - `baseline-plain-install`：最简形式 `npm install evil-pkg`。两版都必须识别为安装；
    它用来证明「没有发现」不是解析器整体失效造成的。
  - `case-sensitivity` 组：`NPM` / `Npm` / `PNPM` / `Bun` / `SUDO` 大小写变体。漏洞版
    `basename()` 不折叠大小写，查表失败 → 零发现；修复版折叠大小写后得到 install 发现。
  - `redirection-prefix` 组：`< in`、`> out`、`>out`、`2>err`、`{audit}>out` 五种前导重定向。
    漏洞版把重定向 token 当作命令位置；修复版跳过重定向及其目标后得到 install 发现。
  - `wrapper-flag` 组：`sudo -u root`、`sudo -E`、`command -p`、`env -i`、`env -S '…'`、`time -p`。
    漏洞版只跳 wrapper 名字、把 wrapper 选项当命令位置；修复版按元数表扫描选项。其中
    `env -S` 的值是第二层命令语言，修复版不做猜测而是显式失败关闭（`unanalyzable`）。
  - `remote-exec-subcommand` 组：`npm create`、`npm init`、`pnpm create`、`yarn create`。
    漏洞版把它们列入非安装子命令而放行；修复版走远程 runner 审批（`runners` 发现）。
  - `routing` 组：`/usr/bin/npm install evil-pkg`。两版都识别为安装，只有改写后的
    manager 名不同（漏洞版保留路径文本，修复版规范化为 `safeinstall npm …`）。
- `benign.json`：普通开发命令。固定版本 `npm install lodash@4.17.21`（正常安装）、
  `npm run build`（非安装子命令，不应被标记）、`safeinstall npm install lodash@4.17.21`
  （已走 safeinstall，不应被二次处理）。

每条命令带 `expect_vulnerable` / `expect_patched` 两个字段，取值来自 `expectation_vocabulary`：
`install_finding`、`runner_finding`、`unanalyzable`、`no_finding`、`uses_safeinstall`。它们是
对固定 revision 解析结果的声明，`reproduce.py` 会把声明与上游返回的原始结果一起写进效果文件，
供判定阶段逐条比对。声明值已在本地用 `sha256` 与公告一致的 npm tarball（0.10.1
`9dfc5232…`、0.10.2 `13f6f19c…`）跑 `analyzeShellCommand()` 逐条核对，22 条攻击 + 3 条正常
全部一致。

`evil-pkg`、`vite`、`foo` 只作为命令文本里的包名 marker，不会被下载或执行：`reproduce.py`
只调用 guard 的纯解析函数，不运行任何包管理器。真实下载与生命周期脚本执行不在本复现范围内。

已登记到 `manifest.toml` 的 SHA-256；新增或修改 fixture 后重新生成 manifest。
