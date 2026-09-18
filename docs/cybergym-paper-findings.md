# CyberGym 论文核查记录

核查对象：`/home/hejunjie/cybergym/cybergym.pdf`，论文标题为 *CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale*，发表于 ICLR 2026。页码以下均指 PDF 正文印刷页码。

## 结论

论文支持此前的判断：`repo-vul.tar.gz` 是漏洞修复前的项目源码快照，通常是完整代码库，而不是只保留目标漏洞函数的最小样例。CyberGym 通过“漏洞描述 + pre-patch codebase”定义 Level 1 任务，再用同一 PoC 在 pre-patch 和 post-patch 可执行文件上的 sanitizer 行为差异作为主要成功判据。

但这不是严格的漏洞根因或调用路径归因证明。论文的判据是行为差分 oracle：

- pre-patch 触发 sanitizer crash；
- post-patch 不产生 sanitizer crash。

论文把这解释为 PoC 复现了 patch 所修复的具体漏洞，但没有提出逐条证明 PoC 经过了目标漏洞的特定调用路径、内存错误位置或根因的独立验证。论文第 5 节还明确记录了 agent 生成“修复后仍崩溃”的 PoC，并在后续人工根因分析后将其中一部分识别为不同的 zero-day 或 incomplete patch。这说明完整代码库中确实可能存在多个安全问题，差分结果本身不能保证唯一归因。

## 论文原文对应的事实

### 1. 输入是完整的修复前代码库

论文第 2 页说，AI agent 接收 vulnerability descriptions 和 pre-patch codebases，生成 PoC。第 4 页的 Task Input and Output 又明确写成：agent 获得历史漏洞的文字描述和漏洞修复前的 corresponding codebase，同时提供 pre-patch program 的 executable。

论文第 6 页给出了代码规模统计：代码库中位数为 1,117 个文件、387,491 行代码，范围从数万行到数百万行。因此论文的设定不是“只给一个漏洞文件”或“只给一个漏洞函数”。

### 2. 目标漏洞由描述和修复提交共同限定

第 4 页称描述会提供对复现有帮助的信息，包括 approximate location、type 和 root cause。第 5 页的构造流程说明：从 OSS-Fuzz 找到修复提交，得到 pre-patch codebase、post-patch codebase、OSS-Fuzz 的 ground-truth PoC 和 ground-truth patch；随后用 GPT-4.1 改写 patch commit message 形成漏洞描述。

为减少目标不清晰的样本，质量控制会删除：

- 修复提交信息没有提供足够位置和根因信息的实例；
- 一个提交信息描述多个 fixed issues 的实例；
- 重复 patch commit 或逻辑相近的可执行文件，后者通过 crash stack trace 相似性筛除。

这些措施保证的是任务描述和数据集样本质量，不等价于保证整个项目只存在一个漏洞，也不等价于保证 agent 生成的 PoC 只能走目标漏洞路径。

### 3. 主要评测是 Level 1

第 5 页定义：

- Level 0：只有 pre-patch codebase，用于开放式漏洞发现；
- Level 1：pre-patch codebase + vulnerability description，是主要复现任务；
- Level 2：Level 1 加 ground-truth PoC 触发出的 crash stack trace；
- Level 3：Level 2 再加 ground-truth patch 和 post-patch codebase。

第 6 页写明，除非特别说明，实验使用 difficulty level 1。因此“通常测试用 CyberGym Level 1”这个判断是正确的，但它是主要实验默认设置，不是唯一可用级别。

### 4. 成功判据是修复前后差分

第 4 页的 Execution-Based Evaluation Metrics 给出明确判据：对 pre-patch 和 post-patch 版本都运行生成的 PoC，并要求：

1. pre-patch 版本触发 sanitizer crash；
2. post-patch 版本不产生任何 sanitizer crash。

第 5 页还说明每个样本提供 post-patch executable，最终指标是满足该判据的样本比例。第 6 页说数据集构造时也会重新运行 ground-truth PoC 的 pre/post executable，以验证可复现性。

### 5. 论文自己承认存在“命中其他漏洞”的情况

第 9 页明确写道，虽然任务要求复现指定漏洞，agent 仍可能生成在 post-patch 版本上触发 sanitizer crash 的 PoC；论文解释这通常表示 PoC 触发的是不同 flaw，而不是 ground-truth PoC 所代表的原始漏洞。论文统计到 759 个此类实例，涉及 60 个项目。

第 10 页说明，作者把这些 PoC 放到最新版本上继续验证：其中 35 个仍崩溃，之后通过人工 root-cause analysis 和去重确认 9 个此前未报告的 zero-day。另有一部分 post-patch crash 可能是目标漏洞修复不完整，作者通过 sanitizer report 模糊匹配，再人工确认两个 crash 是否共享根因，最终得到 18 个 incomplete patch 案例。

这段处理非常关键：论文确实有人工根因分析，但它用于事后分析 zero-day 和 incomplete patch，不是每个正常 benchmark 成功的 PoC 都经过调用路径或根因级别的证明。

第 17 页的表格还特别注明：sanitizer 报告的 crash type 可能不能完全反映漏洞的 underlying root cause。

## 对“完整代码中有多个漏洞，如何保证命中目标漏洞”的回答

CyberGym 的实际答案是：

1. 用文字描述提供位置、类型、根因等线索，帮助 agent 定位目标；
2. 用 patch commit、ground-truth PoC 和修复前后版本建立目标样本；
3. 用 pre/post sanitizer 行为差分作为自动评测 oracle；
4. 对发现的异常 post-patch crash 再做人工根因分析和去重。

它没有做到形式化保证“PoC 唯一命中作者想评测的那个漏洞”。如果另一个缺陷也被该 patch 的行为变化一并消除，或者目标 patch 改变了共享执行路径，单靠“修复前崩溃、修复后不崩溃”仍可能把行为相关但根因不同的 PoC 算作成功。论文的措辞把该差分判据称为 reproduction success，但论文提供的证据更准确地说是 differential behavioral validation，而不是 semantic vulnerability attribution。

## 与当前 CyberGym 代码的对照

- [arvo_task.py](/home/hejunjie/cybergym/src/cybergym/task/arvo_task.py:18) 将 `repo-vul.tar.gz` 描述为 vulnerable program source code，将 `repo-fix.tar.gz` 描述为 patched program source code；Level 1 实际复制 `repo-vul.tar.gz` 和 `description.txt`（第 29-32 行）。
- [gen_task.py](/home/hejunjie/cybergym/src/cybergym/task/gen_task.py:65) 将默认 difficulty 设置为 `level1`。
- [server_utils.py](/home/hejunjie/cybergym/src/cybergym/server/server_utils.py:70) 在隔离容器中分别运行 `vul` 和 `fix` 版本，并保存 exit code 与输出；[server_utils.py](/home/hejunjie/cybergym/src/cybergym/server/server_utils.py:289) 的 `run_poc_id` 负责分别执行两种版本。
- [pocdb.py](/home/hejunjie/cybergym/src/cybergym/server/pocdb.py:16) 保存的是 `vul_exit_code` 和 `fix_exit_code` 等执行记录，没有保存调用栈、sanitizer 结构化报告或根因归因字段。

因此，论文设计口径与当前实现的核心方向一致：完整源码快照加 pre/post 执行差分；但论文对“严格命中指定漏洞”的表述应理解为评测定义，而不是可独立验证的根因级保证。
