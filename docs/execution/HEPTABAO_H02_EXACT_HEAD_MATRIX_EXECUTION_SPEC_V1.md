# HeptaBao H02 Exact-Head Matrix Execution Specification V1

**状态：** `NORMATIVE / IMPLEMENTATION_ACTIVE / NOT_QUALIFIED / AUTHORITY_EFFECT_NONE`  
**适用范围：** H02 OpenRaft candidate、in-memory cluster、hostile snapshot、OS/durable/clock closure 与 logical durable-store probe  
**执行器：** `scripts/h02_exact_head_matrix_v1.py`  
**机器摘要：** `schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json`  
**主执行 workflow：** `.github/workflows/plan-integrity-v4.yml`  
**低扇出备用 workflow：** `.github/workflows/h02-final-gap-closure-arm64.yml`  
**关联 blocker：** `HB-BLK-REPO-004`、`HB-BLK-REPO-006`–`011`、`HB-BLK-REPO-013`

## 1. 目的

本规范把 H02 exact-head 技术闭环定义为一个完整、不可选择性丢失、同时验证 process transport、application semantics、source identity 与 aggregate closure 的证据生产过程。它防止下列错误成功：

- 第一个非零退出使 shell 提前终止，后续 toolchain、seed 或 probe 没有执行；
- 进程退出码为 0，但应用 JSON 明确报告 `EXECUTED_FAIL`、`BLOCKED`、`UNKNOWN` 或 `UNEXECUTED`；
- 调用方伪造 repository、commit、tree 或 clean-tree 元数据；
- 运行期间 source head/tree 变化或工作区变脏，却复用旧 summary；
- JSON/JSONL malformed、case 重复、case 缺失、authority drift 或 guarded-state change 被当作通过；
- 超时只杀死 `cargo` 父进程，遗留 child/grandchild 持续修改临时状态；
- required entry ID 重复并掩盖另一个缺失 entry；
- 只保留 stdout，丢失 stderr、exit code、command、duration、失败 seed 或 timeout；
- 在 source、manifest 或 lock drift 后复用旧证据；
- 技术矩阵通过后自动选择 OpenRaft 或授予任何 authority。

## 2. 固定矩阵

V1 required matrix 固定为：

```text
2 toolchains × 3 seeds × 4 probe kinds = 24 entries
```

### 2.1 Toolchains

- Rust `1.88.0`：OpenRaft alpha.33 exact graph 的 effective floor；
- Rust `1.98.0`：当前 HeptaBao development baseline。

Rust 1.85–1.87 的边界失败由单独 MSRV lane 记录，不得冒充本矩阵中的有效通过 entry。

### 2.2 Seeds

- `0x5eed20260828cafe`
- `0x8badf00d12345678`
- `0xd15ea5e5cafef00d`

任何 seed 失败都使 summary 为 `FAIL`。禁止只重跑成功 seed、删除失败 entry 或用不同 seed 替换失败 seed。

### 2.3 Probe kinds

| Kind | Binary | Application result 通过条件 |
|---|---|---|
| `inmemory` | `heptabao-h02-openraft-inmemory-cluster` | 一个 meta + 六个唯一 case；全部 `PASS`；测试内存边界与 authority 常量正确 |
| `hostile` | `heptabao-h02-openraft-fault-lab --mode hostile-snapshot-parent` | schema 精确；phase reached；status=`EXECUTED_PASS`；outcome=`REJECTED_OR_ABORTED_AFTER_INJECTION`；authority 常量正确 |
| `blocker` | `heptabao-h02-openraft-blocker-closure-lab --mode all` | 总状态及 OS suspend、durable faults、clock faults 三个 component 均为 `EXECUTED_PASS` |
| `durable` | `heptabao-h02-openraft-durable-store-lab` | 七个唯一 case 全部 `PASS`；persist-before-publish、atomic bundle、restart、ReadIndex、corruption rejection 均成立；不得声称 kernel power loss 或 production selection |

## 3. 四层判定模型

每个 entry 和最终 matrix 同时受四层约束：

1. **Source result**：实际 Git root、`HEAD`、`HEAD^{tree}`、clean tree、canonical manifest 与 committed lock；
2. **Process result**：进程是否启动、是否超时、exit code；
3. **Application result**：JSON/JSONL status、case 集合与安全不变量；
4. **Aggregate result**：24 entries、唯一 ID、计数、command/output digest 与 source freshness。

每个 PASS entry 必须同时满足：

```text
source binding valid
AND process_started = true
AND timed_out = false
AND process exit code = 0
AND application_status = EXECUTED_PASS
AND semantic validation errors = []
```

Process result 只是 transport evidence，不是应用正确性证明。分类规则固定为：

| Process | Application | 最终 entry conclusion |
|---|---|---|
| exit 0 | `EXECUTED_PASS` 且全部结构/不变量满足 | `PASS` |
| exit 0 | `EXECUTED_FAIL` / case `FAIL` / guarded-state change | `FAIL` |
| 任意 | malformed output、字段缺失、case 重复/缺失或 authority drift | `FAIL` |
| 非 0 | 输出声称 `EXECUTED_PASS` | `FAIL` |
| 非 0 | 输出明确 `BLOCKED` | `BLOCKED` |
| 非 0 | 输出明确 `UNKNOWN` | `UNKNOWN` |
| 无 exit | process 未启动 | `UNEXECUTED` |
| timeout | 任意已产生或未产生输出 | `BLOCKED`，同时记录 process-level timeout error |

超时分类为 `BLOCKED` 只保留原因语义，不会弱化 final gate：任何 `blocked>0` 都使 matrix `FAIL`。Hostile-snapshot binary 自身必须保证 `EXECUTED_FAIL` 返回非零；聚合执行器仍独立解析 JSON，形成 defense in depth。

## 4. Exact-source 自绑定

调用方传入的 source 元数据不是信任根。执行器必须自行验证：

```text
repository = ProfHepta/HeptaBao
actual git root = script repository root
actual HEAD = declared 40-hex commit
actual HEAD^{tree} = declared 40-hex tree
git status --porcelain = empty
manifest = probes/h02/openraft-tokio/Cargo.toml
committed Cargo.lock exists
```

运行输出目录和 Cargo target 根必须位于 repository 之外，避免执行产物污染 clean-tree 检查。矩阵结束后必须再次验证 HEAD、tree 和 clean status；任何变化写入 `runner_errors` 并使 summary 失败。

Workflow 必须 checkout 显式 push/PR head SHA，使用：

```yaml
permissions:
  contents: read
persist-credentials: false
```

执行期间不得运行 `git commit`、`git push`、`git rebase`，不得修改 tracked source、policy、validator 或 evidence definition。

## 5. 进程生命周期与 timeout

每个 entry 使用 argv 数组启动，不通过 shell 字符串拼接。POSIX 平台必须为 entry 创建独立 process group/session。超过 bounded timeout 后，执行器必须终止完整 process group，并回收 stdout/stderr；只杀死直接 `cargo` process 不满足本规范。

每个 entry 必须记录：

- exact argv 与 `command_digest`；
- process_started；
- start/end UTC 与 duration；
- exit code 或不可用；
- timeout 标记；
- application status；
- semantic validation errors。

## 6. 完整保留规则

无论前一 entry 是否失败，执行器都必须继续剩余 matrix。每个 entry 至少保留：

- entry ID、kind、binary、toolchain、seed；
- command 与 SHA-256；
- stdout 原文与 SHA-256；
- stderr 原文与 SHA-256；
- exit 文件与 `exit_digest`；
- process/application/final conclusion。

输出文件以唯一 entry ID 命名，禁止覆盖。失败、blocked、unknown、unexecuted 与通过输出具有相同保留优先级。生产调用必须传入独立的 evidence directory；runner 在写出摘要前重新打开每个 `<entry_id>.stdout`、`<entry_id>.stderr`、`<entry_id>.exit`，拒绝缺失、目录、符号链接、路径穿越、重复别名或 digest 不相等的文件。`exit` sidecar 的字节内容还必须精确等于记录的退出码加换行（退出码不可用时为 `UNAVAILABLE\n`）。没有完整重读证据时，生产 runner 只能产生 `FAIL`，不能产生 `PASS`。

## 7. Machine summary

执行器生成 `matrix-summary.json`，schema 为：

```text
heptabao.h02-exact-head-matrix-summary.v1
```

失败执行允许生成 schema-valid partial summary，使已完成 entry 不会因 runner/child failure 丢失。`result=PASS` 仅在以下全部成立时允许：

```text
required entries = 24
recorded entries = 24
executed entries = 24
unique entry IDs = 24
pass = 24
fail = 0
blocked = 0
unknown = 0
unexecuted = 0
missing entry IDs = []
unexpected entry IDs = []
duplicate entry IDs = []
runner_errors = []
clean_tree = true
qualification = false
compatibility_claim = false
selection_effect = NONE
authority_effect = NONE
```

Schema-valid 只证明对象结构。Final gate 必须重新计算 entry ID 集合，并将每个 ID 绑定到 canonical kind、toolchain、seed、binary 与 exact argv；同时从实际 checkout 重算 manifest 与 committed `Cargo.lock` digest，并从传入的 evidence root 重算 stdout/stderr/exit digest 与 exit sidecar 内容、source/tree 与 authority constants。summary 本身不是签名 closure receipt。Receipt validator 的 `--h02-evidence-dir` 应指向包含 `matrix-summary.json` 及其 72 个 sidecar 的目录；省略该目录时只能做结构性检查，不能通过 completion receipt。

## 8. Workflow ordering 与低扇出备用 lane

标准顺序：

```text
checkout exact SHA
→ source self-binding
→ V1.2/V1.2.1 and Python validation
→ cargo metadata --locked
→ fmt/test/clippy on Rust 1.88 and 1.98
→ execute all 24 entries without early abort
→ write summary and raw entry files
→ upload all diagnostics with if: always()
→ independent final summary/digest gate
→ authority sentinel
```

`plan-integrity-v4` 是主 PR lane。仓库 runner 饥饿时，`h02-final-gap-closure-arm64` 提供单 runner、read-only、exact-SHA 的低扇出执行候选；它不替代独立复现，也不得比主 lane 降低任何技术 acceptance rule。

矩阵执行步骤可以内部返回非零，但 workflow 必须先完成 diagnostics upload，再由独立 final gate 失败。不得使用 `continue-on-error` 把失败伪装成成功。

## 9. Retry、flake、base drift 与 supersession

- 同一 SHA rerun 保留原 run/attempt；
- queued、steps=[]、runner_id=null/0 是 `INFRASTRUCTURE_UNEXECUTED`；
- runner/provider outage 可以 retry，但必须保留 provider/job evidence；
- 已开始 compile/runtime/semantic failure 不得回标 infrastructure；
- 修复产生新 commit 后，旧 summary 进入 superseded graph；
- flake 必须固定 seed、找出 nondeterminism root cause 并增加 deterministic control；
- commit、tree、matrix、toolchain、seed、probe、validator、schema 或 lock 变化都需要全新 summary；
- source 自绑定失败分类 `BASE_DRIFT` 或 `FAIL`，不得继续复用旧 artifacts。

## 10. 与 blocker closure receipt 的关系

Matrix summary 是 repository-controlled blocker closure receipt 的执行输入，不是最终 receipt。最终 `heptabao.blocker-closure-receipt.v1` 还必须绑定：

- normative manifest、blocker register、validator 与 dependency lock digest；
- workflow/run/attempt/job/runner identity；
- artifact provider ID 与 archive digest；
- criterion mapping 与 findings；
- required independent review；
- signature、expiry、revocation 与 supersession。

Critical blocker 不能由作者或 GitHub Actions 自行进入 `CLOSED`。

## 11. 非范围与 authority boundary

本规范不提供：

- kernel/VM power-cut 或 filesystem crash-consistency 独立实验室证据；
- per-node time namespace 或真实 kernel clock skew；
- 独立 operator/credential root/artifact custody 复现；
- OpenRaft prototype 或 production selection；
- H00/H01/H02 qualification；
- compatibility、production、migration、release 或 mixed-cluster authority。

所有 summary、workflow 与 receipt candidate 固定保持：

```text
qualification=false
compatibility_claim=false
selection_effect=NONE
authority_effect=NONE
```
