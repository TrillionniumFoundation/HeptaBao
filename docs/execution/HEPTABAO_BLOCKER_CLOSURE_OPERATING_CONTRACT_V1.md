# HeptaBao Blocker Closure Operating Contract V1

**状态：** `NORMATIVE / FAIL_CLOSED / AUTHORITY_EFFECT_NONE`  
**适用对象：** `planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml` 中全部 blocker  
**机器收据：** `schemas/heptabao_blocker_closure_receipt_v1.schema.json`

## 1. 目的

本合同规定 blocker 从发现、归属、修复、执行、审查到关闭的唯一过程。它解决以下风险：

- 用实现状态冒充执行证据；
- 用最新绿灯覆盖旧失败；
- 在 base/head 漂移后复用旧证据；
- 把 GitHub 管理员权限、同一人员别名或 CI bot 当作独立审批；
- 把 queued、skipped、空 steps、`runner_id=0` 或未分配 runner 当作测试；
- 用 schema-valid 对象冒充已验签、未过期且未撤销的证据；
- 对矩阵只保留通过 seed 或只报告聚合成功；
- 在修复后变更代码但不重跑 exact head。

## 2. 术语

- **Blocker**：阻止 package、gate、profile 或 release 达到下一成熟度的可枚举条件。
- **Remediation**：对 blocker 原因实施的代码、文档、配置或外部行动。
- **Exact head**：执行时绑定的 repository、ref、40 位 commit、tree 和 clean-tree 状态。
- **Closure criterion**：可二值或 fail-closed 判断的单项验收条件。
- **Execution entry**：一个 toolchain/target/platform/seed/profile 组合。
- **Closure receipt**：绑定 source、plan、criteria、jobs、artifacts、review 和结果的不可变对象。
- **Independent review**：作者、runner 管理者、artifact custodian 和审批者满足所需角色分离。
- **External action package**：仓库自动化无法完成或不得自证的操作化交接合同。

## 3. Blocker 分类

### 3.1 `REPOSITORY_CONTROLLED`

可通过仓库内代码、文档、测试、schema 或 read-only CI 修复。允许自动化产生技术证据，但 critical blocker 的最终 `CLOSED` 仍要求独立 review。

### 3.2 `REPOSITORY_SETTING`

需要 GitHub/托管平台控制面变更，例如 ruleset、required checks、bypass、team ownership。仓库文件只能描述目标状态，不构成配置已经生效。

### 3.3 `EXTERNAL_*`

需要真实人员、法律判断、restricted lab、独立 credential root、HSM、事故值班或独立实验室。除非 action package completion object 已被验签并通过 freshness/revocation 检查，否则一直为 `EXTERNAL_ACTION_REQUIRED`。

## 4. 状态机

| 当前状态 | 允许的下一状态 | 必要条件 |
|---|---|---|
| `OPEN` | `OWNED` | 唯一 owner role、severity、scope、criteria 已登记 |
| `OWNED` | `REMEDIATION_IMPLEMENTED` | 修复已落到 exact branch；diff、测试设计和风险说明完整 |
| `REMEDIATION_IMPLEMENTED` | `EXACT_HEAD_EXECUTED` | 所有 required execution entries 获得真实 runner 并 PASS |
| `EXACT_HEAD_EXECUTED` | `INDEPENDENTLY_REVIEWED` | required reviewers 验证 source、结果、artifact 和残余风险 |
| `INDEPENDENTLY_REVIEWED` | `CLOSED` | 所有 criteria PASS；无 Critical/High/Unknown；receipt 当前、未撤销 |
| 任意非终态 | `BASE_DRIFT` | base、head、plan、lock、profile 或 validator 发生不兼容变化 |
| 任意非终态 | `BLOCKED_UPSTREAM` | 必要 upstream contract/版本/修复不存在 |
| 任意非终态 | `RESUME_REQUIRED` | 技术可继续但当前执行中断，必须给出精确 resume point |
| 任意状态 | `REVOKED` | 签名、来源、测试、review、dependency 或安全结论被撤销 |
| 外部类 | `EXTERNAL_ACTION_REQUIRED` | 对应外部 action package 尚未通过 |

禁止跳过中间状态。对 non-critical repository blocker，`EXACT_HEAD_EXECUTED` 可以直接进入 `CLOSED`，但 receipt 仍必须记录 review rule 为 `NOT_REQUIRED_BY_PROFILE`。

## 5. 每轮 closure loop

### 5.1 Revalidate

每轮开始必须重新读取：

```text
repository
base ref/base commit/base tree
head ref/head commit/head tree
current normative manifest
current canonical state input
blocker register
dependency lock/profile
open PR and workflow status
revocation/supersession state
```

若与 receipt 的输入不一致，停止并分类 `BASE_DRIFT`；不得静默 rebase 后继续沿用旧结果。

### 5.2 Isolate

- 一个 package/紧密耦合 blocker 集合使用一个隔离 branch/PR；
- branch 从精确 parent SHA 创建；
- 不得把 unrelated feature 混入 closure；
- 不得自合并明确要求 independent review 的 PR；
- PR body 必须声明 base/head、scope、non-scope、required lanes 和 authority boundary。

### 5.3 Remediate

修复必须同时更新：

- 实现或配置；
- normative contract；
- validator；
- positive/negative/fault regression；
- blocker register；
- threat/risk delta；
- evidence production path。

只改测试以适配错误行为、删除失败断言、扩大 timeout 掩盖死锁、降低 required matrix 或把 failure 重分类为 pass，均不构成 remediation。

### 5.4 Execute

每个 required entry 必须记录：

- workflow/run/attempt/job；
- runner ID/name/group；
- OS、architecture、image/version；
- toolchain、target、features、seed；
- source commit/tree；
- manifest/lock/config digest；
- start/end time、exit code；
- stdout/stderr/result artifact digest；
- execution outcome。

执行聚合规则：

```text
PASS          = every required entry PASS
FAIL          = any required entry FAIL
BLOCKED       = no FAIL, but at least one BLOCKED
UNKNOWN       = no FAIL/BLOCKED, but at least one UNKNOWN
UNEXECUTED    = any required entry never executed
```

不能用 job 的 GitHub `success` 替代应用级结果验证。

### 5.5 Preserve

失败 evidence 与后续修复 evidence 同等重要。至少保留：

- run/job identifiers；
- provider artifact ID/digest；
- source/plan/lock digest；
- failing seed/command/exit code；
- sanitized stderr tail；
- classification 与 disposition；
- superseding receipt reference。

不得删除失败 run、删除 artifact 引用、重写历史状态或只上传最终通过结果。

### 5.6 Review

Reviewer 必须重新计算或验证：

- exact-source binding；
- criteria mapping；
- test matrix completeness；
- no dropped failures；
- secret canary；
- source/lock/artifact digest；
- reviewer identity/role/COI；
- time validity；
- revocation/supersession；
- remaining risk。

作者可以解释和修复，但不能作为 critical blocker 的唯一 approver。

### 5.7 Close

`CLOSED` 只在以下全部成立时允许：

```text
all criteria PASS
all required entries executed
failed = 0
blocked = 0
unknown = 0
unexecuted = 0
critical/high/unclassified findings = 0
required independent reviews valid
receipt signature valid
receipt current and unrevoked
source/plan/profile scope exact match
authority_effect = NONE
```

任何字段缺失或无法确定均 fail closed。

## 6. Retry 与 flaky policy

### 6.1 Infrastructure rerun

只有以下情形可以标记 infrastructure rerun：

- runner 未分配；
- provider outage；
- dependency registry/network 在下载前失败且无 source execution；
- artifact service 故障；
-明确的 runner image provisioning failure。

同 SHA rerun 必须保留 attempt 和原始 run。获得 runner 后出现 compile/test/runtime failure 就是 executable failure，不能回标 infrastructure。

### 6.2 Flake

Flake 不能通过“再跑一次绿了”关闭。必须：

1. 固定失败 seed/input；
2. 证明 nondeterminism 来源；
3. 增加 deterministic replay 或调度控制；
4. 修复 root cause；
5. 在同一 exact head 上连续执行规定次数；
6. 保留原始失败和修复后结果；
7. reviewer 接受剩余概率风险。

### 6.3 Timeout

扩大 timeout 只有在已有资源模型证明原值过严时允许。死锁、未界定 I/O、无界 backoff 或资源泄漏不能通过扩大 timeout 消除。

## 7. Base drift 与 stacked PR

- parent head 变化后，child PR 必须比较 tree 和受影响 contract；
- 无影响 drift 也必须产生 machine disposition；
- 有影响 drift 必须重建 head，并让旧 receipt 进入 `SUPERSEDED`；
- merge commit、synthetic PR merge ref 和 head SHA 不能混用；
- qualification evidence 只绑定显式 exact head；
- stacked parent 未合并不阻止 child 技术执行，但阻止把 child 称为 canonical integrated truth。

## 8. External action handoff

每个外部 blocker 必须由 `HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml` 唯一覆盖。Handoff 请求至少包含：

- action package ID 与 blocker ID；
- exact scope 和 explicit non-scope；
- prerequisites；
- ordered procedure；
- evidence requirements；
- operator independence；
- custody 与 signer role；
- acceptance criteria；
- failure/escalation outcome；
- expected completion object；
- expiry 与 revocation policy。

仓库管理员完成设置后仍需要读取控制面状态和负向测试；律师、审计师、reviewer 或实验室只提交签名 completion object，不能直接改变 canonical authority flag。

## 9. Closure receipt

`heptabao.blocker-closure-receipt.v1` 是技术/外部 closure 的统一容器。Receipt 必须：

- 使用 canonical JSON payload；
- 拒绝 duplicate keys、浮点替代整数和未知 schema；
- 引用 manifest 与 blocker register digest；
- 逐项列出 criterion 结果；
- 记录所有 required execution entries；
- 记录 reviewer/signature；
- 有 `issued_at`、`expires_at` 与 revocation lookup key；
- `qualification=false`；
- `selection_effect=NONE`；
- `authority_effect=NONE`。

Receipt 通过不等于 package/gate qualification，更不等于 production authority。

## 10. 当前 H02 closure 适用规则

对 OpenRaft H02 当前链：

- effective toolchains 为 `1.88.0` 与 `1.98.0`；
-固定 seed 为 `0x5eed20260828cafe`、`0x8badf00d12345678`、`0xd15ea5e5cafef00d`；
- in-memory、hostile snapshot、linearizability、OS suspend、durable logical store、clock 和 source graph 必须逐项执行；
- stale snapshot API success 只有在 log/committed/applied/snapshot/purged/membership/application state 全部不变时，才可归类为 semantic no-op；
- 任意 guarded state 改变均为 `EXECUTED_FAIL`；
- process-fatal after injection 最多证明窄安全，不证明 availability 或 production readiness；
- logical fault simulation 不替代独立 kernel/VM power-cut evidence；
- candidate 仍未 selected，所有 authority 继续关闭。

## 11. Stop conditions

本合同允许的停止结果只有：

- `CLOSED`
- `BLOCKED_UPSTREAM`
- `EXTERNAL_ACTION_REQUIRED`
- `BASE_DRIFT`
- `REVOKED`
- `RESUME_REQUIRED`

每个非 CLOSED 结果必须包含 blocker ID、exact source、最后完成步骤、未满足 criterion、可执行 resume action 和 owner role。
