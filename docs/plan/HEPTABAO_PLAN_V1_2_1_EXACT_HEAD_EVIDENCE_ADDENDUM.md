# HeptaBao Plan V1.2.1 Exact-Head Evidence Addendum

**Plan ID：** `HEPTABAO-PLAN-2026-08-28`  
**Revision：** `1.2.1`  
**状态：** `NORMATIVE_OPERATIONAL_ADDENDUM / REMEDIATION_IMPLEMENTED / NOT_QUALIFIED / AUTHORITY_EFFECT_NONE`  
**继承：** `HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2` 与 `HEPTABAO_PLAN_V1_2_1_EXECUTION_DEEPENING`  
**主题：** 完整 H02 exact-head matrix、source 自绑定、应用级结果分类、失败保全与 authority re-evaluation

## 1. 触发原因

V1.2.1 exact-head 再审计先发现两个基础缺陷：

1. 原 `plan-integrity-v4` 使用 shell fail-fast loop，第一个非零退出可能阻断后续 entry；
2. hostile-snapshot parent 曾可能在 JSON 报告 `EXECUTED_FAIL` 时返回 0，形成“应用失败、CI 成功”。

进一步审计又发现：

- runner 接受调用方自报的 repository/commit/tree/clean-tree，没有自行对 Git checkout 求值；
- `BLOCKED`、`UNKNOWN`、`UNEXECUTED` 会被折叠成通用 `FAIL`，丢失恢复语义；
- timeout 只终止直接 child，可能遗留 cargo 启动的 process tree；
- duplicate entry ID 可能掩盖另一个 missing entry；
- summary 不记录 command digest、process_started 和 runner-level source drift；
- 高扇出 PR workflows 在 runner 供给不足时形成长期 `steps=[] / runner_id=null`。

这些都是 repository-controlled evidence production gap，不改变 qualification 或 authority 定义。`HB-BLK-REPO-008`、`011` 与 `013` 继续保持 `REMEDIATION_IMPLEMENTED`，直到 exact-head executable results、required review 与 closure receipt 完整。

## 2. 深化交付

### 2.1 Source 自绑定

`scripts/h02_exact_head_matrix_v1.py` 现在自行验证：

- 实际 Git root；
- `HEAD` 与 declared commit；
- `HEAD^{tree}` 与 declared tree；
- clean tracked/untracked state；
- canonical OpenRaft manifest 与 committed Cargo.lock；
- output/target 根位于 repository 外；
- matrix 结束后 source/head/tree 仍未漂移。

调用方传入参数只作为待验证 assertion，不再作为信任根。

### 2.2 完整 24-entry 执行器

固定矩阵仍为：

```text
2 toolchains × 3 seeds × 4 probe kinds = 24 entries
```

执行器：

- 不因前一 entry 失败而中止；
- 使用 argv array；
- 每个 entry 记录 command digest、process_started、stdout、stderr、exit、duration 与 digests；
- 分别验证 in-memory、hostile、blocker、durable application outputs；
- 对 duplicate、missing、unexpected entry ID fail closed；
- 允许保留 schema-valid partial failure summary；
- 只有 24/24 application PASS 且所有 process exit 0 时返回成功。

### 2.3 状态分类不丢失

Process result、Application result 与 Aggregate result 分离。应用状态固定保留：

```text
EXECUTED_PASS
EXECUTED_FAIL
BLOCKED
UNKNOWN
UNEXECUTED
```

`BLOCKED`、`UNKNOWN`、`UNEXECUTED` 不会再被压平成普通失败。它们仍使 aggregate result 为 `FAIL`，但保留不同的重试、调查和 supersession 语义。

### 2.4 Timeout process-group fencing

POSIX entry 使用独立 process group。超时后终止完整 process group 并收集最终 stdout/stderr，防止遗留 child/grandchild 继续运行。Timeout 的 entry conclusion 为 `BLOCKED`，同时记录 process-level timeout error；任何 timeout 都使 final matrix 失败。

### 2.5 Machine summary hardening

`heptabao.h02-exact-head-matrix-summary.v1` 现绑定：

- actual source/root/commit/tree/clean-tree；
- manifest 与 lock digest；
- toolchain、seed、probe kind；
- 最多 24 个 retained entry；
- command digest、process_started、exit、application status；
- entry ID 与 canonical kind/toolchain/seed/binary/argv tuple 的一一绑定；
- stdout/stderr digest；
- duplicate/missing/unexpected IDs；
- runner_errors；
- qualification、compatibility、selection、authority 常量。

`result=PASS` 必须满足 24/24、无 duplicate/missing/unexpected、无 runner errors 且 source clean。

### 2.6 单 runner ARM64 fallback

新增 `.github/workflows/h02-final-gap-closure-arm64.yml`：

```text
exact immutable checkout
→ all V1.2/V1.2.1/Python validators
→ Rust 1.88/1.98 root and OpenRaft fmt/test/clippy
→ all 24 application entries
→ diagnostics upload before gate
→ independent schema/digest/source final gate
```

该 lane 使用 `contents: read`、`persist-credentials: false`，不 commit/push/rebase。它只降低 workflow fanout，不降低 acceptance criteria，也不是 `HB-EAP-EXT-007` 所要求的独立 operator/credential-root reproduction。

## 3. Closure 状态

### Repository-controlled

本修订把 source-binding、result-taxonomy、process-tree timeout 与 duplicate-ID 缺口推进到 `REMEDIATION_IMPLEMENTED`。只有以下全部出现后才能进入 `EXACT_HEAD_EXECUTED`：

```text
plan-and-python = PASS
root-rust = PASS
OpenRaft exact metadata = PASS
Rust 1.88 fmt/test/clippy = PASS
Rust 1.98 fmt/test/clippy = PASS
24/24 matrix entries = PASS
raw artifact upload = PASS
summary schema/digest/source re-verification = PASS
authority sentinel = PASS
```

queued、pending、skipped、cancelled、`steps=[]` 或未分配 runner 都是 `INFRASTRUCTURE_UNEXECUTED`，不是 PASS 或 FAIL。Critical repository blockers 仍需真实独立 reviewer 与 current、signed、unrevoked closure receipt 才能标为 `CLOSED`。

### External

以下仍为 `EXTERNAL_ACTION_REQUIRED`：

- GitHub ruleset 与 negative control；
- 独立 reviewer identities；
- legal/clean-room/outbound license；
- private disclosure、24×7 roster 与 incident drill；
- isolated signer、trust root、transparency、revocation；
- restricted Oracle 与 signed sanitized transfer；
- separately operated kernel/VM power-cut lab；
- `HB-EAP-EXT-007` 独立 operator/credential-root reproduction。

Repository automation、administrator permission 或同一 GitHub-hosted runner 不能伪造这些完成对象。

## 4. Failure、retry 与 supersession

- process 启动失败 → `UNEXECUTED`；
- application `BLOCKED` → `BLOCKED`；
- application `UNKNOWN` → `UNKNOWN`；
- timeout → `BLOCKED` + timeout error；
- malformed output、guarded-state change、`EXECUTED_FAIL` 或 nonzero exit hiding PASS → `FAIL`；
- source/head/tree/clean drift → runner error，aggregate `FAIL`；
- duplicate、missing、unexpected entry → aggregate `FAIL`；
- 修复后必须在新 SHA 全量重跑，旧 artifacts 进入 supersession graph，不得删除。

## 5. 后续执行顺序

1. 在独立 child branch/PR 上提交本修订；
2. 触发主 lane 与低扇出 fallback lane；
3. 对每个 executable failure 保留并分类；
4. 在同 package branch 修复并产生新 exact head；
5. 完整重跑 24-entry matrix；
6. 生成 unsigned technical closure candidate；
7. 请求 program/security/storage-platform independent review；
8. 签发 current、scoped、unrevoked blocker closure receipts；
9. 外部 action packages 按其完成对象继续闭环。

只有前 8 步全部满足，repository-controlled critical blocker 才能进入 `CLOSED`。外部 blocker 不能由这些步骤关闭。

## 6. Authority boundary

本 addendum、代码、测试、CI 与 technical summary 均不能：

- 选择 OpenRaft；
- 证明 kernel power-cut durability；
- 形成 H02 qualification；
- 创建 compatibility claim；
- 授予 production、migration、release 或 mixed-cluster authority。

固定状态：

```text
qualification=false
compatibility_claim=false
selected_candidates=[]
selection_effect=NONE
authority_effect=NONE
```
