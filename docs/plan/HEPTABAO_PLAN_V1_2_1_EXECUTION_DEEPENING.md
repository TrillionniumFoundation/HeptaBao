# HeptaBao Plan V1.2.1——操作化深化与剩余 Gap Closure

**Plan ID：** `HEPTABAO-PLAN-2026-08-28`  
**Patch Revision：** `1.2.1`  
**状态：** `NORMATIVE_OPERATIONAL_AMENDMENT / IMPLEMENTATION_ACTIVE / NOT_QUALIFIED / AUTHORITY_EFFECT_NONE`  
**继承计划：** `docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md`  
**生效方式：** 由 `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml` 纳入 V1.2 规范集合后生效  
**范围：** 不扩大 C5 产品范围；只把剩余 blocker、外部行动、证据闭环和集成控制细化为可执行合同

## 1. 修订目标

V1.2 已完成单一真相、301 个 Work Package、统一成熟度、只读 CI、durability、Oracle、evidence trust 与垂直切片的基础设计。V1.2.1 解决 V1.2 仍然存在的操作层缺口：

1. 每个 blocker 必须拥有唯一、可验证、可重放的 closure path；
2. 仓库内修复必须经 exact-head execution，而不是以“代码已写”代替闭环；
3. 外部治理、法律、签名、Oracle、存储实验室和独立复现必须形成逐项 action package，不能只写一行“需要外部处理”；
4. GitHub 仓库控制面必须有明确目标配置、负向验证和证据对象；
5. closure receipt 必须绑定 repository/ref/commit/tree、plan、criteria、jobs、artifacts、review 与 authority boundary；
6. 重试、flaky、base drift、runner 未执行、证据过期、撤销和 supersession 必须有一致分类；
7. 当前 H02 技术链必须先关闭 exact graph、format/test/clippy、六种 seed/toolchain 执行与 fail-closed evidence，再允许启动新的横向候选扩张。

## 2. 当前精确继承链

本修订必须从最新未合并技术头派生，并在每次运行重新验证：

```text
V1.2 landing PR #26 head
  codex/plan-v1.2-landed-closure-v2
  @ cad9aacab9f7d1ff6f7d081fa8c09e2b7f814243
        ↓
hostile snapshot semantic closure PR #35 head
  codex/h02-hostile-snapshot-noop-closure-v1
  @ 2b3f2e5e31396da9ceceafe76821babafc3035c9
  (supersedes observed head b2e9eeb9d153f98280d1197aee8e895d7409c51c after BASE_DRIFT revalidation)
        ↓
V1.2.1 operational gap closure package
  codex/plan-v1.2.1-operational-gap-closure-v1
```

父分支或 PR head 变化后，旧 exact-head 证据不得自动迁移；必须重新分类为 `BASE_DRIFT` 或 `STALE_EVIDENCE`，并在新 head 上重跑。

## 3. Blocker closure 的双轨模型

### 3.1 Repository-controlled blocker

仓库可自主修改的 blocker 采用：

```text
OPEN
→ OWNED
→ REMEDIATION_IMPLEMENTED
→ EXACT_HEAD_EXECUTED
→ INDEPENDENTLY_REVIEWED（critical scope）
→ CLOSED
```

进入 `EXACT_HEAD_EXECUTED` 至少要求：

- exact repository/ref/commit/tree 与 clean-tree 绑定；
- 所有声明的 workflow/job/seed/toolchain/platform 条目实际获得 runner；
- required jobs 全部 `PASS`；
- `failed=0`、`unknown=0`；
- 失败和非零退出原始输出被保留；
- artifact digest 与执行元数据进入 closure receipt；
- rerun 没有选择性删除失败 seed；
- authority、selection、qualification 不因技术通过而变化。

### 3.2 External-action blocker

仓库设置、真实人员、法律意见、HSM、restricted Oracle、独立实验室和独立复现不允许由代码作者或 GitHub Actions 自行关闭。其状态固定为：

```text
EXTERNAL_ACTION_REQUIRED
```

直到对应 `planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml` action package 完成，并产生可由 HeptaBao verifier 独立校验的 completion object。文档、管理员权限、自报字段、同一人员的多个别名、GitHub-hosted 双 OS job 都不能替代外部独立性。

## 4. 新增规范对象

V1.2.1 引入：

- `docs/execution/HEPTABAO_BLOCKER_CLOSURE_OPERATING_CONTRACT_V1.md`
- `docs/governance/HEPTABAO_REPOSITORY_CONTROL_PLANE_ENFORCEMENT_SPEC_V1.md`
- `planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml`
- `schemas/heptabao_external_action_package_catalog_v1.schema.json`
- `schemas/heptabao_blocker_closure_receipt_v1.schema.json`
- `scripts/validate_plan_v1_2_1.py`
- `tests/plan/test_plan_v1_2_1.py`

这些对象只定义程序、证据和 fail-closed 验证；均为 `authority_effect: NONE`。

## 5. Repository-controlled closure 优先级

### P0-A：精确技术门禁

1. `plan-integrity-v4 / plan-and-python`
2. `plan-integrity-v4 / root-rust`
3. `plan-integrity-v4 / openraft-exact-graph-and-runtime`
4. `h02-openraft-inmemory-cluster`
5. `h02-openraft-fault-lab`
6. `h02-openraft-blocker-closure`
7. `h02-candidate-adapters`
8. `h02-source-integrity-evidence`
9. `h02-probe-sbom-msrv`
10. authority sentinels

每个矩阵必须覆盖声明的 Rust `1.88.0`、`1.98.0` 与三个固定 seed；任何一个条目 `FAIL/BLOCKED/UNKNOWN/UNEXECUTED` 都阻止 closure。

### P0-B：证据生成

每个 repository blocker 生成 `heptabao.blocker-closure-receipt.v1`：

- 绑定 exact source、plan、manifest 与 blocker register digest；
- 逐条记录 closure criterion；
- 记录 run/job/runner、toolchain、target、seed 和 artifact digest；
- 记录失败历史与修复提交；
- `result=CLOSED` 时必须有独立 reviewer signature，且 critical author 不是唯一 approver；
- receipt 的 `qualification=false`、`selection_effect=NONE`、`authority_effect=NONE` 为常量。

### P0-C：集成

技术通过只允许形成“可审查的未 qualified 实现”。合并目标必须是被仓库控制面显式指定的 canonical integration branch；在 ruleset 完成前，不得把任何未保护分支描述为受保护集成真相。

## 6. External action package 执行顺序

外部行动可并行准备，但资格依赖按下列顺序闭合：

1. `HB-EAP-CTRL-001`：仓库 ruleset 和 required checks；
2. `HB-EAP-EXT-001`：真实独立 reviewer identities；
3. `HB-EAP-EXT-002`：legal/clean-room/outbound-license disposition；
4. `HB-EAP-EXT-003`：private disclosure、24×7 roster、incident/revocation drill；
5. `HB-EAP-EXT-004`：isolated signer、trust root、transparency、emergency revocation；
6. `HB-EAP-EXT-005`：restricted Oracle 与首个 signed sanitized transfer；
7. `HB-EAP-EXT-006`：独立 kernel/VM power-cut 和 filesystem crash lab；
8. `HB-EAP-EXT-007`：不同 operator/credential root/artifact custody 的独立复现。

其中 2、3、4、5 可以并行；6 依赖 clean-room 和 reviewer 基础；7、8 依赖 exact source profile 冻结。

## 7. P0/P1 垂直切片启动约束

### `HB-P0-DEV-MEMORY`

只在下列条件满足后进入 implementation-active：

- H03 operation registry、canonicalization、error/effect contract `FROZEN`；
- P0 crate graph 与 trust boundary reviewed；
- development-only barrier/seal 明确不可用于真实秘密；
- memory storage、token、minimal ACL、KV v1、file audit 都有 package contract；
- secret canary、audit ordering、sealed-state negative tests 已列名；
- Oracle 只允许 secret-free public/sanitized fixture；
- compatibility 和 production authority 保持 false。

### `HB-P1-CORE-POSTGRES`

额外要求：

- PostgreSQL transaction/CAS 与 durability profile frozen；
- barrier envelope/keyring、init/seal/unseal 状态机 frozen；
- backup/reopen/schema upgrade crash matrix 已声明；
- legal、crypto、storage reviewer roles 已有真实身份；
- 任何外部 effect 都有 intent/fence/reconcile contract。

Integrated Raft、HA、全部后端、namespace、Agent/Proxy 和 migration 不得重新成为 P0/P1 的隐式入口条件。

## 8. 失败、重试与证据保留

- `queued/pending/skipped/cancelled/steps=[]/runner_id=0` 均为 `UNEXECUTED`；
- 测试失败是有效证据，禁止删除、改名或用后续绿灯覆盖；
- 同 SHA rerun 必须保留 attempt number，并解释基础设施故障与代码故障；
- 修复后 SHA 变化必须产生新 receipt；旧 receipt 进入 superseded graph；
- seed 失败后不得只重跑通过的 seed；
- flake 只有在有确定性复现、root cause、修复和重复通过证据后才能关闭；
- artifact provider TTL 不得被当作永久证据；至少永久保存 digest、metadata、receipt 和可验证 provenance；
- 任何 Critical/High/Unclassified finding 未归零时，技术 lane 不能进入 CLOSED。

## 9. 有效终止状态

一个 closure loop 只能以以下状态停止：

- `CLOSED`
- `BLOCKED_UPSTREAM`
- `EXTERNAL_ACTION_REQUIRED`
- `BASE_DRIFT`
- `REVOKED`
- `RESUME_REQUIRED`

“代码大概完成”“CI 大部分通过”“等待以后处理”不是终止状态。

## 10. Authority boundary

V1.2.1 不签发 Qualification Receipt、Compatibility Claim、Dependency Selection、Authority Grant 或 Release Attestation。它不能把 OpenRaft、Tokio、rustls、PostgreSQL 或任何其他候选推进为生产依赖。所有 authority flag、compatibility flag、selection effect 和 release authority 继续保持 false/NONE。
