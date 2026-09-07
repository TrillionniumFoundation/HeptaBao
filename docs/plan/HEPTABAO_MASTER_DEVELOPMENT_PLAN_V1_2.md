# HeptaBao 全量 Rust 重写 OpenBao 服务端——总体开发计划 V1.2

**Plan ID：** `HEPTABAO-PLAN-2026-08-28`
**Revision：** `1.2`
**状态：** `NORMATIVE_EXECUTION_PLAN / IMPLEMENTATION_ACTIVE / NOT_QUALIFIED / NO_COMPATIBILITY_CLAIM / NO_OPERATIONAL_AUTHORITY`
**生效日期：** 2026-08-29
**目标：** 独立、clean-room、operator-level 的 OpenBao-compatible Rust secrets-management server
**Oracle 冻结基线：** OpenBao v2.6.2，commit `dd9c19c37a878cf4a81b18efb8d6f0599c7da923`
**主 Rust 工具链：** 1.98.0；候选依赖的有效 MSRV 必须单独证明

## 0. V1.2 的性质

V1.2 不扩大 V1.1 的最终 C5 范围，而是把计划从“详细目录”升级为**可执行、可验证、可审计、可收敛的工程合同**。本版解决七类系统性问题：

1. 建立唯一 normative manifest 和 canonical state 输入，禁止多个手写状态文件同时自称权威；
2. 将“代码进入受保护集成线”和“获得 qualification/compatibility/production authority”彻底分离；
3. 将 Work Package 数量纠正为目录实际存在的 **301 个**，并为每个包补齐统一合同字段；
4. 删除能够修改源码并直接推送的自修改 CI，所有验证 workflow 默认只读、绑定 exact SHA；
5. 把 schema valid、semantic valid、cryptographically verified 三种证据成熟度严格分层；
6. 为 storage、request pipeline、Oracle、threat model、crate graph 和 evidence trust root 建立独立规范；
7. 用可运行的垂直切片替代长期横向铺开，优先形成 `HB-P0-DEV-MEMORY` 与 `HB-P1-CORE-POSTGRES`。

V1.2 允许未 qualified 的代码经普通审查进入受保护集成线，但任何合并、标签、CI 成功或 qualification receipt 都**不得自动产生**兼容、生产、迁移、发布、mixed-cluster 或 OpenBao physical-storage authority。

## 1. 单一真相体系

### 1.1 文档层级

冲突时按以下顺序解析：

1. 经验证、未撤销的 Revocation；
2. 经验证、未过期且 scope 匹配的 Authority Grant；
3. 经验证、未过期且 scope 匹配的 Compatibility Claim；
4. 经验证、未过期且依赖闭合的 Qualification Receipt；
5. `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml` 中列为 `NORMATIVE` 的机器对象；
6. 由 canonical renderer 在 exact source 上生成的 resolved state；
7. 本计划与架构规范；
8. 说明性报告、历史状态和 PR 描述。

缺失、冲突、无法解析、签名失败、摘要不匹配、过期、撤销、scope 不匹配或依赖不闭合时一律 fail closed。

### 1.2 静态输入与解析状态

`planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml` 是不可自引用的静态输入。它使用 `SELF_RESOLVED_AT_VERIFICATION` 绑定模式；CI 必须在 checkout 的 exact commit/tree 上运行 `scripts/render_canonical_project_state_v1.py`，生成包含 repository、ref、commit、tree、lock digest、validator digest 和运行身份的 resolved JSON artifact。README、dashboard 和执行报告只能从该 resolved state 派生。

### 1.3 历史文件

V1.1 gate matrix、status JSON/YAML 和 execution queue 保留为历史证据，不再拥有 V1.2 当前状态 authority。任何工具把历史对象当作当前真相必须失败。

## 2. 集成与 authority 完全分离

### 2.1 正确的代码流

```text
isolated package branch
→ exact-source read-only CI
→ independent code/security/domain review as required
→ small PR into protected integration truth
→ merged but UNQUALIFIED implementation
→ signed qualification receipt
→ optional exact-profile compatibility claim
→ separate scoped, expiring, revocable authority grant
```

禁止把所有分支堆叠到 qualification 完成后一次性合并。长期未合并分支会造成 base drift、validator drift、重复状态和不可复核的 evidence graph。

### 2.2 CI 权限

默认 workflow 权限为 `contents: read`。验证 workflow 不得：

- `persist-credentials: true`；
- `git commit`、`git push`、直接更新 branch ref；
- 在 runner 中修改随后被称为“已测试”的 source tree；
- 同时修改 evidence policy、validator 和 evidence result；
- 使用 PR synthetic merge commit 代替 exact head SHA 作为资格来源。

生成器只能输出 patch/source/lock/evidence artifact。需要进入仓库的变更必须通过新的普通 PR。

## 3. 统一生命周期状态

所有 Gate、Work Package、fixture、candidate 和 release artifact 使用同一有序状态语义：

```text
PLANNED
→ SPECIFIED
→ IMPLEMENTED
→ LOCALLY_EXECUTED
→ REMOTELY_EXECUTED
→ CROSS_PLATFORM_EXECUTED
→ INDEPENDENTLY_REPRODUCED
→ REVIEWED
→ QUALIFIED
→ CLAIMED
→ AUTHORIZED
→ RELEASED
```

失败与等待不是正向成熟度，必须正交记录为：

- `PASS`、`FAIL`、`BLOCKED`、`UNEXECUTED`、`UNKNOWN`；
- `BASE_DRIFT`、`STALE_EVIDENCE`、`REVOKED`、`SUPERSEDED`；
- `EXTERNAL_ACTION_REQUIRED`。

“implemented”“executed”“qualified”“authorized”不得混用。CI 成功最多推进到对应的执行成熟度，不能自行推进到 REVIEWED、QUALIFIED 或 AUTHORIZED。

## 4. 全量范围与明确排除

最终 C5 仍覆盖 HTTP/API、HCL、seal/storage/audit/plugin、policy/identity/MFA/OIDC、token/wrapping、lease/WAL/reconcile、全部内置 auth/secrets/database provider、namespace/workflow、自初始化、PostgreSQL、Integrated Raft、HA、CLI/Agent/Proxy/OpenAPI、逻辑迁移、可复现供应链和 LTS。

默认不包含：

- 与 OpenBao 节点组成同一个 Raft/HA cluster；
- 原地读取或修改 OpenBao `raft.db`；
- byte-for-byte barrier/snapshot/physical-storage 兼容；
- 未列入 exact support matrix 的第三方插件；
- 未经真实认证的 FIPS 声明；
- OpenBao 商标、官方认可或未来版本的自动兼容。

## 5. 安全与一致性不变量

1. Physical storage 永远不可信；离开 barrier 的持久业务状态必须是认证密文。
2. sealed scope 不处理普通业务请求，也不保留可使用的 root/barrier/namespace key。
3. dispatch 前完成 canonicalization、namespace/mount binding、operation classification、auth/identity/MFA/policy 和 request audit。
4. external effect 前持久化 fenced intent、operation key、owner epoch 和 payload digest。
5. secret response 前 response audit 成功；audit 失败不得 silent bypass。
6. ambiguous outcome 进入 `INDETERMINATE`，只允许 reconcile、lookup、revoke、compensate 或 manual hold。
7. token、unseal share、root/recovery key、plugin mTLS key 和 dynamic credential 不进入普通日志、指标、trace、CI 或 debug bundle。
8. parent token revoke 关闭非 orphan descendant token 与 lease；过期或 fence 变化后不得复活。
9. namespace context 绑定 storage、cache、identity、policy、token、lease、audit、plugin 和 OIDC。
10. Raft FSM 不读取系统时间、随机数、网络、KMS、plugin 或其他外部 I/O。
11. 每个 durable/migration domain 任意时刻只有一个 authoritative writer。
12. durable mutation 必须满足“持久化成功后发布内存状态并确认”或“失败且外部不可观察状态不变”。
13. snapshot/state/log 的跨文件关系必须由一个原子 generation manifest 或单一 bundle 约束。
14. unknown operation、algorithm、protocol、format、dependency、unsafe boundary 和 authority 一律拒绝。
15. 密码、安全、耐久、分布式和 operator-critical 条目要求 100% named evidence，禁止平均覆盖率掩盖缺口。

## 6. Program Gates 与 301 个 Work Packages

H00–H27 仍是 evidence/authority gate，不是巨型开发任务。V1.2 的实际 Work Package 总数为 **301**，机器目录位于 `planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_2.yaml`。每个包必须声明：

- scope 与 explicit non-scope；
- accountable role 与唯一 durable writer（若适用）；
- `work_start_requires`、`qualification_requires`、`release_requires`；
- public/internal API 和 schema/versioning；
- threat-model delta；
- positive、negative、property、fuzz、fault、crash/adversarial tests；
- Oracle fixture 或正式 deviation；
- source/requirement/invariant/test/evidence trace；
- dependency/SBOM/unsafe/native/build-script delta；
- migration/rollback/supersession；
- independent review role；
- immutable evidence bundle；
- `authority_effect: NONE`。

Gate 只有在 profile-required Work Package 均 QUALIFIED、global blocker 为 0、dependency receipts 当前有效、Critical/High/Unclassified finding 为 0、独立审批满足且残余风险签名接受后，才能产生 Qualification Receipt。

## 7. 垂直切片优先级

### 7.1 `HB-P0-DEV-MEMORY`

目标是形成首个可启动、可测、明确非生产的垂直切片：

- config 与 process bootstrap；
- bounded HTTP listener 和 canonicalization；
- operation registry 与 request pipeline；
- memory storage；
- development-only barrier/seal profile；
- token + minimal ACL；
- KV v1；
- file audit；
- secret-free Oracle differential；
- 所有 compatibility/production authority 继续为 false。

### 7.2 `HB-P1-CORE-POSTGRES`

在 P0 稳定后加入 PostgreSQL transaction/CAS、真实 durability contract、init/seal/unseal、keyring rotation、service token graph、KV v2、lease、audit devices、backup/restore 和 reopen/upgrade。

Integrated Raft、HA、全部后端、namespace、Agent/Proxy 和迁移不再阻塞第一个可运行 server；它们按独立 profile 继续推进。

## 8. H00/H01/H02 当前事实

### H00

政策、schema、基础 validator 和 runbook 已实现，但仓库 ruleset、真实 CODEOWNERS team、clean-room ACL、legal disposition、private disclosure roster、HSM/isolated signer、transparency log、独立审批和 H00 receipt 仍未完成。

### H01

已有公开基线、endpoint/config/CLI seed、normalizer 和 synthetic observer，但真实 restricted raw fixture、sanitized black-box fixture、签名 transfer 和 independent compatibility review 仍为 0。任何 OpenBao 兼容结论仍禁止。

### H02

已实现 runtime/TLS/Raft reference harness、OpenRaft candidate adapter、三节点 cluster、hostile snapshot、linearizability、OS suspension、logical durability 和跨平台 evidence scaffolding。OpenRaft alpha.33 的 exact dependency family 与 immutable `validit 0.2.5` source override 已能由只读 workflow 生成并验证；该 lock 必须进入 exact source 后重跑全部 validator、Rust、fault 与 cross-platform lane。候选仍未 SELECTED，production dependency authority 仍为 false。

## 9. Blocker closure loop

每个 blocker 只能通过下列状态流关闭：

```text
OPEN
→ OWNED
→ REMEDIATION_IMPLEMENTED
→ EXACT_HEAD_EXECUTED
→ INDEPENDENTLY_REVIEWED (critical scope)
→ CLOSED
```

有效终止状态只有：

- `CLOSED`；
- `BLOCKED_UPSTREAM`；
- `EXTERNAL_ACTION_REQUIRED`；
- `BASE_DRIFT`；
- `REVOKED`；
- `RESUME_REQUIRED`。

每次 loop 必须绑定 exact repository/ref/commit/tree，保留失败 evidence，不允许删除失败运行来制造绿色历史。一个修复若没有 exact-head execution，只能标记为 `REMEDIATION_IMPLEMENTED`。

## 10. Evidence 成熟度

三个层级严格分开：

1. `SCHEMA_VALID`：对象结构满足 JSON Schema；
2. `SEMANTICALLY_CONSISTENT`：引用、计数、scope、状态转换和不变量一致；
3. `CRYPTOGRAPHICALLY_VERIFIED_AND_CURRENT`：签名、trust root、identity/role、时间、revocation、supersession、transparency 和引用摘要全部验证。

只有第 3 层可作为 qualification/claim/grant 的输入。任何对象自报 `ACTIVE`、`signature_valid=true` 或 `revocation_status=ACTIVE` 都不构成验证。

## 11. Definition of Done

每个 package 的 DoD 至少包括：

- exact source、clean tree、toolchain、target、lock 和 config digest；
- required lanes 全 PASS，failed=0、unknown=0；
- Critical/High/Unclassified finding 为 0；
- deterministic replay 或明确的不确定性边界；
- crash/fault result 保留；
- secret-canary 为 0；
- traceability closure；
- required independent review；
- current、unrevoked、scope-matched evidence；
- qualification 仍为 `authority_effect: NONE`。

## 12. 近期执行顺序

1. 提交 V1.2 normative docs、canonical state、blocker register 和 validator；
2. 删除自修改/自推送 workflow，所有 active CI 改为 exact-SHA read-only；
3. 提交由只读 runner 生成并验证的 exact OpenRaft lock；
4. 绑定 candidate direct dependencies 与 source override，修复 validator drift；
5. 修复 durable store 的 persist-before-publish 和 state/snapshot atomic generation；
6. 在 Linux/macOS、Rust 1.88/1.98 上执行 exact-head full matrix；
7. 建立受保护 integration truth 和真实 reviewer team；
8. 完成 H00 外部治理条件与首个真实 H01 fixture transfer；
9. 冻结 H03 protocol/type/error/effect seams；
10. 启动 P0 memory vertical slice。

## 13. 不可伪造的外部 closure

以下事项不能由 repository administrator、CI 或自动化自行声明完成：

- 独立法律/商标/专利/出口结论；
- 独立 crypto、storage、distributed-systems、security 和 release 审批；
- 真实人员与 clean-room ACL 隔离；
- HSM/isolated signing key 和 emergency revocation ceremony；
- separately operated independent reproduction；
- kernel/VM power-cut laboratory；
- 24/7 incident roster 和 private disclosure drill。

在真实证据进入 trust graph 前，这些 blocker 必须保持 `EXTERNAL_ACTION_REQUIRED`，所有 authority flag 保持 false。
