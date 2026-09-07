> **Historical notice:** V1.1 is retained for audit history and is superseded as the current execution plan by `HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md`. V1.1 grants no authority.

# HeptaBao 全量 Rust 重写 OpenBao 服务端——总体开发计划 V1.1

**日期：** 2026-08-28  
**Plan ID：** `HEPTABAO-PLAN-2026-08-28`  
**Revision：** `1.1`  
**状态：** `NORMATIVE_EXECUTION_PLAN / H00_ACTIVE / NO_COMPATIBILITY_CLAIM / NOT_PRODUCTION_AUTHORITY`  
**目标：** C5 operator-level OpenBao-compatible server  
**OpenBao Oracle 基线：** v2.6.2，commit `dd9c19c37a878cf4a81b18efb8d6f0599c7da923`  
**Rust 基线：** 1.98.0

## 0. 决策与 V1.1 修订

HeptaBao 是一个独立的 Rust secrets-management server，全量目标覆盖 OpenBao 服务端、CLI、Agent、Proxy 和全部 built-in backends。浏览器 UI 可以继续是独立 TypeScript 客户端；这不改变“服务端 Rust 全量重写”的定义。

V1.1 保留全量目标，但纠正 V1 的执行模型：

1. `H00–H27` 只作为 **Program Gate**，聚合资格、风险和 authority readiness；不直接作为工程排期单元。
2. **Work Package** 是唯一开发单元，可以并行推进。完整目录位于 `planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml`。
3. 依赖拆成 `work_start_requires`、`qualification_requires` 和 `release_requires`。接口冻结后可并行开发；资格与发布仍必须等待签名证据。
4. Qualification Receipt、Compatibility Claim、Authority Grant 和 Revocation 完全分离。Qualification 的 `authority_effect` 永远为 `NONE`。
5. 安全、耐久、密码、分布式和 operator-critical 行为必须逐项 100% named evidence；禁止用 95% 或 98% 总覆盖率掩盖关键缺口。
6. Compatibility 只能按 `C-level + exact profile + HeptaBao version + Oracle versions + platforms + deviations + exclusions` 声明。
7. Durable domain 只有一个 authoritative writer；adapter、cache、projection、standby 和 migration 工具都不能形成第二写者。
8. 默认 C5 容量窗口调整为 M60–M84；M52–M68 只是满足严格 staffing、并行度、Oracle 自动化和外部审查条件的加速情景。

## 1. 全量范围

C5 support matrix 最终必须覆盖：

- OpenBao-compatible HTTP API、header、status、JSON shape、错误分类和可观察 side effects；
- HCL server config、listener、TLS、seal、storage、audit、plugin、telemetry 和 service registration；
- `sys/`、auth/secrets/audit mount、tune、remount、reload、disable；
- policy、identity、MFA、OIDC、service/batch/recovery token、cubbyhole、wrapping、root ceremony；
- lease、expiration、renew、revoke、WAL、rollback 和 unknown-effect reconciliation；
- file、HTTP、socket 和 syslog audit devices；
- auth、secret、database 和 KMS 外部插件协议、catalog、version、OCI 与 lifecycle；
- OpenBao v2.6.2 全部 built-in auth methods、secrets engines 和 database providers；
- nested namespaces、namespace sealing、profiles、workflows 和 declarative self-init；
- PostgreSQL 和 Integrated Raft storage、snapshot/restore、HA、forwarding、read standby；
- CLI、operator commands、Agent、Proxy、OpenAPI 与 UI protocol adapter；
- 从受支持 OpenBao 版本到 HeptaBao 的逻辑迁移、验证、fenced cutover、回滚或前向恢复；
- reproducible build、SBOM、signatures、transparency、canary、24/7 support、backport 和 EOL。

C5 默认不自动包含：

- 与 OpenBao 节点组成同一个 Raft/HA cluster；
- 直接打开或原地修改 OpenBao `raft.db`；
- 所有未来 upstream 功能；
- 未列入 support matrix 的第三方插件；
- OpenBao 商标或官方认可；
- 未完成真实认证的 FIPS 声明；
- byte-for-byte barrier、snapshot 或 physical-storage 兼容。

## 2. Compatibility Profiles

计划采用以下独立资格 profile：

| Profile | 候选级别 | 范围 |
|---|---:|---|
| `HB-P0-DEV-MEMORY` | C0 | memory storage、synthetic fixtures、无生产 authority |
| `HB-P1-CORE-POSTGRES` | C2 | single-node PostgreSQL、barrier、seal、policy、identity、token、lease、audit |
| `HB-P2-RAFT-HA` | C4 | Integrated Raft、HA、snapshot、read standby、operations |
| `HB-P3-AUTH-WAVE-A` | C3 | token、userpass、AppRole、cert |
| `HB-P4-AUTH-WAVE-B` | C3 | JWT/OIDC、Kubernetes |
| `HB-P5-AUTH-WAVE-C` | C3 | LDAP、RADIUS、Kerberos |
| `HB-P6-SECRETS-FOUNDATION` | C3 | KV v1/v2、Transit、TOTP |
| `HB-P7-PKI-SSH` | C3 | PKI、PKIext、SSH |
| `HB-P8-DYNAMIC` | C3 | Database、Kubernetes、OpenLDAP、RabbitMQ |
| `HB-P9-NAMESPACE-WORKFLOW` | C3 | nested namespace、namespace seal、profiles、workflows、自初始化 |
| `HB-P10-CLIENT-OPS` | C4 | HTTP、CLI、Agent、Proxy、OpenAPI、operations |
| `HB-P11-MIGRATE-OPENBAO-2_6` | C4 | OpenBao 2.6 逻辑迁移与 fenced cutover |
| `HB-P12-FULL-C5` | C5 | support matrix 中的全部 operator-level 能力和 90 天 canary |

任何 profile 未覆盖能力必须明确标记为 `UNSUPPORTED`、`DEVIATION`、`EXPERIMENTAL` 或 `QUALIFIED`；不得通过笼统的“兼容”措辞隐藏范围。

## 3. Authority 与证据优先级

冲突时按以下顺序解析：

1. 已验证签名的 Revocation；
2. 已验证、未过期且未撤销的 Authority Grant；
3. 已验证、未过期且未撤销的 Compatibility Claim；
4. 已验证、未过期且未撤销的 Qualification Receipt；
5. 机器可读 Program Gate、Work Package、Profile、Requirement、Invariant 和 Operation Registry；
6. 本总体计划；
7. ADR、runbook 和说明性文档。

缺失、过期、撤销、签名失败、scope 不匹配、依赖不完整或无法确定的对象一律 fail closed。

`QUALIFIED` 至少要求：

- exact repository、commit SHA、tree SHA、ref 和 clean-tree 绑定；
- exact plan digest、config digest、dependency-lock digest 和 runtime/platform profile；
- required dependency receipts 完整且未撤销；
- required lanes 全部 `PASS`；
- `failed=0`、`unknown=0`；
- critical/high/unclassified finding 全部为 0；
- 所有 exit gate 为 `PASS`；
- critical author 不是唯一 approver；
- signature 有效、receipt 未过期、未撤销；
- `authority_effect = NONE`。

资格通过仍不等于生产、迁移、发布或 mixed-cluster authority。

## 4. 安全不变量

1. Physical storage 视为不可信；离开 barrier 的持久业务数据必须为认证密文。
2. Sealed scope 不得处理普通业务请求，也不得残留可使用的 barrier/root/namespace key。
3. Dispatch 前必须完成 route exception 或 authentication、identity、policy 和 request audit。
4. External/cluster effect 前必须持久化 fenced intent、operation key、owner epoch 和 payload digest。
5. Secret response 前 response audit 必须成功；audit 失败不得 silent bypass。
6. Ambiguous outcome 进入 `INDETERMINATE → RECONCILING/MANUAL_HOLD`，不得 blind retry。
7. Token、unseal share、root/recovery key、plugin mTLS key、dynamic credential 不进入普通 log、metric、trace、debug bundle、snapshot manifest 或 CI artifact。
8. Parent token revoke 必须撤销所有非 orphan descendants 及其 leases。
9. Lease/token 到期、revoke、authority epoch 或 fence 变化后不得续期、复活或重新授权。
10. Namespace context 必须绑定 storage、cache、identity、policy、token、lease、audit、plugin 和 OIDC。
11. Raft FSM 必须确定性执行，禁止系统时间、随机数、网络、KMS、plugin 和其他外部 I/O。
12. 一个 cluster 或 migration domain 任意时刻只能有一个 authoritative writer。
13. Unknown operation、algorithm、protocol version、storage format、dependency、unsafe 和 authority 一律拒绝。
14. 密码、安全、耐久、分布式和 operator-critical 行为必须 100% named evidence，waiver 不允许。
15. 所有 claim 和 grant 必须可过期、可撤销、可追溯到签名 receipts。

## 5. Authoritative Request Pipeline

所有 operation 先由版本化 registry 分类为：

- `PURE_READ`
- `DURABLE_MUTATION`
- `LEASE_ISSUING_READ`
- `EXTERNAL_EFFECT`
- `AUTH_LOGIN`
- `TOKEN_ISSUE`
- `SEAL_CEREMONY`
- `CLUSTER_OPERATION`
- `MIGRATION_OPERATION`

通用管线是：

```text
receive/bounds
→ path/header/query canonicalization
→ namespace and mount context binding
→ operation classification
→ authentication or declared unauthenticated route guard
→ identity/MFA
→ policy decision
→ request audit gate
→ durable intent when required
→ backend/plugin/cluster dispatch
→ effect observation and local state/lease/token commit
→ response audit gate
→ response
```

HTTP method 不能被直接当作只读；动态 secret 的 GET 会创建 lease。Client disconnect 不撤销已经 commit 的 authority，也不授权重试。Response audit 在 external effect 后失败时，系统保留 opaque effect reference 和 digest，随后只能通过重新审计的 retrieval、revoke、compensation、lookup 或 manual hold 处理。

## 6. Durable Domain 单写者

- Canonicalization/operation registry：`heptabao-protocol`
- Barrier envelope/keyring：`heptabao-barrier`
- Seal lifecycle：`heptabao-seal`
- Mount/system registry：`heptabao-system`
- Policy source/decision：`heptabao-policy`
- Entity/group/alias/MFA：`heptabao-identity`
- OIDC provider/key：`heptabao-identity-oidc`
- JWT external login：`heptabao-auth-jwt`
- Token store/graph/wrapping：`heptabao-token`
- Token auth mount API：`heptabao-auth-token`
- Lease/effect intent/reconcile：`heptabao-lease`
- Audit gate/device config：`heptabao-audit`
- Plugin catalog/process：`heptabao-plugin-host`
- Namespace tree/keyring/seal context：`heptabao-namespace`
- Workflow：`heptabao-workflow`
- Raft FSM：`heptabao-storage-raft`
- Cluster membership/forwarding：`heptabao-cluster`
- Migration authority：`heptabao-migration`
- Qualification/claim/grant/revocation：`heptabao-qualification` 与 `heptabao-governance`

Projection、cache、adapter、standby、Oracle 和 migration comparator 都不是 writer。

## 7. Program Gates

| Gate | 目标 | 候选级别 | 标准窗口 |
|---|---|---:|---:|
| H00 | 治理、来源、Clean-room、权限与资格基础 | C0 | M0–M3 |
| H01 | Oracle 实验室与行为清单 | C0 | M1–M8 |
| H02 | Rust 平台、依赖与供应链 Bakeoff | C0 | M2–M10 |
| H03 | 协议、类型、规范化、错误与 Effect 模型 | C0 | M4–M12 |
| H04 | Physical Storage、事务、耐久性与 Schema | C1 | M6–M16 |
| H05 | Encryption Barrier、Keyring、Ciphertext Envelope | C1 | M8–M20 |
| H06 | Init、Seal/Unseal、Rekey、Recovery、Auto-unseal | C1 | M10–M22 |
| H07 | Core Pipeline、Router、Mount、System Backend | C1 | M10–M22 |
| H08 | Policy/ACL、Template 与参数约束 | C1 | M12–M24 |
| H09 | Identity、Entity/Group/Alias、MFA、OIDC Provider | C2 | M16–M30 |
| H10 | Token、Cubbyhole、Wrapping、Root/Recovery | C2 | M16–M32 |
| H11 | Lease、Expiration、WAL、Rollback、Reconcile | C2 | M18–M34 |
| H12 | Audit Broker、HMAC/Redaction 与 Devices | C2 | M16–M30 |
| H13 | Plugin Protocol、Catalog、OCI、Sandbox | C3 | M22–M40 |
| H14 | Namespaces、隔离与 Namespace Sealing | C3 | M22–M40 |
| H15 | Profiles、Workflows、Declarative Self-init | C3 | M26–M44 |
| H16 | 全部 Built-in Auth Methods | C3 | M24–M48 |
| H17 | KV、Transit、TOTP、Internal Backends | C3 | M24–M42 |
| H18 | PKI/PKIext 与 SSH | C3 | M30–M50 |
| H19 | Dynamic Engines 与 Database Providers | C3 | M34–M56 |
| H20 | Integrated Raft、Transaction、Snapshot、Autopilot | C4 | M24–M48 |
| H21 | HA、Cluster mTLS、Forwarding、Read Standby | C4 | M34–M58 |
| H22 | HTTP、CLI、Agent、Proxy、OpenAPI、UI Adapter | C4 | M28–M52 |
| H23 | Operations、Telemetry、Limits、Diagnostics、Reload | C4 | M32–M56 |
| H24 | Migration、Snapshot Conversion、Upgrade、Rollback | C4 | M42–M66 |
| H25 | Formal、Fuzz、External Audit、Red Team | C4 | M8–M70 |
| H26 | Performance、Capacity、Chaos、Long Soak | C4 | M24–M70 |
| H27 | Supply Chain、Canary、GA、LTS、Upstream Sync | C5 | M60–M84 |

Work Package 才是实际排期单元。后续 gate 可以在前序的 required interface/spec/test seam 被 `FROZEN` 后开始编码，但只有前序 signed qualification receipt 完整后才能获得自身资格；release 还必须满足 profile 和跨 gate 条件。

## 8. 分阶段 DoD

每个 Work Package 至少包含：

- versioned normative spec；
- threat-model delta；
- owner 与唯一 writer；
- public/internal API；
- positive tests；
- negative、fault、crash 或 adversarial tests；
- Oracle fixtures 或 deviation；
- requirement/invariant/test/evidence links；
- dependency/SBOM delta；
- migration/rollback note；
- independent review when critical；
- evidence bundle 和 immutable receipt reference。

每个 Program Gate 只有在所有 profile-required Work Package qualified、global blocker 为 0、依赖 receipts 有效、残余风险签名接受后才可产生 Qualification Receipt。Compatibility Claim 和 Authority Grant 必须另行签发。

## 9. 密码与 Barrier

不得设计新密码原语。H02 先选择并审计成熟 provider；H05 才实现 versioned authenticated envelope。Envelope 至少绑定 format version、cipher suite、key version、storage key、namespace ID、object class、nonce 和 tag。Nonce uniqueness、AAD、key lifecycle、rollback、snapshot clone、crash recovery 和 rotation 必须分别证明。

`rekey`、barrier root rotation、encryption-keyring rotation、auto-unseal provider rotation 和 namespace seal 是独立状态机，不能用模糊的 `rotate` 操作合并。任何 KMS/HSM outage、key deletion、rollback 或 partial ceremony 都必须 fail closed 并保留可恢复证据。

## 10. Token、Lease 与 External Effects

Service token 使用高熵 opaque value；持久层只保存 keyed digest/accessor mapping。Batch token 使用版本化认证密文，绑定 namespace、policies、identity、parent、TTL 和 key epoch。Parent graph、orphan、periodic、explicit max TTL、num uses、CIDR、role、cubbyhole、wrapping、recovery 和 root ceremony 均为独立 Work Package。

Lease 绑定 namespace、path、issuing token、renewability、TTL/max TTL、plugin instance、operation key 和 revoke payload。Dynamic credential/provider effect 在调用前持久化 intent；响应未知时不重新创建。无法证明 revoke 成功时记录 irrevocable/revoke-error，不能伪装完成。

## 11. Plugin 与 Sandbox

Rust built-in 使用静态 trait/registry，不承诺稳定 Rust ABI。外部插件使用版本化进程协议、gRPC/mTLS、catalog、type/name/version/digest/command/args/runtime UID 绑定。Plugin directory 禁止 symlink，校验 owner、mode、size、digest、signature 和 SBOM policy。

Linux sandbox 可使用 namespace、seccomp、Landlock、cgroup 和 `no_new_privs`，但兼容模式也不得扩大 host 权限。Seal、stepdown、shutdown、disable、reload 和 connection mutation 必须正确 fence/terminate plugin；crash/hang/fork bomb/output flood/FD leak 都进入 qualification。

## 12. Storage、Raft 与 HA

Storage API 明确 transaction、CAS、list/scan、lock、consistent read、snapshot、restore 和 durability contract。Committed write 的目标 RPO=0；torn write、fsync、disk full、corruption、partial migration 和 reopen 必须可注入、可重放。

H20 使用成熟 Raft library，但 OpenBao-compatible semantics 位于独立 deterministic FSM。FSM 内禁止系统时间、随机数、网络、KMS 和 plugin。Snapshot 有独立格式、cluster ID、barrier metadata、checksum/signature 和 atomic install。默认禁止与 OpenBao 节点混合集群和直接读取 OpenBao `raft.db`。

H21 的 cluster traffic 强制 mTLS；join 绑定 cluster ID、node identity、unseal challenge 和 membership authority。可能写入的 GET 只能在 active 执行。Read standby 使用 applied-index/freshness policy；安全敏感读取可强制 active。Stepdown/leader loss 取消 active-only context 并 fence 旧 owner。

## 13. 迁移

固定流程：

```text
Inventory
→ Observe
→ Shadow Read
→ Offline Import Rehearsal
→ Source Writer Freeze
→ Final Logical Delta
→ Verify
→ Authority Epoch/Fence
→ Target Canary
→ Signed Cutover
```

不把 OpenBao 和 HeptaBao 指向同一个可写 backend；shadow 不执行第二次 dynamic effect；未决 token、lease 和 external effect 必须 reconcile、revoke 或 manual hold。Target-only irreversible effect 发生后禁止简单 rollback，改为签名前向恢复。

## 14. 测试、形式化与安全

- 类型/解析：unit、compile-fail、property、fuzz；
- 并发：Loom、deterministic scheduler、stress；
- 密码：KAT、cross-provider、tamper、nonce/AAD、external review；
- 状态机：TLA+、Stateright、Kani、trace replay；
- 存储：kill points、torn write、fsync、corruption、reopen；
- 分布式：Jepsen-style、partition、membership churn、snapshot、linearizability；
- 外部集成：真实服务和版本矩阵；
- 兼容：raw fixture + versioned normalization + side-effect differential；
- 安全：continuous fuzz、Miri、sanitizers、red team、secret canary；
- 供应链：cargo-vet/deny/audit、SBOM、reproducible build、signatures、transparency。

安全工作从 H03/H04/H05 即嵌入；H25 负责集成级 closure、外部审计和红队，不是“开发完成后再补安全”。

## 15. 性能和 SLO

生产比较必须使用相同 hardware、TLS、audit、storage、durability 和 payload。不得通过关闭 audit、fsync、ACL、TLS 或扩大 stale cache 获得性能。

RC 初始目标：committed write RPO=0；hot KV/token/policy p99 不高于 OpenBao v2.6.2 同条件 1.25 倍；吞吐不低于 0.9 倍；30 天 soak 无 unbounded memory/task/fd growth；audit backpressure 不丢 event；read standby staleness 有 index/freshness evidence；secret leak canary=0。例外必须是签名、限期、可撤销的风险接受。

## 16. 团队与容量

标准目标为 34 dedicated FTE：governance 3、Oracle 4、crypto 4、core 6、storage/Raft 5、ecosystem 7、edge/ops 3、qualification/release 2；另需独立法律、密码学、分布式系统、红队和 release/incident 能力。

时间线：C1 M12–20；C2 M20–30；selected C3 M30–48；C4 M42–62；Full C5 M60–84。加速 M52–68 仅在第 9 个月前 34+ FTE、Oracle 自动化第 6 个月完成、三条长期独立实现线、H05/H20 前签约外部审查和严格 profile scoping 同时满足时成立。每季度和任何 scope/security/staffing/dependency/audit 变化后重算。

## 17. 当前 H00 与下一步

本开发分支已经实现：

- `H00-WP01` 仓库和执行基线；
- `H00-WP02` Program Gate + 并行 Work Package + 三类依赖模型；
- `H00-WP03` Qualification/Claim/Grant/Revocation 分离与 fail-closed schema；
- `H00-WP04` semantic validator、CI 和 Rust governance sentinel。

GitHub workflow 当前未获得 Runner，远端记录为 `steps=[]`、`runner_id=0`；这属于 `INFRASTRUCTURE_UNEXECUTED`，不能被算作测试通过或失败。H00 仍未 qualified。

H00 下一批必须关闭：

1. `H00-WP05` Oracle/spec/implementation/interop-exception 的真实人员、仓库与 ACL 隔离；
2. `H00-WP06` license、trademark、patent、export 和公开发布结论；
3. `H00-WP07` private security disclosure、incident owner、24/7 escalation 和 canary revoke；
4. `H00-WP08` signing key/HSM、provenance、transparency log 和 revocation ceremony；
5. `H00-WP09` budget owner、34-FTE ramp、independent reviewer 和 external-audit contracts；
6. `H00-WP10` 在真实 Runner 和独立 approvals 上签发第一个 H00 receipt。

在这些条件完成前，所有 compatibility、production、migration、release、mixed-cluster、OpenBao physical-storage read/write、real-secret fixture 和 root-token fixture authority 必须保持 false。
