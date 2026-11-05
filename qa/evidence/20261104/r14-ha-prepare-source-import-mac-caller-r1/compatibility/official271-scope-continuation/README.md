# OpenBao 2.7.1 替代范围：已固定来源、实际覆盖与下一实现项

**当前仍不能声明全量替代。** 这里更新的是既有部分源码审计的进度和执行顺序，并明确完整分母还需要怎样建立；它不是一个新的完整覆盖率。原 13 件审计包 `53081eed42653db1b8f51b840b7eb4b89e3bf7cb`、原运行失败和全部边界均保留。

## 三种现有计数的含义

| 现有材料 | 实际意义 | 不能据此声称 |
| --- | --- | --- |
| 历史 59 行 surface ledger | 明确以 OpenBao **2.6.2** 为目标的工作分类；所有 whole-surface admission 仍为 false | 已枚举 2.7.1 的全部必需能力 |
| 2.7 补充的 15 / 11 / 11 行 | 安全差异、功能/正确性差异和准入门槛的结构性声明；原文明确非穷尽 | 把这些行加到 59 后就得到完整 2.7.1 分母 |
| 实际 69 个比较案例 | 候选 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` 对固定官方二进制的有限 API 场景 | 其他认证/引擎、全错误优先级、持久重启、HA、升级、迁移或 Agent/Proxy/CLI 全覆盖 |

69 的原始来源、逐案映射和计数未变；没有把它转移给诊断源码 3cb。既有更正包 `00457eb96647344bb61944d4aa0e24e1f08e51a3` 只修正三处 family 交集：MOUNT-REGISTRY→kv/transit、POLICY-ACL→token、LEASE-EXPIRATION→pki，既不增加案例也不提高 whole 资格。

## 固定官方默认注册表

目标为官方 `v2.7.1`，commit `a5db72cef75c24b920ade02065b18dd8eb666bac`。本包保留已经完整取得并哈希绑定的 `helper/builtinplugins/registry.go` 原文，Git blob `94af1a84cec148883c926941f50eea138d3644ae`。

| 分类 | 该固定源码中的名字 |
| --- | --- |
| 认证插件 | approle、cert、jwt、kubernetes、oidc、userpass |
| Secret 插件 | kubernetes、kv、pki、rabbitmq、ssh、totp、transit |
| Database 插件 | mysql、mysql-aurora、mysql-rds、mysql-legacy、cassandra、influxdb、postgresql、redis、valkey，完整名字均以 `-database-plugin` 结尾 |
| 注册表以外的核心后端 | token、identity、cubbyhole、system，需单独审计 |

这些分别是 6、7、9 个**注册名字**，不是 API 数或独立实现数。jwt/oidc 使用同一 factory；四个 MySQL 名字共享实现但使用不同用户名模板配置；redis/valkey 使用同一 factory。默认 `addExtPluginsImpl` 为空。各名字仍有可观察的配置合同，不能因为共享实现而删去差异。

LDAP、RADIUS、Kerberos、OpenLDAP 不在该固定默认表中。若实际部署或用户范围明确配置了它们，应作为外部插件范围单列，不能从旧 ledger、UI 或 SDK 类名推定为默认内置要求。

## 必须推进的具体事项

下表依据审计候选 `3cb873919170cc77101b27f6a3ab9e98f41f8d93` 的真实 native admission、owner 和调度源码。完整原始锚点保留在 `updated/current-native-gap-map.public.json` 和 `reference/source-pins.public.json`。源码拒绝不被当作已执行的失败测试；非 native wrapper 或 SDK transport 也不被当作 native 兼容实现。

| 优先范围 | 已证实的当前边界 | 最小下一工作与源码入口 |
| --- | --- | --- |
| **当前迁移门槛：真实 native snapshot / 官方 CLI / standby** | 旧 B01 leader save 得到 503、CLI exit 2，仍保持 unknown；未产生合格归档。3cb 仅增加有界失败观察，不是行为修复 | 在全新 Phase B fixture 中识别具体 admission 错误；依据真实错误修复。入口：`service_snapshot_transfer.rs`、`http_snapshot.rs`、`ha_native_v6_runtime.rs`。真实 archive A/B、API 内容与冷启仍需实证；streaming relay 的 custody / negative audit / unsettled fence 必须单独落地 |
| **Native 认证与 MFA** | native profile 要求 JWT/Kubernetes/OIDC 状态与 password policy 为空、identity_mfa absent；已准入 auth mount 集有限 | 在 `auth_native_v6_routes.rs`、`service_native_auth.rs`、`service_native_storage.rs` 增加真正 typed owner、冷恢复编码、续租/撤销和身份绑定，再扩大 admission |
| **数据库及外部 Secret 引擎** | 非空 database 状态拒绝；native EngineState 仅准入 KV1/KV2、本地 Transit、TOTP、SSH、本地 PKI，并要求 SDK owner/catalog/lease/external-key 状态为空 | 在 `service_native_storage.rs`、`engines.rs`、`service_plugin.rs` 建立每个后端的 durable external-effect/reconciliation。真实 provider 创建、轮换、撤销、unknown 结果和迁移恢复必须分开验证 |
| **PKI ACME/EAB 与外部 KMS/HSM** | local PKI profile 排除外部 signer/history 和非默认 ACME；native local route 排除 ACME/EAB 与 KMS selectors；Transit 外部状态也被排除 | 为这些状态与外部动作增加 native owner、审计、一次请求/结果 custody 与 cold codec。入口：`engines/pki_native.rs`、`engine_native_pki.rs`、`service_plugin.rs` |
| **系统密钥/生命周期** | native 对 rekey/raw 和未拥有的系统操作拒绝；activation 排除 pending rekey/recovery；部分 wrapper/PGP backup 有独立 501 | 依据官方已注册的 rekey/rotate/generate-root/namespace-seal 合同实现 native epoch/key owner 和冷恢复。raw 必须按 rawEnabled 配置分别定义，不是普遍开放底层数据 |
| **Plugin catalog 与运行时 SDK owner** | catalog mutation 501；没有 durable reconciliation 的通用写插件拒绝；native profile 不允许这些 owner 状态 | 在 `service_plugin.rs` 增加真实注册、CRUD/reload、root namespace 和命令路径围栏。插件可启动、checksum 正确或 transport 测试通过不足以证明业务生命周期 |
| **Namespace、workflow、策略及集群管理** | protected namespace custody / namespace leases 未普遍准入；部分 control-group owner 受限；非默认 raft_admin 状态不满足 native migration profile | 在 `service_native_plain_namespace.rs`、`auth_native_v6_routes.rs`、`service_raft_admin.rs` 逐 owner 补齐配对迁移、真实 incarnation、finite actor、审批和管理状态，不用统一空状态绕过 |
| **工具、存储适配器和 2.7.1 差异分母** | CLI/Agent/Proxy、存储迁移、UI/OpenAPI 和版本差异未被 69 覆盖；现有两个分母文件不穷尽 | 从实际官方注册/dispatch 和 CLI 命令构建 route×operation×config/backend×lifecycle 矩阵，逐项关联当前候选证据；部署特定的迁移范围与通用兼容声明分开 |

这八组是已经定位的行动项，不是“2.7.1 恰好有八类缺口”的穷尽声明。前三个默认 registry 类别之外还有核心 backend、配置条件、CLI 与存储合同，需要独立追踪。

## 不应新增的假门槛

- 当前 native SSH 已有真正 typed owner 和 OTP lease 方法。旧“SSH unsupported”测试假设不能继续作为当前缺口。
- 仅看到 native `sys/replication*` 拒绝，并不能证明官方默认存在相应操作 backend；本审计只确认 special unauthenticated path 的线索，实际注册仍需确认。
- 官方 `operator migrate` 直接实例化 physical backends 并复制加密数据；不能把 native `sys/migrate` 拒绝等同于该 CLI 合同，也不能据此发明必需 HTTP route。
- raw 是配置相关的合同。应验证开启与关闭时各自的安全语义，不要求在关闭时提供读取。
- 外部 provider 的真实验证仍需其明确环境与授权；本包没有触发任何 provider、认证刷新或生产动作。

## 完整分母怎样才能成立

`denominator-construction-contract.public.json` 给出尚待完成的最小行结构：上游模块、路径或 CLI 命令、操作、必要配置/后端、存储及所有权 profile、生命周期状态。每行还需登记真实上游路由可达性、当前 native owner/cold codec、拒绝及无副作用边界、实际测试 IDs、精确候选源码/产物以及未闭合项。

应先完整枚举核心系统/认证/identity/cubbyhole 注册，再覆盖每个默认 backend factory 和 database adapter，最后单列工具与显式配置的外部插件。15/11 的 2.7 差异须落到具体行，不能只保留声明。直到这个矩阵完成并且每个必需行都有对应实现和实际证据，whole replacement 仍为 false。

## 本次只有进度变化

3cb normal 的原 44 和独立 7 已真实通过；独立 canonical source 已导入 desktop，三个产品文件的运输也已完成。新的 local-stage/prepare/live 尚未执行。完整 launch SOURCE 包是 `01c2ef7e0ac1d210eff8dad50f0ae59deb9719d3`，实际运行仍等待单独准入和独占窗口。

`updated/current-native-gap-map.public.json` 与旧 map 的差分只更新这一状态、schema 和来源附注；其他七个行动行逐字段相同。13 个离线源数据检查验证了这一点以及默认 registry 的精确名字。本包执行了零主机操作、零产品测试，未改原审计、原 69、旧 unknown、源代码或任何 branch/ref。
