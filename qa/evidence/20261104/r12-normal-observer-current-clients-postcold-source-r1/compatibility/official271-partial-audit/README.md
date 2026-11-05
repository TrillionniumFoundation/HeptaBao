# OpenBao 2.7.1 替代范围：固定源码审计与下一步开发清单

## 结论与使用边界

**当前不能声明“完整替代 OpenBao 2.7.1”。** 本包把旧 59 行范围、现有 69 项真实对照以及 2.7.1 的声明增量放在同一份可核对的映射中，并定位当前原生存储明确拒绝的能力。它是开发范围审计，不是新运行资格，也不是对上游所有路由的穷尽证明。

产品源码固定为 `3cb873919170cc77101b27f6a3ab9e98f41f8d93` / tree `7f4d48a647a81ca96e8a24a0a057c2c829459060`。上游官方 tag `v2.7.1` 直接指向 commit `a5db72cef75c24b920ade02065b18dd8eb666bac`；实际读取的递归树有 6,328 项，`truncated=false`。本包的 `source-pins.public.json` 绑定 14 份产品源码、11 份上游源码、5 份既有范围声明及实际 69 项原件。GitHub API 原始树文本的 SHA 是内容绑定，不意味着本审计已经逐文件理解全部上游代码。

生成本包时，3cb 的唯一正常构建仍在运行。本包没有执行产品、CLI、provider、OAuth 刷新或主机命令。3cb 只增加已有失败路径的有界诊断并修正其 Rust 类型注解，不能凭源码将旧 B01 的 503 或 unknown 改成已知原因、行为修复或 PASS。

## 三个分母分别代表什么

| 清单或证据 | 实际含义 | 不能推出的结论 |
| --- | --- | --- |
| 当前 `HEPTABAO_SURFACE_WORK_V1.json` 的 59 行 | 文件仍标注 OpenBao **2.6.2**；历史声明为 2 个 runtime_complete、52 个 runtime_partial、5 个 tooling_partial，59 行 whole_surface_admitted 全为 false | 不能当作 2.7.1 的完整产品面，也不能把两个 runtime_complete 当作两项全面合格 |
| 实际 R10/X230 的 69 项对照 | 495033 候选、正式 native_v6_file、非 fixture 启动；官方 2.7.1 binary/archive/member/TLS 关联在外层 execution_binding 中，69 项 scoped case 全匹配 | 不能涵盖其他认证/引擎、全部错误优先级、重启、HA、迁移、升级、Agent/Proxy/CLI 或生产安全 |
| 2.7.1 admission supplement | 15 条安全增量、11 条功能/正确性增量、11 个 gate；现行结构校验器明确不证明上游穷尽覆盖或可执行兼容性 | JSON 中 OPEN/null 是该冻结规划文件的值，不能据此否认后来独立证据；反过来，列出 ID 也不是已经执行 |

`legacy-59-to-current-source.public.json` 逐行保留全部 59 个 ID、原目标版本、历史状态、当前精确源码 blob、已实际读取全文与仅解析树路径的区别、对应行动项及 69 项家族交集。55 行能解析到当前源码路径；路径解析本身不证明实现完整。Token 的两行映射共享同一组 10 个实际 case，不重复累计。

`bounded69-case-map.public.json` 从真实原件提取全部 69 个 case 的 method、path_template、candidate/oracle 状态及原语义投影。两份完整实际原件也保留原字节。其家族为 AppRole 3、core 1、edge_tls 1、identity 6、KV 18、operations 1、PKI 12、system 1、token 10、TOTP 2、Transit 10、userpass 1、wrapping 3。

## 官方默认注册表的准确边界

固定官方 `internal/helper/builtinplugins/registry.go` 第 56–96 行注册：

- 认证名称：approle、cert、jwt、kubernetes、oidc、userpass。其中 oidc 复用 JWT Factory。
- secret backend 名称：kubernetes、kv、pki、rabbitmq、ssh、totp、transit。
- database plugin 名称：mysql、mysql-aurora、mysql-rds、mysql-legacy、cassandra、influxdb、postgresql、redis、valkey 对应的 database-plugin 名称。四个 MySQL 名称使用同一实现的不同用户名配置，redis/valkey 也不能当作两套独立实现。
- `addExtPluginsImpl` 在该默认源码中为空。

这些是注册名称集合，**不是整个 OpenBao 的能力总数**。token、identity、cubbyhole、system 等核心 backend 不在这个插件表内。LDAP/RADIUS/Kerberos/OpenLDAP 不在该固定默认表中；旧 59 行的相关项目可代表历史承诺或配置中的外部插件，但不能仅凭 UI、客户端 helper 或旧标签宣布它们属于此版本默认内置 backend。[官方注册表](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/helper/builtinplugins/registry.go#L56-L96)

## 按当前源码定位的行动顺序

下面第 1 项直接影响本次已约定的迁移门槛。第 2–8 项是完整替代声称所需的产品或证据工作，不能全部当作这次 AuthBus 四键切换的隐含新前置。正式切流仍需既定备份、恢复、消费者与 hold 条件；本包没有解除它们。

| 顺序 | 当前边界与最小入口 | 下一步必须交付的能力或证据 |
| --- | --- | --- |
| 1. 合法 native archive 与官方 CLI | 旧 B01 leader save 为 503/CLI exit 2、无合法 archive、unknown；已证明 admission Complete 先于 external export，具体 inner error 尚未知。默认 standby snapshot 的 wire 差异仍在 | 完成当前独立 3cb normal qualification后，另审 fresh Phase B；保留 15/8 等原期限、一次 ownership 和 negative settlement。诊断后才能修实际错误。合法 archive A/B、API 两版本和 cold 验证缺一不可；307 或 CLI exit 0 不能代替恢复证明 |
| 2. JWT/OIDC、Kubernetes、MFA 与密码策略 | `Auth::native_v6_storage_profile` 要求相关状态为空；root auth 只允许 token/AppRole/cert/userpass，已纳管 child auth 只允许 token/AppRole/cert | 真实 typed native owner、持久 codec、renew/revoke/身份绑定、cold 与迁移验证。先补 owner，再讨论扩大 allowlist |
| 3. 数据库、Kubernetes/RabbitMQ secret 与外部租约 | native storage 拒绝非空 database；EngineState 的 root profile 要求 SDK owners、SDK leases、external_keys 为空 | 每个 backend 的外部效应准入、durable result/unknown custody、reconcile 和租约退休；真实 provider fixture 必须与 fake transport 测试分开 |
| 4. ACME/EAB、外部 KMS/HSM PKI/Transit | native local PKI profile 要求无 external/history 且 ACME default；local route 排除 ACME/EAB/KMS selectors；native Transit 不接受 external state | native 持久化外部密钥/ACME owner、授权和 mandatory audit、异常与重启证明；不能将现有 local PKI12/Transit10 泛化为这些能力 |
| 5. 系统生命周期 | native dispatcher 明确拒绝 rekey/raw 及未纳管 sys 路径；activation 要求无 pending rekey/recovery。官方真实注册 rekey/rotate/root generation/namespace seals；raw 有条件启用 | 保留 key/epoch/finite actor/audit 的 typed native 生命周期与 cold 恢复；明确 rawEnabled 条件，不直接开放原始存储 |
| 6. 插件目录 CRUD 与原生 SDK owners | `service_plugin` 的 catalog mutation 仍返回 501，write-capable generic plugin 需外部效应 reconcile；native profile 同时排除这些 owner | root-only/command path confinement、实际插件注册/卸载/reload、原生持久 owner 和运行证明；wrapper、checksum 或 transport 不能替代 CRUD/语义 |
| 7. namespace、workflow/control group 与管理策略迁移 | native plain namespace 拒绝 protected custody/namespace leases；control groups 限于已绑定的 KV2 read/create/update owner；activation 要求 Raft admin 为 default | 对缺失的 namespace/admin/workflow owners 给出准确范围、持久模型及成对迁移；不能把现有 HA128/Direct98 当成全部管理功能 |
| 8. 工具、存储和 2.7 的额外行为 | 历史 59 与 supplement 都不构成穷尽新版分母；Agent/Proxy/CLI、物理存储迁移、发行默认、安全增量另有合同 | 从固定上游 source 的 route/operation/backend/tooling 构造明确分母，并将每项映射到同候选真实证据；把本机部署迁移和普适 API 兼容分开声明 |

具体产品入口：

- [native auth profile](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/auth_native_v6_routes.rs#L112-L197)
- [native root activation/restore guard](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/service_native_storage.rs#L130-L160)
- [native engine owner profile](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/engines.rs#L188-L213)
- [local PKI route/profile](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/engines/pki_native.rs#L1-L32)
- [native dispatcher closed allowlist](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/service.rs#L5113-L5198)
- [plugin catalog refusal](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/service_plugin.rs#L1084-L1128)
- [plain namespace profile](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/service_native_plain_namespace.rs#L16-L45)
- [control-group admitted owner shape](https://github.com/TrillionniumFoundation/HeptaBao/blob/3cb873919170cc77101b27f6a3ab9e98f41f8d93/crates/heptabao-server/src/auth_native_v6_routes.rs#L199-L229)

这些边界是保护旧状态和未纳管 effect 的真实拒绝。修复不能只把 501/409 改成成功，也不能把 flat State、工具 wrapper、历史 fixture 或 mock provider 的成功当成 native ownership。

## 不应凭字符串另造的门槛

**SSH 已有 native owner。** 当前 EngineState 明确允许 Backend::Ssh，`engine_native_ssh.rs` 有真实请求实现。旧 CI 使用 SSH 充当“未支持 owner”的四个负例已被识别为过时假设；相关测试修正属于 6d3040 源，不把旧失败改写为产品路由失败。SSH 全面兼容仍需自身分母，但不能再在本包中列作“完全没有原生实现”。

**sys/migrate 不等于官方 operator migrate。** 固定官方 `operator_migrate.go` 直接实例化物理源/目标 backend 并复制加密条目。产品对某个 HTTP sys/migrate 的拒绝，既不是该 CLI 合同的完整证明，也不是上游必须存在同名 HTTP 路由的证明。[官方迁移命令](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/command/operator_migrate.go#L1-L180)

**replication/status 特殊路径不自动证明可操作的 replication 产品面。** 本次确见官方 SystemBackend 的特殊路径声明，但尚未建立完整 operational backend/route 证据，因此保留 conditional/unresolved，不能从产品 501 独立推出一项新实现承诺。

**raw 是条件功能。** 官方 SystemBackend 只有 `core.rawEnabled` 才附加 rawPaths；Raft routes 也依实际 Raft backend 条件附加。根请求管线、权限和发行配置必须与路线一起映射。[官方系统路径装配](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go#L134-L175)

## 2.7.1 supplement 的处理方式

`declared-271-delta-review.public.json` 保留冻结文件的完整 15 安全/11 功能/11 gate 行。需要重点建立的同候选证据包括：mandatory audit 下 root generation/rekey 不外泄、SecretID 到期与 form encoding、TLS certificate quota 身份、Kubernetes revoke 后 renewal、namespace policy cache、plugin root-only 和 executable path、Agent/Proxy quit header、ACME SAN、OIDC UI、外部 KMS、PQC、索引一致性、control groups、SDK watcher backoff、rotation disabled 字段持久和默认 pebble 包配置。

这是对声明行的精确搬运和缺口分类，**不是本次逐项重做了上游 2.7 的行为对照**。69 项里某家族有 PASS 不能自动闭合一个完整安全场景。现有其他真实证据应按具体 source/ABI/入口/预算另行接入，不能用“规划 OPEN”推断那些证据不存在。

## 包内复核顺序

1. 先读本 README 与 `current-native-gap-map.public.json` 的 8 个行动项。
2. 用 `source-pins.public.json` 和 `official-source-tree-observation.public.json` 核固定身份；`official-tag-v2.7.1.raw.json` 与 `official-builtin-registry.go` 保留原文。
3. 查看 `legacy-59-to-current-source.public.json`，逐行区分历史声明、当前树中路径与实际全文读取。
4. 查看实际 `bounded69-case-map.public.json` 和两份原始 69 项收据，保持 495033 的源身份。
5. 查看 `declared-271-delta-review.public.json`，继续建立明确而可执行的新版范围，完成后才评估完整替代声称。

本包的最终状态始终是 `source_only=true`、`exhaustive_upstream_coverage=false`、`full_replacement=false`、`production_cutover=false`。它不授权主机运行或更改生产。
