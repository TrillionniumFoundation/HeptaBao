# OpenBao 2.7.1 验收分母与证据资格审计

## 结论

当前还没有闭合的 OpenBao 2.7.1 全量验收分母。旧 corpus 的 59 个 surface 和 472 个 fixture ID 确实重算一致，但它的目标是 **2.6.2**；已有 **2.7.0** 真实实例清单记录了 511 条 generic path、735 个 operation，也明确不覆盖所有部署和外部插件。两者均不能改标签后算成 2.7.1 资格。

本次固定官方 2.7.1 tag/commit/tree，并独立读取注册表、CLI、HTTP 和系统路由生成代码，以及候选 21a 的正式 V6 接入谓词。发现的明确门槛包括：正式 V6 目前不接纳带 JWT/OIDC/Kubernetes auth、数据库、MFA、SDK/plugin owner、external-key 或独立 namespace custody 的完整存量状态。已有 34MiB KV2 迁移成功不能覆盖这些存量所有者。

审计没有运行远端进程，没有改产品，没有读取凭证明文，没有重启此前被自动安全检查拦截的开发。这里只生成待归档的审计文件；完整替代、所有客户端已迁移、可删除旧版三个结论仍为 false。

## 1. 固定身份与可重算的源代码清单

官方标签 `v2.7.1` 直接指向 `a5db72cef75c24b920ade02065b18dd8eb666bac`，tree 为 `3a8ba726d8d557a5f9b3f2ed28b406da33632182`。候选固定为 `21a521e3e59af291dd2abc6721e8559e06338657`，tree 为 `625b0a5d4e2bce62fe0b014edff9c18f96840a3c`。

| 来源 | 本次重算结果 | 计数含义 |
|---|---:|---|
| builtin plugin registry | auth 6、secret 7、database 9 | 仅各注册 map 的名字；别名保留 |
| command registries | audit 4、physical storage 5、service registration 1 | 配置/工厂注册名字 |
| CLI command map | 127 个唯一 key | 包括父命令与子命令；不等于参数或行为用例 |
| SystemBackend constructor | 34 个 path builder 调用 | raw 与 raft 两项按配置出现 |
| logical_system_paths.go | 86 处 Pattern 字段 | 仅一个源文件的词法计数，不能称全部 endpoint |

Auth 注册名为 approle、cert、jwt、kubernetes、oidc、userpass。JWT/OIDC 共享工厂。Secret 注册名为 kubernetes、kv、pki、rabbitmq、ssh、totp、transit；database 由命令层另行注册。Token、system、identity、cubbyhole 及 namespace 共享后端由 Core 注册，不在上述 plugin 数中。

Database 注册名包含 Cassandra、InfluxDB、PostgreSQL、四个 MySQL 名字、Redis 和 Valkey。四个 MySQL 名字使用不同用户名模板的构造入口；Redis/Valkey 共用工厂，别名行为仍需保留验收。Physical storage 名字为 inmem_ha、inmem、raft、postgresql、pebbledb；其中两项为内存后端。

这些数不能相加成为“功能总数”。完整 127-key 清单和每个引用的 commit/blob 在 accompanying JSON 中。

来源：[builtin registry](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/helper/builtinplugins/registry.go)、[commands](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/command/commands.go)、[Core](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/core.go)、[SystemBackend](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go)、[system path declarations](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system_paths.go)。

## 2. 为什么现有分母仍不完整

旧 `complete_surface_corpus_v1.json` 的 target=2.6.2、11 类、59 surface、472 个唯一 fixture ID，且独立 current exact-head observation=0；所有兼容、生产和完整覆盖 claim 都为 false。候选的 inventory 目录仅存在 2.6.2 和 2.7.0。

2.7.0 observed inventory 使用固定官方真实非 HA PebbleDB 实例，启用了 15 个 auth/secret variant mount，记录 511 个 generic path 和 735 个 operation。该文件明确写明 candidate semantics、full replacement、全部部署/插件路由资格均为 false。

官方 `pathInternalOpenAPI` 先选择调用者有权看到的 mounts，再调用各 backend 的 HelpOperation 合并文档。它依赖实际启用的 mount、KV 版本、namespace、配置和 backend；单个普通 PebbleDB 实例不会自动囊括条件 Raft 路由、恢复模式、listener 直挂 HTTP 路由、CLI/Agent/Proxy/UI 或外部 provider 效果。OpenAPI 文档本身也不证明每种状态转换正确。

来源：[2.6.2 corpus](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/qa/openbao-acceptance/complete_surface_corpus_v1.json)、[2.7.0 observed inventory](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/oracle/inventory/openbao-v2.7.0/builtin-surface-observed.json)、[OpenAPI generator](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go)、[HTTP handlers](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/http/handler.go)。

## 3. 2.7.1 必须单列的版本语义

2.7.1 安全修复应分别有不可混用的验收项：sanitized config 隐去 ACME EAB MAC key；匿名 root/rekey 在 audit 故障时拒绝交付；SecretID 在 tidy 前过期也拒绝；form AppRole login 的解析；cert role quota 传入真实 TLS connection；Kubernetes renewal 再验证 Service Account JWT。

源码目录已有 AppRole、control-group、Kubernetes 2.7.1 相关脚本。源文件存在不等于在候选 21a 实际执行过。尤其本次读到的 `quota_role_271_live.py` 题头和业务范围明确是 **AppRole role quota**，不能拿它替代 cert/TLS role-quota 修复的回归。

2.7.0 新增且 2.7.1 仍需涵盖 External Keys、PKI/Transit ML-DSA、PQC TLS、PostgreSQL HA read scaling、consistency headers、PebbleDB 和 Control Groups。2.7.1 另涉及 rotation disabled 持久化、gRPC invalidation 生命周期、Raft auto_join 地址带端口、PostgreSQL applied LSN、LifetimeWatcher backoff。

LDAP/RADIUS/Kerberos auth、LDAP secret 和若干 KMS provider 从 core 移到外部插件，file storage 已移除。旧分母里的这些条目不能当成现版内建；若实际部署仍使用它们，必须以准确插件版本、digest 和 provider 接入单独保留，不能直接从迁移清单删除。

版本依据：[fixed release notes](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/CHANGELOG.md)。脚本路径、blob 和审计读取层级见 JSON。

## 4. 候选正式 V6 的真实接入边界

以下是读取 21a 实际谓词得到的范围，适用于正式 native V6 profile；它不等于整个仓库所有 V5/adapter 功能的有无。

| 维度 | 谓词接受的范围 | 仍不接纳的主要现存状态 |
|---|---|---|
| root auth | token / AppRole / cert / userpass | JWT、OIDC、Kubernetes、LDAP、RADIUS、Kerberos、plugin auth 配置；identity MFA、password policy、SDK credential state |
| 普通子 namespace auth | token / AppRole / cert，service token | Userpass、batch roles，以及超出普通 catalog/custody 形状的状态 |
| root secret | KV1/KV2、本地 Transit、TOTP、SSH、满足 native_local_profile 的 PKI | 数据库、其他动态 engine、SDK owner/lease、external keys |
| 普通子 namespace secret | KV1/KV2 | 其他 engine 和 provider owner |
| namespace/control groups | 普通 root-barrier namespace、受支持的 KV2 create/update/read control-group 形状 | 独立 sealed/protected custody、namespace lease、workflow/其他 controlled target |
| storage startup | Shamir file custody；Raft 要已入组且 seed 已明确初始化完成 | PostgreSQL durable、Wrapper、SDK/plugin/external KMS adapter；native V6 Raft 不接纳 fresh init |
| Raft administration | 默认状态 | 非默认 management policy 需独立迁移 |

`service_native_storage.rs` 的错误文本列举的 engine 比实际谓词少。本报告已跟到 engine/Auth predicate，未把那条错误文本误当完整能力清单。PKI 是否符合 local profile、各类 token 和控制组的进一步约束仍需要逐状态验证。

`server_storage.rs` 也明确 native on-disk/SQL format 并不是 OpenBao physical format。配置接受 pebbledb/raft 名字不构成文件或快照格式兼容；必须使用明确、验证过的迁移/恢复路径。

来源：[storage admission](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/service_native_storage.rs)、[storage configuration](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/server_storage.rs)、[plain namespace](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/service_native_plain_namespace.rs)、[Auth predicate](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/auth_native_v6_routes.rs)、[engine predicate](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/engines/native_empty_namespace.rs)、[control groups](https://github.com/TrillionniumFoundation/HeptaBao/blob/21a521e3e59af291dd2abc6721e8559e06338657/crates/heptabao-server/src/service_native_controlgroups.rs)。

## 5. 当前证据只能授予对应源代码的资格

| 源码/证据 | 已独立读取的实际结论 | 不能授予的资格 |
|---|---|---|
| 21a，r5 syntax job 30a2 | 控制脚本 compiled=true；driver/source preflight/product build/test 均未执行 | 当前产品通过、Mac 14项通过、LAN或切换 |
| 21a 预定候选，r5 实际 job 30d1 | 0.349972 秒因现有外部产品进程被守卫拒绝；实际输入仍为 f064/tree5389 且 clean，4 条只读命令完成，0 项测试执行 | 补丁未应用、未 strict/编译/link；不能算产品回归通过 |
| f064/tree5389，Mac r3 | strict/libtest compile成功；14项5通过9失败 | 不能转授21a；没有normal server link或34-case HTTPS通过 |
| 7071/treeef0，X230 | 正式native_v6_file，31/31；17 retained versions共34MiB；export/import各一次；恢复/CAS/冷重启；408 child终态完整 | 全实例、其他engine、后继源码、HA、生产流量、跨产品物理快照 |
| 7071，完整workspace | 67 groups，4752 pass / 8 fail / 9 ignored，cargo101 | 全workspace通过 |
| 33系列，AuthBus r4b | 421项验证了真实双writer反例、清理与rollback；singleWriterGatePassed=false | 修复有效、新candidate或默认gateway切换 |
| 33系列，历史LAN | 本次仅记录root上下文中的128/98历史数，未重新读取完整原件 | 本次独立复现或任何21a资格 |

JSON 每行有精确证据 commit/path/blob/job。r5 已取得完整权威终态和原始结果：它在应用补丁前被并发守卫拒绝；顶层 input_tree 是预定目标，不是已应用源码。此前 Mac 5 通过/9 失败的实际记录保持不变。[r5 原始结果](https://github.com/TrillionniumFoundation/HeptaBao/blob/edbdb2f754bbd9cb8d84418f3d04bac970e970e6/qa/evidence/20261105/ha-mac-snapshot-api-attempt-61ff-r5/execution/candidate-normal-result.public.json)

## 6. 逐台迁移与清理分母

已独立重读六机 inventory 的固定原件：53 个 service-path candidate、91 个非递归 backup-path candidate；这些不是 53 个已证明服务或 91 份可恢复备份。ROG/Pocket Docker listing 实际失败，不能写“无容器”。AI395 缺席结果只对原扫描范围有效。Desktop 有单独本机 provider/gateway/renewal，仍要独立迁移。X230 的固定 OpenBao 2.7.1 oracle 要保留。

报告 all_clients_migrated、all_backup_restore_paths_migrated、complete_asset_inventory、retirement_qualified 全为 false。需要把实际客户端、服务、计划任务、TLS续期、备份及恢复脚本分别关联到配置、凭证来源、端点、一次读写、restart、rollback 和 cutover 收据，才可逐项退出旧安装。

来源：[six-host root review](https://github.com/TrillionniumFoundation/HeptaBao/blob/938d6a2d57dcdd2626480387a8ed6372fa3c55a4/qa/evidence/20261104/retirement-inventory/six-host-root-review.public.json)。

root 已将六份历史报告整理为 [逐台候选台账](https://github.com/TrillionniumFoundation/HeptaBao/blob/3f910144cf1f37c3c66605d97026d036d07a61f7/qa/evidence/20261105/root-continuation-reviews-61ff-r1/fleet/fleet-candidate-migration-register.public.json)：144 个主机/路径候选组合、21 个已配置 agent 条目；没有重新扫描、切换流量或删除。全部清理资格仍为 false。

## 7. 可复核的 2.7.1 清单生成办法

1. 固定 tag/commit/tree、官方二进制 hash 与真实 version、平台/build flags、配置和插件 digest。源文件 AST 清单保留所有动态表达式与条件；无法解析的项目明确未决。
2. 在新建且独占的合成 fixture 内，用固定 2.7.1 官方 server 收集 catalog、mounts/auth、普通及 generic OpenAPI。按 registry 启用全部内建 auth/secret variant、KV1/KV2 和 database；持久保存原始响应和来源绑定，不输出令牌。
3. 补集来自 Raft/PostgreSQL 模式、namespace、raw/recovery/listener 条件和直接 HTTP handler；CLI 的127个key再拆参数、输出和退出码；部署插件、Agent/Proxy/UI/provider 为独立层。
4. 稳定ID包括版本/二进制、profile/mode、namespace、mount type/options、route/operation、HTTP或logical operation及content type。source declaration、API operation、semantic case、fleet client是四类分母，分别重算并保留未决项。
5. 为每个contract映射授权负例、状态码/结构/header、状态变化、TTL/renew/revoke、重放、审计故障、持久化与相应HA性质。把源码、实际binary、lock/build、oracle、精确case集合、request journal、owned cleanup、前后状态和rollback串成可查的证据索引。
6. 先关闭2.7.1版本分母与各受支持profile的语义，再关闭逐机依赖/backup/cutover记录。缺项不改成通过；历史来源不转授后继源码。

这只是后续验证所需的可审查规格，本次没有按此启动新实验或隐式扩大已批准的运行范围。

