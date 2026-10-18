# HeptaBao Native V6 HA Backup：下一门槛与恢复边界

## 1. 状态与适用范围

**状态：设计与源码审计记录；Native V6 HA backup / snapshot restore 尚未实现完整接线，尚未通过资格验收（UNQUALIFIED）。**

审计日期：2026-10-17。本文依据现有 Native V6 Raft、共享密文闭包、Service 本地安装和单机对象快照代码，定义下一块可实现、可验证的工作。文中的新归档格式、恢复句柄及 epoch-transition 接口均为拟议设计，不能视为已经存在的 API。

本次文档变更不开放 HTTP guard，不增加恢复入口，不改变生产流量，不删除旧服务或备份。三机 HA、34 MiB 闭包传输、单机对象快照或 record-v5 HA 快照各自的通过记录，均不能替代 Native V6 HA 备份恢复验收。远程执行受阻也不能作为省略真实主机验收的理由。

目标覆盖三个不同场景：

| 场景 | 当前可信权源 | 恢复结果 | 本文所述实现状态 |
| --- | --- | --- | --- |
| 原 quorum 存在，同一已提交根的共享密文缺失 | 原集群的真实 ReadIndex 和 opaque committed root | 只补回该根的精确密文闭包；根、epoch 和 replay ledger 不变 | 尚缺归档导出与 archive-assisted repair 接线 |
| 原 quorum 存在，恢复历史应用数据 | 当前实际根、当前 Actor、当前 protected floors | 新 epoch、新 intent、真实多数 fsync、一次新根 CAS | 尚缺 Native V6 epoch transition 与本地跨 epoch 安装 |
| 原 quorum 已丢失，进行灾备重建 | 显式恢复所有者、认证归档、独立可信恢复高水位；不存在原集群的新鲜 quorum 权源 | 在隔离的新集群建立新的实际共识权源 | 尚缺恢复 incarnation、protected-state 迁移及专门验收 |

最小下一切片是第一行所需的 **HA 归档导出 + 当前根缺块修复**。这块通过后仍不能宣称第二行或第三行已经通过。

## 2. 已有组件及其不可越过的边界

| 代码位置 | 已有能力 | 本门槛不能直接借用的资格 |
| --- | --- | --- |
| [Service 路由](../../crates/heptabao-server/src/service.rs)，`native_snapshot_route` | 单机 native V6 的专用快照入口 | 当前条件要求 `self.ha.is_none()`；HA native root 仍明确拒绝 |
| [快照请求与最终完成](../../crates/heptabao-server/src/service_snapshot_transfer.rs)，`SnapshotTransferPlan`、`stage_snapshot_transfer`、`finalize_snapshot_transfer` | 原 Actor、原时钟、单个 spool lease、物理 seal 身份、activation、HA Arc 身份及最终审计边界 | 尚未把 Native V6 的确切 Raft 根、完整 LogId 和 enrollment 作为导出选择保留下来 |
| [单机 V6 快照](../../crates/heptabao-server/src/service_snapshot_v6.rs)，`check_v6_snapshot_owner` | 本地 barrier、seal、原请求身份、当前状态根和截止检查 | 明确拒绝 `self.ha.is_some()` 与 `plan.ha.is_some()` |
| 同文件，`prepare_v6_snapshot_download` | 完整 typed graph 验证，再导出本地 `HBV6PK01` 对象包 | 未导出 HA 根指向的原共享密文闭包 |
| [归档格式](../../crates/heptabao-server/src/snapshot_archive.rs)，`Metadata::V6` | 格式、长度、本地 Durable generation、seal identity 与认证校验和 | 未包含 Raft root / intent / enrollment / membership 的完整 provenance |
| [Durable 对象备份](../../crates/heptabao-durable-service/src/v6_object_backup.rs)，`prepare_v6_backup`、`export_v6_backup_to` | 实际本地 source session、完整对象密文、AEAD 校验及受控输出 | 本地对象包不是共享 HA ciphertext closure |
| [Native HA runtime](../../crates/heptabao-server/src/ha_native_v6_runtime.rs)，`native_v6_committed_read`、`verify_native_v6_committed_read`、`with_native_v6_source` | 实际 ReadIndex、配置 pin/enrollment 核验、闭包恢复和同实例 opaque read | 不接受归档构造的 read；现有入口先要求共享闭包恢复成功 |
| [Native 本地安装](../../crates/heptabao-server/src/service_native_v6_ha_install.rs)，`LocalSelection`、`NativeHaCursor` | 用实际已提交根安装本地 barrier 对象；分离本地 generation 与 Raft generation | `covered_by` 只用于已认证本地 journal 的冷追赶，不是任意备份导入许可 |
| [Native 冷读](../../crates/heptabao-server/src/service_native_v6_ha_read.rs)，`load_cold_native_ha` | 实际本地 seal/barrier 与实际 HaProcess 下的冷恢复 | 不允许备份自声明的根替换 Raft 当前根 |
| [现有 HA 历史恢复](../../crates/heptabao-server/src/service_ha_restore.rs)，`publish_ha_native_restore` | record-v5 的新 epoch、新共识发布及后续 fencing | 实现明确要求 record-v5 root；名称中的 native 指快照传输路径，不能据此宣称 V6 对象恢复通过 |

另须保留 [Durability 与 Crash-Consistency Contract](HEPTABAO_DURABILITY_AND_CRASH_CONSISTENCY_CONTRACT_V1.md) 和 [Descriptor Anchor 与 Writer Fence Contract](HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md) 的持久化与目录所有权要求。

## 3. 本地对象包不等于共享根备份

### 3.1 两个不同的加密域

本地 `HBV6PK01` 包保存导出节点 **AeadBarrier 下的对象与 Durable core**。Raft Native V6 根指向的是 **replication key 下的共享 ciphertext closure**，两者用途不同。

[HA V6 codec](../../crates/heptabao-server/src/ha_v6_native_codec.rs) 的 `stage_object` 对新的共享对象使用随机 nonce，并把实际 cluster digest、replay epoch、typed object domain 和完整 reference 绑定到 AEAD。相同 typed 明文重新加密，通常会产生不同的密文，因此产生不同叶引用、目录对象和 closure manifest 摘要。

**不能通过重新加密本地包的明文来复原旧 Raft 根引用的精确共享密文。**

因此：

- 认证的本地完整对象包可作为新根恢复的 typed 数据输入。
- 只有本地对象包和 Raft provenance，不足以修复同一个已提交根的缺失共享密文。
- 若备份要覆盖所有共享副本缺块，必须同时保存该根选中的原始共享 manifest 和全部原始 cipher leaves。
- Raft state-machine snapshot 包含根、intent 和 enrollment 等元数据；它本身不包含这些外部密文叶。

### 3.2 完整备份集合必须声明密钥依赖

归档的完成状态不能隐含 seal metadata、unseal/recovery material、HA 配置或密钥来源已经完成备份。

当前根修复仍需要原集群实际配置和原 replication key 来打开现有共享根；本地对象包的认证需要匹配的原 seal/barrier 权源。灾备新集群可从经原 barrier 认证的 typed 本地包重新生成新共享密文，但必须在新的实际配置与恢复授权下进行。

TLS 私钥、replication key 和 unseal material 不得以明文写入公共 provenance、日志或验收报告。若后续设计选择把必要密钥包装进备份，须增加独立的受保护格式、原所有者检查和恢复验收；本文未实现或授权该扩展。

## 4. 最小 HA 归档设计（未实现）

新增明确的 HA 归档 profile，复用现有 descriptor-backed spool 与 gzip/tar 传输，不将新字段默认为旧格式的可选兼容字段。

归档包含三个逻辑部分：

1. 现有 `HBV6PK01` 本地完整对象包。
2. 当前实际提交根选中的共享 closure：canonical manifest 与全部原始 cipher leaves。
3. 两包共同绑定的来源与长度元数据。

共享包只包含当前根 manifest 选中的精确集合。不能把整个目录的 orphan 枚举当作闭包证明，也不能要求恢复时复活所有历史 orphan。本地 core 的内容仍由真实 Durable 备份接口生成和验证，不能为了缩小归档而自行删改 journal/ledger 条目。

### 4.1 必需的来源字段

| 字段 | 来源与用途 |
| --- | --- |
| cluster digest、实际 replay epoch | 来自当前实际 committed enrollment，不能重新从调用方字符串推断 |
| enrollment digest、实际 voter/pin 配置绑定 | 来自真实 enrollment；是归档事实，不是网络身份声明 |
| membership full LogId、enrollment full LogId | 保留 term、node、index；不只保存 index |
| 完整 commit intent 与 intent full LogId | 绑定操作、原根、目标根、闭包摘要和原 intent provenance |
| root publication full LogId、root digest、Raft root generation | 绑定导出的实际提交根 |
| migration source digest/full LogId | 保留已有真实来源；不能由归档重造 genesis |
| 本地 Durable generation | 单独记录，不能与 Raft generation 相等替代 |
| 本地包与共享包的摘要、长度、对象数量 | 绑定全部归档内容并执行边界检查 |
| 原 seal identity 与格式版本 | 保留现有同 seal 认证合同 |

以上元数据与两个包的摘要一起进入 barrier 认证的 sealed checksum。新内部 pack 可放在现有受控归档容器中，但必须有独立 magic、严格计数和长度验证；不能让旧 reader 静默接受一种新恢复语义。

从归档解析出的 provenance 始终只是数据。不得增加把这些字段反序列化成 `NativeV6PeerEnrollment`、`NativeV6PublishedRoot`、`CommittedNativeV6Read` 或 fsync quorum receipt 的构造路径。

### 4.2 导出请求的权源

导出必须由原 Service 请求持有以下对象：

- 原 Actor、原可信时钟与原操作截止；后续 Auth 状态不能延长原凭证对该请求的资格。
- 原 HaProcess Arc 实例身份及实际 opaque committed root selection。
- 原 seal 物理身份、barrier owner、activation 和目录/文件 descriptor custody。
- 本地 Durable source session、原本地 generation 与精确 root/cursor 条件。
- 实际 canonical typed graph 和精确共享 closure 选择。

建议流程：

1. 取得真实 ReadIndex 下的 native committed read，核对实际配置 pins/enrollment。
2. 完成本地当前根同步和完整 typed graph 验证，绑定本地 root、active cursor、retained V5 source 与 HA cursor。
3. 保持原 Service source session 与所有者，流式导出两包；每个对象 I/O 都受原 deadline 和实际 custody 检查。
4. 输出完毕后取得新的真实 ReadIndex，比较同一实例、根、完整 LogId、enrollment 和原选择范围。
5. 只有原权源、内容与截止仍成立时，完成认证封口并经过现有最终审计和传输完成路径。

单次 ReadIndex/witness 仍保持既有 8 秒上限。若导出跨过该 witness 的生命周期，必须取得新 witness 并严格比较原选择；不能继续使用过期 witness。15 秒原操作截止不续期，不能为备份性能不足而自动提高截止。

初始接线可仅允许 leader 上的显式候选备份路径；备用节点使用现有可信目标机制。不能把大归档装进普通 HA forwarding frame。

## 5. 当前根的归档辅助缺块修复（未实现）

这是第一块可以独立验收的恢复能力：**原 quorum 仍存在，应用根未变，只缺其外部共享密文。**

### 5.1 必需流程

1. 从实际配置所属的 ProcessRaftNode 获取 opaque current root selection；不能从归档获得这一句柄。
2. 认证归档、原 seal 和实际本地恢复所有者。
3. 比较归档与当前实际根的全部 provenance：root、intent、enrollment、membership、完整 LogId、epoch 和 canonical closure digest/count/bytes。
4. 仅对该 manifest 列出的缺失共享叶调用 checked staging。
5. 已存在但损坏或身份不符的叶继续拒绝；不能覆盖后再宣称普通恢复成功。
6. 对实际收到的每个叶完成文件持久化，验证完整闭包，并完成 canonical manifest 与目录持久化。
7. 取得新的实际同根 ReadIndex，核验原 selection；再进入现有 typed materialization、local barrier 安装、unseal/Actor 与响应边界。

现有可复用原语包括：

- [checked blob staging](../../crates/heptabao-raft-runtime/src/v6_replica_blobs_checked.rs)，`stage_received_replica_checked`。
- [canonical closure](../../crates/heptabao-raft-runtime/src/v6_closure_manifest.rs)，`persist_local_closure` 与闭包重开验证。
- [opaque committed root read](../../crates/heptabao-raft-runtime/src/process/v6_committed_root_read.rs)。
- [当前根 pull/repair](../../crates/heptabao-ha-service/src/v6_committed_root_pull.rs) 的原截止、最终 fresh same-root 校验模式。

`persist_local_closure` 的 manifest 持久化不能替代每个叶的数据 fsync。归档修复返回的本地持久化结果也不能计作一次新复制操作的多数派 ACK。

### 5.2 需要的窄接线

当前 `HaProcess::native_v6_committed_read` 会先尝试从现有 voter 修复闭包。所有共享副本缺块时，需要一个内部恢复路径先保留实际 opaque selection，按认证归档补叶，再消费该选择并返回新鲜的实际同根 read。

该路径不得成为业务读取旁路：没有完整闭包和 typed 验证时，selection 本身不允许解封、读取凭证或返回业务成功。

如果缺块已经阻止正常 unseal，归档输入必须属于显式恢复所有者或受控启动恢复流程。不能因为普通 HTTP 请求走不到快照 handler，就添加匿名上传或绕过 seal 的替代入口。恢复入口本身尚未实现、也尚未资格通过。

### 5.3 明确禁止的效果

- 不安装归档中的本地 core、replay ledger 或 HA cursor。
- 不发布新的 Raft root，不改变 epoch、membership 或 pins。
- 不把历史归档根声明为当前根。
- 不绕过实际 local barrier owner 和最终响应审计。
- 不在 root/full LogId/enrollment 已变化后沿用旧归档修复结果授予读取资格。

## 6. 历史恢复为什么不能直接复用现有 publisher

当前 native 发布、codec 和 installer 都要求同一实际 enrollment epoch：

- [publication source](../../crates/heptabao-server/src/ha_native_v6_publication.rs)，`observe_native_publication_source`。
- [cipher codec](../../crates/heptabao-server/src/ha_v6_native_codec.rs)，`binding`。
- [local installer](../../crates/heptabao-server/src/service_native_v6_ha_install.rs)，`LocalSelection::read`。
- [Raft apply](../../crates/heptabao-raft-runtime/src/v6_root_publication.rs)，`apply_native_v6_root`。

同一 Raft 文件中的 `apply_native_v6_enrollment` 在已有 native root 时拒绝重新 enrollment；现有 API 也明确说明 activation 后不能改变 enrollment。

因此，不能仅把恢复候选的 `replay_epoch` 改成 `current + 1`，然后调用现有 publisher；更不能删除同 epoch 检查来让它通过。

普通 `service_snapshot_v6.rs::commit_incoming_v6` 最终调用本地 `restore_v6_prepared_with_io_gate`，其效果包含本地备份状态替换。这不是 HA 共识发布路径，必须继续被 HA guard 拒绝。

## 7. 在线历史恢复的完整最小转换（未实现）

### 7.1 认证候选与保留当前源

导入后先复用真正的 pack 认证、`IncomingObjects` 和 typed materializer，生成不可克隆、不可序列化的内部已验证候选。完整 graph、root、owner、reader floor、容量和归档 seal 必须一致。

恢复源仍是当前真实 Service 与 Raft：原 Actor、原时钟、当前 root/full LogId/enrollment、原 HaProcess、seal/activation、本地 journal generation 与四项精确资源条件。归档中的旧凭证、旧 cursor 或旧 generation 不能替换这些源条件。

必须完整执行 [protected floor 验证](../../crates/heptabao-server/src/service_backup_restore.rs) 的 `validate_snapshot_protected_floor(current, incoming)`，包括实际 SDK epoch/retirement、时钟、namespace custody、recovery control 等规则。在该检查前不能把归档 schema 归一化成当前 writer schema，从而掩盖降级。

现有 external-provider、同 cluster、原 seal 和 raft-admin 恢复限制也应保留。不同 seal 的 force restore 不因新增 Native V6 HA profile 自动获得支持。

### 7.2 实际提交 pending epoch transition

拟议的 pending transition 必须通过真实 Raft 提交，绑定：

- 当前 root digest 与完整 publication LogId。
- 当前 enrollment 与实际非 joint membership。
- 原 epoch 和严格的 `next_epoch = current_epoch + 1`，检查溢出。
- 唯一操作身份、新 intent、新闭包摘要和该 pending transition 的完整 LogId。
- 由实际配置所有者提供、与当前 membership 一致的 pins。

这个阶段不能先改掉 active enrollment 或 active root，否则旧根会因 epoch 不匹配失去正常读取能力。应保留单独的已提交 pending 状态，并由 runtime 返回新的 opaque transition 句柄。

若当前 root 或 membership 在准备期间变化，原 transition 必须失效；不能自动改绑新源并继续同一个未知恢复写。

### 7.3 真实闭包 fsync 多数派

新 epoch 下的共享对象必须按新 AAD 重新生成。旧 epoch 的 cipher mapping 不能改标签复用；codec 现有 epoch 绑定应保留。

Receiver admission 必须从真实 applied pending transition、原 intent full LogId 和实际 enrollment/pins 得到权限。只有完成实际叶文件与目录 fsync、完整 manifest 校验后的真实 TLS final ACK 才能计票。

需要增加窄的 pending-transition admission；不能把旧 epoch 的 ACK、归档的对象数量、本地 read witness 或外部 NodeId 声明转换成新 epoch 的 quorum receipt。本机票仍须沿既定真实认证传输路径取得。

### 7.4 一次原子 root/epoch CAS

最终一次实际 Raft command 同时：

1. 验证原 active root、完整 LogId、旧 enrollment、原 epoch、实际 membership 与 exact pending transition。
2. 发布新 root，并使新的 epoch/enrollment 成为 active。
3. 消费该 pending transition，持久化其恢复 provenance。

Raft root generation 从当前 generation 向前推进，不使用归档中的旧 generation。未知返回值保留同一个 operation 与 recovery reference，禁止重发 root 或生成新 intent 来掩盖结果未知。

现有真实 V5 migration source 不能被伪造或重编号。跨 epoch 的恢复 lineage 必须记录实际旧 native root、pending transition 与新 publication 的完整 LogId，并纳入 Raft snapshot/replay 验证；不能凭备份创建一条虚构的 V5 migration publication。

### 7.5 已提交结果的本地安装

只有新的实际 committed root/epoch 才能驱动各节点本地 barrier rewrap、locator 批次和最终 root/cursor 安装。

可复用现有 per-object custody、checked rewrap、精确本地条件与批次写入，但必须处理跨 epoch 的新增状态：

- 原 `LocalSelection` 和 `NativeActiveCursor` 只接受现有同 epoch lineage，不能删除检查后沿用。
- `NativeHaCursor::covered_by` 不允许把归档 cursor 解释为合法的当前 enrollment。
- 本地 replay retirement、root、active cursor 和 HA cursor 的转换必须可冷恢复。
- 必须显式覆盖“本地 epoch 已持久化，但 root/cursor 尚未完成”的崩溃窗口，或以现有恢复事务基础提供原子 epoch/root publication。
- 保留当前 replay ledger 的正确退休关系；不能在 live 集群安装归档旧 ledger 来倒退重放保护。
- 本地持久化失败发生在 Raft CAS 之后时，结果是已提交后的恢复/fence 状态，不能返回“确定未提交”。

最终 activation、原 Actor 资格和审计仍需通过。即便导入了相同 Auth 配置，旧 pending provider/auth 结果也不能重新取得资格。

## 8. 灾备新集群的额外门槛（未实现）

原集群已失去 quorum 时，不能生成它的新鲜 ReadIndex。归档中的 term、LogId、enrollment、generation 和 cursor 只能作为来源记录，不能变成新集群的 live 许可。

灾备恢复至少需要：

1. 显式恢复所有者、认证归档和匹配的 seal/barrier 恢复材料。
2. 隔离的新目录、实际新 membership、新 TLS 身份与新的 replication key。
3. 由新集群自身的真实 Raft 提交建立恢复根，保留归档来源记录，但不复用旧活跃句柄。
4. 在接受客户端流量前隔离旧集群权源，验证旧节点、旧证书、旧 pending intent 和旧恢复句柄均不能加入或写入新集群。
5. 独立可信的恢复高水位，或明确限定的备份时点恢复语义与重新建立凭证来源的流程。

当前还有两个具体设计缺口：

- `ClusterStateCodec::native_v6_cluster_digest` 只从配置 `cluster_id` 推导，没有独立恢复 incarnation。直接改变 `cluster_id` 会影响 keyed object address 与 protected owner 绑定；保留它则需要新的 incarnation/epoch 隔离合同。两种方式都不能只改一个 JSON 字段。
- 旧归档无法证明在它之后没有发生 credential retirement、recovery-control 变化或更高 replay floor。不能仅用 `archive_epoch + 1` 声称覆盖所有灾前撤销。若没有独立可信高水位，必须如实声明恢复点与凭证重新建立的范围，不能标记完整凭证恢复资格通过。

这些新增权源不能由归档自签声明或调用方传入整数代替。需要的独立来源及其持久化方式必须在实现前确定，并通过实际重启和回滚测试。

## 9. 建议的分块实现范围

以下文件名是建议边界，除本文引用的现有文件外均未据此新增实现。

| 切片 | 建议位置 | 完成条件 |
| --- | --- | --- |
| HA archive export | 新 `service_snapshot_v6_ha.rs`、`snapshot_archive_v6_ha.rs` | 实际 opaque 来源、双对象包、严格认证封口、原请求与审计边界 |
| 当前根归档修复 | 新 `ha_native_v6_backup.rs`，复用已有 checked stage / manifest / opaque read | 只补 exact-current closure，最终 fresh same-root，不写归档 core/ledger |
| 在线历史恢复 | 专用 Service restore coordinator、Raft pending transition/apply/snapshot 验证、受限 closure admission | 实际 pending provenance、真实多数 fsync、一次原子新 root/epoch CAS |
| 本地跨 epoch 安装 | 现有 native installer 的明确 transition 分支及可恢复持久化原语 | 原本地 generation 与条件保留，所有崩溃窗口可恢复，旧 ledger 不回退 |
| 灾备新集群 | 专用恢复所有者与 incarnation/floor 合同 | 新集群实际权源、旧权源隔离、可信高水位及完整新集群冷恢复验收 |

首块可只为显式候选开启对应导出与当前根修复路径。普通 direct JSON restore、历史 native HA restore 和灾备入口继续关闭，直到各自真实验收通过。不得一次性移除现有 HA/single-node guard。

## 10. 必需的真实验收与证据

下表是待执行矩阵，不是通过记录。每次执行须绑定实际源码 tree、二进制摘要、平台/ABI、归档摘要、原操作截止和独立证据目录。测试名称中的 native、HA、backup 或 snapshot 不能替代对实际调用路径的核对。

| 验收 | 必须取得的证据 | 失败时不允许的处理 |
| --- | --- | --- |
| 真实 34 MiB Service 历史导出 | 实际 17 × 2 MiB KV2 历史，完整 typed graph、当前 opaque Raft provenance、两包摘要/长度、客户端完整收到归档 | 用随机 blob 测试代替 Service 历史，或只检查元数据 |
| 当前根全副本缺块修复 | 保留实际 Raft quorum，隔离所有目标根共享叶，从归档补回，逐叶原摘要/大小一致，根/full LogId/epoch 未变化 | 用重新加密产生的新叶冒充旧引用，或本地恢复旧 ledger |
| 本地 barrier 独立性 | 实际不同本地 barrier owner 下的 typed materialization/rewrap 与冷重开 | 手工把旧 cursor 当成当前安装权源 |
| 精确范围拒绝 | 历史根、错误 full LogId、enrollment/membership 漂移、错误 cluster/epoch、坏 manifest、缺叶、重复叶、trailing bytes 均拒绝 | 只比较 index 或 root digest 后继续 |
| 已注册坏叶 | 存在但损坏的文件拒绝并保留证据 | 覆盖坏叶并报告普通修复成功 |
| 原请求与审计 | 原 Actor 到期/撤销、seal/目录替换、操作截止、取消与最终审计失败均不能释放成功归档或业务响应 | 重新认证、续期原截止，或用新状态延长原凭证资格 |
| 在线历史恢复 | 真实 pending epoch transition、2/3 实际 TLS fsync 回执、一次 root/epoch CAS、每台读到新根 | 将本地 receipt 算 quorum，或重发未知 root |
| 历史恢复崩溃窗口 | intent 前后、最后 fsync、CAS 返回丢失、Raft snapshot/compaction、本地 epoch/root/cursor 各窗口的真实重启结果 | 吞掉结果未知，或自动初始化空 store |
| Protected floors | 实际旧归档对最新 SDK retirement、clock floor、namespace/recovery custody 的拒绝证据；原 pending auth/provider 结果被 fence | 在校验前归一化 schema，或仅证明 KV 值读回 |
| 灾备新集群 | 新集群实际选主/ReadIndex、可信恢复高水位、新身份、旧权源拒绝、原备份源不可用后的独立冷恢复 | 从归档构造原集群 live quorum 证明 |
| Mac / ROG / Pocket4 | 三台真实平台的导出、传输、恢复、重启、逐台读写与回滚证据 | 只凭 in-process / 单平台通过标记三机通过 |

34 MiB 资格必须记录原预算下各阶段耗时。原操作 15 秒与单次 native ReadIndex/closure admission 8 秒约束保持；超时、慢盘、TLS 往返或归档尺寸不足均作为真实失败保留，不能通过提高截止改成通过。

进程 SIGKILL、故障注入、实际主机重启与物理断电是不同证据范围，必须分别标明。未进行的物理断电、磁盘满或长期恢复测试不能写成已经覆盖。

## 11. 门槛关闭条件

本门槛只有在指定恢复模式完成实现、同源测试和 Mac / ROG / Pocket4 实测后，才能按该模式标记通过。归档还必须在原导出数据源不可用的条件下完成独立恢复，证明它没有暗中依赖源目录、旧进程内存或现存共享副本。

Native V6 HA 核心写入、真实 TLS 多数 fsync、AuthBus、逐台流量切换与旧资产清理有各自的验收条件。本文不改变这些条件；尤其不能把本设计文档或单机快照通过视为已完成备份迁移，从而触发旧生产备份路径清理。
