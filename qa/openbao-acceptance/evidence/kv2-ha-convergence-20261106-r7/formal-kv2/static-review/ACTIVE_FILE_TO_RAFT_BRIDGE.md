# 已写入的普通 V6 文件实例到新 Raft 集群：静态桥审查

## 核心判断

在产品提交 `9c68b95b152a468ab378b68730e9e3f04e6a7100` 中，存在一条**完整当前 KV2 逻辑历史**转移路径：

普通活动 `native_v6_file` 的 `GET /v1/sys/migration/openbao/kv2/export?mount=<mount>` → 私有完整 lossless bundle → 新集群 pristine KV2 mount 的 native-large import。

当前 `heptabao-seed recover-ha` **不支持普通 HBV6PK01 归档**。它只接受已有 HA 归档，不应伪造 HA 元数据或用旧 preactivation seed 冒充当前恢复。逻辑桥保留被导出 mount 的 KV2 数据和元数据，**不迁移整个 Service 的 root token、AppRole、policy、lease、其他 engine、原 mount incarnation 或 Raft 权威**。

这是源码结论，未启动 HA 或执行迁移。实际 Mac/ROG/Pocket4 当前数据全链仍需单独运行并保全原件。

## 1. 为什么 seed export / recover-ha 不是当前普通状态的捷径

`service_native_seed.rs:25,516–533` 只允许 `state.hbs`、`journal.hbj`、`ledger.hbl`、`seal.json` 四文件。额外 native objects 会被拒绝，导出不是完整活动 V6 的备份通道。

`service_native_cold_seed.rs:490–519` 在真实解封和归档解析后，明确要求 `metadata.is_v6_ha()`、matching seal，之后才调用 `validate_cold_native_v6_archive`。`ha_native_v6_backup_format.rs:5,96–98` 要求 `HBV6HA01`；`ha_native_v6_backup_cold.rs:115–175` 要求 `HBV6HAP1` 与实际 membership、enrollment、migration、intent、publication 的内在关系。这些都是已有 HA 事实，普通 File 包不能补造。

`recover_ha_seed` 的输出仍只是认证过的 migration bootstrap，代码注释 `service_native_cold_seed.rs:404–409` 明确要求新实际 cohort 之后恢复完整归档。即使输入是合法 HA 备份，也不能把生成的 seed 当成完整当前业务数据。

## 2. 普通活动 File 的现行导出

入口与权限：[service_snapshot_lossless_export.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/9c68b95b152a468ab378b68730e9e3f04e6a7100/crates/heptabao-server/src/service_snapshot_lossless_export.rs#L137-L284)。

- 第 16–37 行只接受 unwrapped root namespace 的 GET/HEAD，恰好一个 mount query。
- 第 137–176 行要求实际 root principal、typed HTTP transport、原 token clock、sudo/read 权限及已激活 paged V6 reader2。
- 第 179–284 行对普通 File 从真实冷 root 读取；每份 descriptor/object、payload、原 owner、原 deadline 均受检查，完成后再做闭合语法验证。
- 第 43–134 行在 mandatory audit 后重新验证原 actor/root/effect generation。只允许本次终结时钟的精确推进，外部改变不能替代原来源。
- `engine_native_kv2_lossless_export.rs:24–57,63–112` 选择实际 root namespace 的 canonical mount，绑定其真实 incarnation 和 KV2 graph。

### 完整保留项

`engines/kv2_native_lossless_export.rs:137–154,258–424` 逐项输出：

- mount 的 max_versions、data CAS、metadata CAS、delete_version_after；
- 全部 key/path 的 created/updated time（含精度）、current_version、oldest_version、current_metadata_version、每 key 配置、custom_metadata；
- 每个 retained version 的 created_time、deletion_time、destroyed、source_deletion_time；
- 软删除但未 destroy 的真实 payload 仍解密并完整导出；destroyed 版本必须没有 descriptor/data，输出 null；
- 数据使用现行 lossless JSON 表达，完整 descriptor、全部 scoped ObjectRef 与 aggregate keyed digest 在本次读取中验证。

这里的 `openbao270-kv2-lossless-v1` 是已有传输 schema 的名字，**不是 OpenBao 来源证明**。从 HeptaBao 当前 File 导出的包必须记录真实 HeptaBao 来源，不能标成旧 OpenBao 生产历史。

### 不能忽略的上限

- 每 bundle 最多 64 MiB，单 payload record 最多 4 MiB：`kv_lossless_native_large.rs:10–17`。
- NativeLarge 最多 50000 paths，`1 + paths + versions <= 100000`；每 key retained versions 最多 10000：`kv_lossless.rs:23–36` 与 `kv.rs:25`。
- `kv2_native_lossless_export.rs:27–47` 遇到 sparse retained history 明确 409。不能补造缺失版本或声称 export 成功。
- 输出语法也使用相同导入 profile 检查，不会默许不能重新导入的包。

新普通正式实例应在准入和最终转移时实际证明当前各 mount 可导出，并保留后续增长边界。源码不支持“任意大、任意稀疏历史都可无损移入 HA”的无限主张。

## 3. 新集群导入的实际产品入口

`crates/heptabao-server/src/bin/heptabao-seed.rs:22–43` 暴露：

```text
heptabao-seed import-kv2-ha \
  /absolute/new-server.json /absolute/new-ha.json \
  /absolute/target-private-shares.json /absolute/target-private-root-token \
  /absolute/current-file-export.bundle <canonical-mount> <private-bundle-sha256> 360
```

以上是命令形状，不包含凭据值，也不是本审查实际执行的命令。默认 300 秒、最大 360 秒为该维护操作已有独立预算，不能改变 HTTP 请求或 HA 测试时限。

`service_native_seed_ha_import.rs` 的职责与前置条件：

1. 164–214：必须是普通 `native_v6_raft` 配置，与 HA enrollment/路径匹配；不会默默丢弃 mandatory audit collector，输入不允许藏在 data/raft 目录内。
2. 225–246：启动当前节点真实 HaProcess/Service，获取真实文件与 Raft writer fences。该节点不得同时有另一个 server 占用；其他 voters 须已在隔离新 cohort 运行。工具不创建 seed、mount、membership 或 root principal，也不创建 HTTP listener。
3. 300–351：在原 READINESS 界限内证明当前节点是真 leader、committed 非 joint membership、同 term、majority fresh/matched、applied 达到 committed。不能由 operator 自写 proof 代替。
4. 529–627：持有并逐次复核普通配置、peer TLS/key、bundle、target Shamir shares 与 target root token 的实际 private file identities；核真实 root principal。
5. 628–669：必要时执行正式 V6 激活，然后调用**同一个现行 native-large writer 一次**；原输入 consumption/hash/owner 在 finish 前再次检查。
6. 678–803：ack 后任何异常变为 outcome unknown，不重放。成功需真实 quorum selection、完整 graph、关闭 writer、raw durable cold reopen、再建真实 owner、cold ReadIndex、实际 Shamir unseal、相同 root/generation/epoch 与完整 graph，最后所有原 peer workers 收尾。

目标必须是新建但未改配置/未写数据的 pristine mount。`engines/kv2_native_import.rs:118–155` 检查 paged graph/scope 与 pristine；`kv_lossless.rs:518–525` 还要求 entries 空、未导入过、max_versions=0、CAS flags=false、delete_version_after=0。**不要提前写 canary 或调 KV2 config 使它变成非 pristine。** 原 source config 将随 bundle 导入。

`engine_kv2_native_import.rs:83–136` 在目标实际 mount scope/incarnation 下重新构图，保留逻辑数据但生成目标地址。`kv_lossless.rs:392–515` 不采新时钟，恢复精确时间、版本、metadata CAS、删除状态和 payload；不将源物理 root digest 等同于目标 digest。

## 4. 最小正确顺序

1. **先完成普通 KV2 阶段**：普通真实当前数据的写入、读回、冷启、完整 native archive 与 fresh-directory 恢复都保留。preactivation seed 从始至终仅标为引导。
2. **冻结迁移边界**：最终切换前对该普通实例的业务 writer 建立真实 fence。多 mount 需要共同的来源边界；单次导出的一致读取不等于跨 mount 原子快照，也不保证导出后无人继续写入。
3. **导出当前历史**：各 mount 经上述当前 export 保存到 create-only private 文件，保留源 mount 映射与全部实际版本清单。使用 bounded typed binary download；普通 JSON helper 的小响应上限不能拿来接 64 MiB。`native_v6_ha_official_history_wire.py:105–129` 有 64 MiB、明确 media type、Content-Length、独占0600文件及 fsync 的现成模式，但硬编码 oracle271 需要在新控制器中按允许映射收窄泛化。
4. **新 cohort 引导**：另行初始化真实 Shamir 的空普通 seed，创建目标空 KV2 mount，停止后导出/stage 四文件到 Mac/ROG/Pocket4 的全新目录；或者用已保存、能够提供相同必要基础的旧 seed，但只作为 bootstrap。不得认为其中旧数据代表当前代际。新 cluster、peer mTLS、replication key/enrollment 均实际建立。
5. **导入当前包**：各目标 mount 必须 pristine。可经正常 native-large HTTP writer，或已有 `import-kv2-ha` 维护入口；保持各自原 deadline，单次执行，未知结果只读核当前 quorum/cold storage。导入工具要求其节点实际成为 leader，不能跳过其原 leader 准入。
6. **逐节点完整核验**：读全部 metadata/版本状态；用目标 HA 的 committed lossless export 与源 bundle 作精确 lossless 比较，验证软删 payload/destroyed null、CAS counters/配置。File-only `sys/internal/storage/kv2-version-witness` 对 HA 是 501，不能当成漏掉 HA 验证的理由；HA export 另受真实 committed-read proof（`service_native_v6_ha_lossless_export.rs:7–105`）。
7. **再做物理 HA 验收**：断主、选主、ReadIndex、持久提交、全冷启、故障恢复和新 HA archive 的完整恢复必须在真实三机执行。通过之前不切实际消费者，不删除 File 实例或任何旧资产。
8. **AuthBus 以后单独迁移**：逻辑 bundle 不含 auth/policy/lease 等状态。通过 KV2→HA 后，重建并验证目标可信凭据、AppRole/TLS/policy/renew/revoke/SDK，再逐机切流。此顺序与用户要求一致。

## 5. 已有测试和控制器能证明到哪一步

- `service_snapshot_lossless_export_tests.rs::lossless_export_default_file_exact_history_cold_reopen_and_restore_cas`，172–245：普通 File 导出、冷启、另一 pristine mount 导入、再次导出一致和 CAS 后续版本。
- `engines/kv2_native_lossless_export_tests.rs`：相同 authenticated root 往返、34 MiB streamed/reimportable、sparse 明确拒绝、原 limits、source schedule 保存等定义。
- `service_native_seed_ha_import_tests.rs::maintenance_ha_import_real_quorum_writer_and_cold_readindex_preserve_history`，404–435：真实 quorum writer、cold ReadIndex/graph，并明确 physical_failover/full_replacement=false。
- `native_v6_ha_official_history_live.py` 是现有 physical harness 扩展，但输入固定为已有 **synthetic OpenBao full34**（66–145），不是当前业务 File 导出。不能拿其名称当成已经完成 File-current→三机业务迁移。其目标 committed export 对照（365–379）和一次 import ledger（381–408）可复用。

上述只是可复用实现与测试定义的查证。本包不声称本轮运行了这些测试，也不声称实际三机迁移已通过。

## 6. 新增工作的最小边界

产品已有有界逻辑桥；目前缺的是面向真实当前来源、精确 mount 清单、write fence、private credential-safe evidence 和实际三机执行的操作控制器。普通 archive→HA 物理转换确实未实现。超出导出 profile、稀疏历史或需要整个 auth/lease owner 原样迁移的业务属于真实未解决缺口，不能通过换标签、拆坏 metadata 或重置历史消除。

生产数据 bundle SHA、payload/metadata digest 可能是凭据指纹；产品维护 receipt 的 bundle hash 必须在私有原件中保全，公开投影仅给计数、精确一致布尔、预算/custody和代码/二进制 pin。不要沿用 synthetic harness 的公开 payload 哈希习惯。
