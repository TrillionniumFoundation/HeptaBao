# Native V6 HA 归档修复：候选代码与下一接线边界

## 状态

2026-10-18 内部接线更新。此切片基于 root 已恢复并冻结的 R8l，新增内部 repair helper 和三项有实际 Raft 依赖的回归代码。**两处模块声明已加入，helper 和回归已进入内部编译入口；本切片未运行 Cargo、尚无新增通过记录，Service 或 HTTP 恢复入口仍未接入。** 此切片没有修改 R8l 的三个 checked I/O 文件、任何物理 89 项验收源码、生产配置或旧资产。

R8l 原三文件已按已知 SHA-256 再检查，字节保持一致：

| 文件 | SHA-256 |
| --- | --- |
| `crates/heptabao-raft-runtime/src/v6_replica_blobs.rs` | `130f2c42acadcf2f932b053bbc0becf48c4beb250f0b03a6a04c16f871b3895e` |
| `crates/heptabao-raft-runtime/src/v6_closure_manifest.rs` | `bd7d5e29be01702131e0f395cc47f392067192dc5d8602aaa78129fa953caa40` |
| `crates/heptabao-server/src/ha_native_v6_backup.rs` | `c1ee4f697b084e1c808903bdd416cd8de31c7bb92901f35e56dfca16119b88b0` |

## 本切片实际实现了什么

新增 [ha_native_v6_archive_repair.rs](../../crates/heptabao-server/src/ha_native_v6_archive_repair.rs)，已作为现有 `ha_native_v6_runtime` 的内部子模块接入，保持对实际 `NativeV6Runtime`、`ProcessRaftNode` 和存储实例的私有访问。

入口为 `HaProcess::repair_native_v6_current_closure_from_archive`。参数只有受控输入 reader、预期 seal identity、实际归档 barrier、原 `OriginalDeadline` 及原 Service owner 回调；调用方不能提供 root、epoch、enrollment 或外部 claimed NodeId 来选择恢复目标。该方法从实际运行节点重新取得 opaque current root，验证真实配置 pins 与 enrollment，再用已有双包 factory 认证输入。

owner 回调接收该实际选择保留的 `NativeV6PeerEnrollment` 和 `NativeV6PublishedRoot` 引用。下一层 Service 必须将自己的实际本地 typed root、原 Auth 和四项资源条件精确绑定到它们，防止用落后的本地 A 授权去修复当前 B。回调中的这些数据不授予业务读取权限；本 helper 独立核验真实 ReadIndex。回调不能重新获取调用方已经持有的 HaProcess mutex。

认证完整输入之后，helper 遍历且重新验证每片归档密文，用既有 `stage_received_replica_checked` 完成实际 no-replace 文件与目录 fsync。已有坏叶保持原字节并拒绝。已有好叶经相同受控路径验证、fsync；只有缺失目标才会被建立。所有叶完成后才调用 canonical manifest 持久化，重新打开完整 manifest/closure，并强制执行一次新的实际 same-selection ReadIndex。

第一次真实 handle 是不可变的比较锚。单次 ReadIndex 的八秒生命周期到期后，可另外执行一次真实 ReadIndex，且必须通过现有 `NativeV6CommittedRootRead::same_selection`，其中包括真实 store 实例、applied generation、leader、term、完整 enrollment/root 和同一 operation deadline。此流程不会复活旧 witness，不会把归档 provenance 转为 live handle，也不会把原请求的 15 秒截止延长。调用时当前 scope 若已经收紧到另一截止，直接拒绝，避免在旧的更长界限下启动阻塞 ReadIndex。

成功结果包含现有 `CommittedNativeV6Read` 与归档数据回执。它与普通 committed read 的权限边界相同：不授予 Actor、local install 或响应交付。helper 不发布 Raft 命令、不更改 root/epoch/membership/pins、不安装归档 local pack/core/ledger/cursor，也不产生多数派 ACK。失败可能留下精确且未被交付为成功的本地不可变文件；不会返回 completed repair。

## 已加入的内部接线与待运行测试

以下两处模块声明已加入。root 应先在 Mac 完成实际 Rust 1.98 格式化，再编译和运行内部回归；Service 或 HTTP 仍无恢复调用方。

已在 `crates/heptabao-server/src/ha_native_v6_runtime.rs` 中加入：

```rust
#[path = "ha_native_v6_archive_repair.rs"]
mod archive_repair;
```

已在 `crates/heptabao-server/src/service_native_v6_ha_install_tests.rs` 中加入：

```rust
#[path = "service_native_v6_ha_archive_repair_tests.rs"]
mod archive_repair_tests;
```

新 [回归文件](../../crates/heptabao-server/src/service_native_v6_ha_archive_repair_tests.rs) 定义三项测试，均依赖现有真实三节点 Raft、实际日志/快照、本地 Durable 与独立 barrier fixture。归档 factory 调用仍是明确的 fixture，不被描述为正式 Service 导出。

| 测试名后缀 | 计划实际执行的行为 |
| --- | --- |
| `all_donors_missing_exact_bytes_and_independent_cold_owner` | 删除三个 fresh fixture voter 中目标根的全部精确共享叶；检查错误 seal、坏 footer、I/O 中取消、已有损坏叶的拒绝；从归档逐字节补回；原 Raft generation、本地 journal generation、epoch 与四项资源条件不变；再关闭本地 Service、丢失一个真实本地 barrier 对象，经现有 cold loader 从修复后的共享闭包恢复并读取真实 KV2 历史。成功路径回调实际核验原 Principal/Auth、物理 seal/activation/barrier、Durable ownership 与四项条件。 |
| `real_readindex_after_eight_seconds_keeps_original_deadline` | 在实际 archive read 中等待 8.1 秒，证明旧 witness 失效而新实际 read 仍能核验，操作截止与原值严格相等；另一单独操作的 reader 跨过其原 500 ms 截止后拒绝，零目标叶发布。 |
| `rejects_real_checkpoint_drift_and_historical_root` | 输入 read 时完成真实 Raft checkpoint，应用 generation 真实推进，即使根 digest 未变也拒绝；随后真实发布另一个 native root，旧归档以 full selection 不符拒绝，当前根和本地状态不回退。 |

待 root 串行运行：

```text
cargo test --locked --offline -p heptabao-server --lib --features experimental-native-v6-ha native_ha_archive_repair_ -- --nocapture --test-threads=1
```

此回归使用小型真实 Service 历史，覆盖 helper 的权限/持久化关系，**不补记为新的 34 MiB、物理 TLS 或三机验收**。测试文件已由 Mac 原 Rust 1.98 实际格式化并恢复到丢失前 SHA-256；本次随后只改接线状态注释。内部编译与三项测试仍待 root 实际执行，结果须另记。

## 正式 Service 导出和恢复的具体阻断

### 1. SnapshotTransferPlan 尚未保存 native HA 导出所需的全部 owner

现有 [service_snapshot_transfer.rs](../../crates/heptabao-server/src/service_snapshot_transfer.rs) 已保存原 Actor、路径、时钟锚、deadline、activation、物理 seal、HaProcess Arc、base 与单个 spool lease。现有 [service_snapshot_v6.rs](../../crates/heptabao-server/src/service_snapshot_v6.rs) 的 owner check 明确拒绝 HA；现有 [Service 路由](../../crates/heptabao-server/src/service.rs) 的 `native_snapshot_route` 也要求 `self.ha.is_none()`。

最少应新增 `service_snapshot_v6_ha.rs` 作为 transfer 模块的子模块，保留其私有请求字段；另在 native installer/read 的所有者内部新增 narrow snapshot-source capsule，复用实际 `LocalHaEnvironment`、`LocalSelection`、全 typed materializer 和原 source Auth，不能仅把旧 proof 的根 digest 拿出来。在开始导出时固定精确本地 generation 与 `state`、active cursor、retained source、HA cursor 四项条件。archive selection 是这些实际权源派生的数据；跨 I/O 和最终响应要重新核验实际当前源。

### 2. 终端时钟发布会在当前 snapshot finalizer 之后改变根

当前调用顺序是 `finalize_snapshot_transfer` → `audit_completed_response` → `persist_terminal_token_clock_with_receipt` → mandatory response audit。[service_token_precision.rs](../../crates/heptabao-server/src/service_token_precision.rs) 在存在 precise Token API state 且原请求观察推进了 floor 时，会真实发布新的 native root 和本地 generation。

因此，先导出的 A 可能在请求结束时变成 B 之前的历史备份。`TerminalClockReceipt` 只能证明那次实际时钟写，不能把 archive A 的密文/root/full LogId 改称 B，也不能被用来略过原 Actor 资格或跳过时钟持久化。正式 exporter 必须专门设计这一终端完成顺序，明确保留归档选择与终端状态关系，并在 mandatory audit 后再核验其原交付 owner。不能无差别复用 NativeAuth 的 checkpoint 前进逻辑来赋予 archive B 身份。

### 3. 全副本缺块会让普通请求在新恢复 handler 之前失败

当前 `HaProcess::native_v6_committed_read` 先做真实 peer pull。所有共享副本缺块时，普通 HA 同步不能到达可用的 snapshot handler。可闭合的 warm recovery admission 必须专门取得真实 raw current selection，确认本地已认证的完整 typed graph、原 Auth 与四条件属于**同一当前根**，再受控调用此 helper；这不是普通业务读取旁路。

如果缺块已经阻止正常 unseal，则必须增加显式恢复 owner 或受控启动恢复合同。现有 `native_snapshot_destination` 在 sealed 状态直接拒绝。不能添加匿名 upload，不能从静态 archive root 或旧本地 Auth 构造新当前权限。新的 helper 没有解决或开放这个入口。

### 4. 严格当前根 repair 不能代替历史恢复或灾备

一次正常后续写入、一次终端时钟 native publication，都会让此前完整归档成为历史根；这不是 archive codec 错误。真正可恢复的正式备份必须实现历史恢复的实际 pending epoch transition、真实新 epoch 密文多数 fsync、一次原子 root/epoch CAS 以及可冷恢复的本地 epoch/root/cursor 安装。

现有 `apply_native_v6_enrollment` 在已有 native root 后禁止重新 enrollment；publisher、codec、Raft apply 和 installer 都验证原 epoch。现有 [service_ha_restore.rs](../../crates/heptabao-server/src/service_ha_restore.rs) 明确只接受 record-v5 roots。不能改候选 JSON 中的 epoch 或删除这些 guard。原 quorum 丢失的灾备还缺独立恢复 incarnation、旧权源隔离与可信 protected high-watermark 来源。

完整设计及 protected floor 要求继续以 [Native V6 HA Backup Next Gate](HEPTABAO_NATIVE_V6_HA_BACKUP_NEXT_GATE.md) 为准。新增此 helper 后仍不能触发生产流量切换、备份迁移完成标记或旧 OpenBao 清理。

## 初始正式切片的文件分工

| 所有者 | 最少涉及文件 | 具体完成条件 |
| --- | --- | --- |
| 当前根 repair 原语 | 两份本次新增 Rust 文件；runtime 与 installer-tests 两处 module 声明 | 三项实际本地测试通过，再做真实 34 MiB 和三机测试；始终不发 Raft 写、不装旧 core |
| Service export owner | 新 `service_snapshot_v6_ha.rs`；新 installer-owned snapshot-source helper；`service_snapshot_transfer.rs` | 原 Actor/source Auth/clock + local generation/四条件 + 实际新鲜同根 ReadIndex，明确终端时钟关系和审计后交付检查 |
| 有界归档传输 | `snapshot_archive.rs` 的独立 `V6Ha` profile；必要时独立 bounded envelope helper | 明确 `HBV6HA01`，保持现有入口容量限制；不能把 codec 的合成上限直接扩成 HTTP/spool 上限，也不能误送入单机 V6 local restore |
| 受控恢复 admission | 新 Service warm-repair coordinator；以后另行设计 sealed recovery owner | 认证前后的实际根关系可核验；不存在从落后 Auth 或 archive provenance 获得 live 权限的路径 |
| 在线历史恢复 | 专用 Service restore coordinator、Raft transition/apply/snapshot、receiver admission、本地 epoch 安装 | 原 protected floors 不回退；严格新 epoch、多数真实 fsync、一次 CAS 和全部崩溃窗口验收 |

这些属于不同验收范围。内部 helper 接线可以单独冻结测试；HTTP 开放、全量迁移和旧资产清理必须继续由各自完整证据决定。
