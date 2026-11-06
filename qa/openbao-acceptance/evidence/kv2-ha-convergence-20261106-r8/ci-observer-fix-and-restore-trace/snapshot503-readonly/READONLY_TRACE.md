# CI 42260689756：历史 snapshot 恢复 503 的只读定位

当前结论：这次完整 merge CI 确实失败在历史 snapshot 恢复 POST 的 HTTP 200 断言。原始错误是 `root_attempted=false` 的 `HaError::OutcomeUnknown`；现有原件不足以确定内部失败原因，不能据此改状态预期、延长预算或自动重放。

## 已观测的范围

- merge 作业 128048873935：server libtest 3751 通过、1 失败、8 ignored；head 作业 128048874677 的同一测试通过。两者源码 tree 相同（7f4b75930e8491a3110d8c7f8f894cfc0cfc1fdb）。head 仍因后续 Clippy items_after_test_module 失败。
- 原串行日志窗口给出同一 snapshot_test：HTTP503，elapsed_us=2107497，entry_remaining_ns=14999999910，exit_remaining_ns=12892502113，phases=[]，bucket_bound_reached=false。原 15 秒请求截止没有耗尽；这只否定整个请求已超时，不能排除某个更短的内部边界。
- 按固定测试的顺序控制流，先前大于 34 MiB 的导入204、历史校验、snapshot GET200、CAS19 后续变更200均已越过。失败发生在恢复这份 archive 的 POST。两个 history404 是软删/销毁版本的预期校验，不是 fatal。
- 后面的显式断主、继任选主、cold rejoin、恢复后 undelete/完整历史检查没有执行。测试析构清理不能替代这些步骤。

## 源码错误链与证据限度

`service_native_kv2_large_ha_tests.rs` 的 snapshot helper 保持单一 15 秒截止：实际 admission → external snapshot transfer → original finalizer → HTTP200 assertion。`service_snapshot_v6_ha_restore.rs` 将 `publish_native_v6_historical_restore` 的错误转为503，并原样保留 root_attempted 与 retry_allowed=false。

精确的无前缀错误文本 `HA durable outcome is unknown` 来自 `heptabao_ha_service::HaError::OutcomeUnknown`。逐一对照同一固定源码的 Archive/Codec/ReplicatedState/LocalBlob/RaftRuntime/RemoteRaft 错误显示后，历史发布协调器中能够直接传播该 HaError 的两处是 closure fsync quorum collection（614–626）以及 Root 前 quorum verification（642–647）。这使可定位的控制流范围更窄，但原日志仍无法选择其中一处，也没有独立保存这次 Begin/Stage 的持久收据；不能把源码推导当作实际磁盘/复制状态复验。

closure collector 将初始 admission、本地 ciphertext 读取、peer 交换失败后票不足、最终 admission/verify 等归并为同一个 OutcomeUnknown；exchange_reply 也丢弃了 transport 内因。Root 前的最后 quorum.verify_for_publication 同样归并原见证验证失败。原响应没有保留这些分支的区分。

`root_attempted=false` 的含义限定为该协调器尚未调用此次 Root CAS。源码明确警告：Begin/Stage 即使在 Root 之前也可能已提交。因此既不能声称无任何持久副作用，也不能将未知结果当作安全重试资格。

## 为何 phases 为空不能解释为未进入发布

现有 EpochRestorePhaseTimer 及其所有 historical_epoch_* 调用只在 private-ha-forward-diagnostic feature 下编译；它没有接入正常测试的 NativeV6TimingSpan。原 CI 命令是 `cargo +1.98.0 test --locked --workspace --all-targets --no-fail-fast -- --test-threads=1`，没有启用这个私有 feature。haservice 的内部诊断在该依赖构建中也不能由 server 的 cfg(test) 自动启用。故这个空数组确实是内部观测缺口，不能倒推为零工作、零提交或某一特定根因。

本次只读取固定源和已完成 CI 原件。没有增加诊断代码、修改产品、运行单项/全量测试、重跑 CI、改预算或放宽断言。下一步如何补足内部原因证据应在这个明确边界上决定。
