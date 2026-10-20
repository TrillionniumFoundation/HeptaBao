# HeptaBao R12 实机证据：KV2 迁移恢复通过，HA 仍受阻

候选为 `dd82a68baac4386ede8b9ced4e89492024c19145`，tree `72a180244162a19930d7e4be7426f168d34b653c`，完整 3,552 文件。Manifest SHA256 为 `6dc01ef55ad9ab7206d7c756c6d36856ec4d3427ed9ce4720c5b8675c8a72c84`。

**本证据不证明全量替代 OpenBao 2.7.1。没有生产切流，没有删除旧服务或二进制。** 新增报告不改变已测试的候选源码身份。所有原始回执、来源路径与 SHA256 见 [INDEX.json](INDEX.json)。

## 已实际完成的范围

| 门槛 | 平台 | 结果 | 原始证据 |
|---|---|---|---|
| 原生恢复测试 | Mac | 原 18 组 / 58 项通过，完整源码前后不变 | [mac-native58.json](mac-native58.json) |
| 原生恢复测试 | Main GNU/Linux | 原 18 组 / 58 项通过，完整源码前后不变 | [main-native58-r2.json](main-native58-r2.json) |
| 原测试程序在目标机执行 | X230 GNU/Linux | 18 组 / 58 项、36 条 list/run 命令通过；实际服务 TLS/ABI 探测及 owned 清理通过 | [x230-native58.json](x230-native58.json) |
| HA 同根读取、恢复及原相关门槛 | Mac | 原 focused20 的 20 项、40 条命令通过 | [mac-focused20.json](mac-focused20.json) |
| OpenBao 2.7.1 → native KV2 全量 34MiB 流程 | Mac | 原 31/31 项通过 | [mac-official271-full34.json](mac-official271-full34.json) |
| 同一 34MiB 流程 | X230 | 原 31/31 项通过 | [x230-official271-full34.json](x230-official271-full34.json) |
| Mac、ROG、Pocket4 真实局域网 HA | 三台物理机 | **失败：53/98 通过，54 项有结果** | [lan98-r2-summary.json](lan98-r2-summary.json) |

34MiB 流程保持原 17 × 2MiB 历史数据、实际官方 2.7.1 oracle、迁移、冷启动、快照恢复、历史读取、软删除/恢复、销毁、CAS 拒绝与清理。原 HTTP 15 秒、迁移 360 秒未改。它的通过不代表 HA、所有 credential provider、所有 OpenBao 功能或生产客户端迁移通过。

X230 执行的是 Main 实际构建并逐文件封存、转运、重新校验的原测试程序。X230 没有冒称本机编译；原 capsule、producer summary、实际依赖、完整 R12 源码、最终服务探测和所有 owned 子进程清理均由目标机执行器验证。

Mac/Main 原 58 项保持原 target、Cargo home、默认 debug、jobs 2/8、locked/offline、每命令 1,800 秒。Main 首次因离线缓存缺失失败，保留原失败和两个缓存修复回执；第二次仅补充 Cargo.lock SHA 匹配的现有缓存包后完整通过，没有更换依赖或放宽测试。

## 真实 HA 剩余 blocker

第二轮使用原 98 项脚本、相同候选的实际原生二进制和三个全新 owned fixture root。第 13、14 次 2MiB 写入实际返回 200。第 15 次写入（请求版本 17）在 14,132.356 ms 后返回 503，后续断主、重新选主、ReadIndex 故障、冷重启及缺密文重建门槛没有执行完成。

原阶段日志显示这次 publication 和 local install 都已完成，交付前剩余预算只有 28,710 µs，最终 HA sync 用时 31,654 µs，触发原期限及审计序号 111 的交付拒绝。日志足以定位累计耗时；不据此将客户端 503 改写为成功，也不把所有并发 Raft transport timeout 都归入该请求。

失败写入**没有重放**。原 mutation intent/outcome 与私有 fixture 状态保留在原主机；27 个 mutation 均有 HTTP 结果只说明 transport 已知，不能推导写入未提交。三台 owned 服务和 mesh 已清理。没有停止生产 gateway、生产 HeptaTrader/PAPER 或旧 OpenBao。

诊断材料为原日志的明确筛选副本，带完整原日志 SHA、字节数和行号：

- [阶段日志](lan98-r2-delivery-phases.json)
- [失败窗口](lan98-r2-delivery-window.json)
- [审计尾部元数据](lan98-r2-audit-tail.json)，不冒称已独立认证完整审计链。

## 执行层异常及核对

首轮 HA 被错误的 30 秒外层任务期限打断。当时仅完成三个 build receipt 与两个清理检查，初始化尚未发生，mutation 数为零。该失败保留在 [原总结](lan98-r1-controller-interrupted-summary.json)。第二轮使用全新目录，原每项期限不变。

X230 首个包装器在进入测试前因参数索引断言退出；修正后的 SSH 包装器又被 30 秒外层期限截断。只读核对发现原 X230 executor 仍以同一 PID/start ticks 运行，因此没有重跑。最终同一 run 完成 58/58、服务探测和全部清理。所有经过及实际 job identity 见 [execution-reconciliation.json](execution-reconciliation.json)。

## 后续资格

AuthBus 的真实 credential chain、各主机真实客户端重启/回滚、全部备份与客户端迁移、未闭合的 2.7.1 兼容性门槛和原 HA 98 项仍需要独立证据。下一候选的测试或修复不会继承本候选的通过结论。
