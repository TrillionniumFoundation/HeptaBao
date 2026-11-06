# R49 — 正式 release 已越过旧阻断，测试编译修补后继 4a49405b 继续验证

证据截止：2026-11-06 23:21:45 UTC。任务继续执行；本节点记录实际结果、失败原因和已创建的后继候选。

## 当前结论

全量替代 OpenBao 2.7.1、生产切流、全部客户端及备份迁移、旧版清理均为 **false**，正式客户端切换数为 **0**。还没有足够证据宣布替代完成。截止时 A/B/C/root 的 Native process/call/future 均已释放为零；原 job、闭合记录及最多两条 Native 通道约束见 [STATE.public.json](STATE.public.json)；发布证据不会重发任何原执行。

最新候选是 [4a49405b93c45ab1c25ecba11cde63a7ede20dce](https://github.com/TrillionniumFoundation/HeptaBao/commit/4a49405b93c45ab1c25ecba11cde63a7ede20dce)，树为 f02dd113d208d79f5275005dc65a5e8aecd0e9d3，父提交为 5767739cd25e458ac052dc8d384019bab8688ae0。实际 commit、父链、branch 和完整递归树均已读取核对；3,932 叶合计 62,553,956 字节，索引 SHA256 为 7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d。只修改三个测试文件，另外 3,929 叶与父提交相同。新候选尚未获得实际编译或运行资格。[冻结候选及原始读取](../candidate4a-qualified6/)

## ROG 的实际构建结果与最小修补

父候选 576 的原 job rog/1a1b2d90976-fc05-7fff 正式 release 成功，耗时约 957.48 秒，生成了当前次构建的 server 与 seed。这一结果实际越过了上一轮九个 Service 锁调用和相关 E0277 的 release 编译阻断。随后 ordinary no-default check 与 file libtest 编译成功，但 default libtest 编译以 **101** 退出，未超时。四个直接子进程均已回收；运行测试没有开始，HA libtest 编译也没有到达。后续 stdout 383,786 字节和 stderr 2,146 字节均已完整读回，七个固定版本范围全部闭合。stdout 442 行为 396 条 compiler-artifact、45 条 build-script-executed 和一条 success=false，没有 compiler-message；诊断位于 stderr。[完整原构建链](../rog576-build-original223/)、[完整报告读取](../rog576-build-body-original59/)

完整 stderr 的 2,146 字节给出两条 E0063 和两条 E0658：两处 HaProcess 测试夹具遗漏 feature-gated snapshot_forward_handler 与 snapshot_server_pins；两处 ExactSizeIterator 使用了当前稳定工具链不可用的 is_empty。后继候选为夹具填入 None callback 与空 BTreeMap，并把两处空迭代器断言改为 len() == 0。原有断言含义、时间限制、feature、依赖和生产实现均保持。

独立审查与 root 的 30 项重放检查已经核对严格正反差分、原候选叶、全部测试函数及真实字段类型。根源码还确认：这些夹具仍没有 native runtime 或监听器；空 callback 和空 server pin 不会开启 snapshot 转发。原始失败保留在 [最小修补 SOURCE](../default-libtest-four-error-fix-source17/)，独立结果见 [peer review](../default-libtest-fix-peer-review7/)。

下一轮先执行 lib-only、test profile 的 Cargo check，并核验实际 Cargo JSON 的 target、features、profile.test 和成功终态。该检查与正式 release 共用原有 **1,800 秒绝对阶段截止**，检查自身最多 300 秒；后续共享编译 3,600 秒、总计 12,000 秒、原清理预算保持。检查只做测试代码类型检查，不能替代正式链接和运行测试。该控制器仍需冻结并实跑。

Linux 的原 **252 个唯一测试、280 个配置实例、18 组**计划没有删减：file28/default235/HA17。父候选 release 成功不计作 4a 的构建资格，源码审查也不计作测试通过。

## Mac 外接盘、X230 和真实 LAN

Mac 576 已在 T5 UUID FB804D1B-24CB-4D6E-AEA7-A9E180807758 上完成独立源码暂存：完整内容及模式、索引、Git fsck、父链和历史数量通过，原 02b 目录未改，没有 Git alternates 或共享对象硬链接，31 个直接子进程全部成功回收。该次只暂存源码，没有启动编译器或服务。原 stage、INFO 和 BODY 三条证据链已分别按 124、46、58 项检查重放。[Mac 完整原链](../mac576-stage-original54/)、[最终报告读取](../mac576-stage-body-original36/)

4a 的后继模板以实际 Mac 576 为只读 base，只有 18 处数据替换、四个差分 hunks；20 个完整函数和 finally 保持原字节。root 的 27 项检查已复现。新 576→4a bundle 必须来自实际生产和固定版本完整运输，不能用旧 02b→576 bundle 代替。[后继 stage SOURCE](../mac4a-stage-template-source11/)

Mac normal 仍是 **89 个唯一测试、117 次配置执行**，保留原 61 次并加入明确的 default28/file28 组；formal34 仍是 17×2 MiB 和 31 项迁移、恢复检查。X230 的两次 bundle 导入机制已通过 45 项源码重放及额外绑定检查，但新版本的实际源码落盘、Linux 二进制、正式 34MiB 和备份恢复均未获得资格。模板、旧版结果或 source stage 都不能代替真实存储测试。

历史 4e808 的 Mac/X230 formal34 各 31 项、Mac/ROG normal 各 61 项、LAN98 与 12 项独立冷重启仍作为历史保留。后继必须重新完成 Mac、ROG、Pocket4 真实断主、重新选主、quorum 拒绝、ReadIndex、持久化和重启。六条路由身份已经核验；现有端口曾观察为空闲，不表示预留。

## AuthBus：已缩小 Node 故障范围，尚未建立业务资格

固定崩溃读取已得到公开的 dyld/ignition 符号栈；实际 termination namespace 为 <0x23>。公开源码中的 LIBIGNITION 数值对应并没有解释 termination code 2，29 个固定诊断槽也没有给出原因。此前两秒固定日志读取未获得符合闭集的事件，不能解释成没有日志或没有拒绝。

一次受限与基线对照使用同一 Node 25.9.0、相同环境和全新空目录：受限 Node --version 以 SIGABRT 退出，基线返回 v25.9.0。随后只增加三处公开系统/Cellar 路径的 file-map-executable 许可再次对照，受限仍为 **-6**，基线仍为 **0**。后一原 job 的两个子进程及 14 个应用 FD 全部关闭，root 已重放 359 项原链检查。这个特定许可增加不足以修复故障；没有因此放开生产沙箱。[实际映射许可对照](../auth-node-mapping-original75/)

固定 /usr/bin/log help stream 读取已正常闭合，帮助子命令以 64 从 stderr 返回完整 1,684 字节使用说明；四个 FD 和子进程已回收。现场确认 stream 使用 --level 和 --style ndjson 等参数，后续将据此准备有界实时观测。未来观测仍应只关联新公共 Node 的已知 PID、测得的时间窗及允许的公开字段，保留原隔离边界，不改系统日志隐私或安全设置。实际日志结果不预先假定；启动日志进程也不等于已确认订阅就绪。

J3160 没有被用作凭证来源。新可信 issuer、实际 SDK AppRole/TLS/KV/Policy、续期及撤销仍未获资格；本轮公共 Node 对照没有调用 SDK 或读取业务凭证。旧私有流程的未知进度保持未知。

## 逐台迁移和清理门槛

已登记的有限客户端与备份范围继续用于执行规划，原登记完整保留于 [FINITE-MIGRATION-REGISTRATION.original.json](FINITE-MIGRATION-REGISTRATION.original.json)。不凭空追加无限手工路径扫描；若出现新的实际消费者或恢复路径，则纳入登记。

每台机器必须用新可信凭证完成真实读写、重启、回滚及登记备份的恢复验证，才切换该台流量。ROG enabled=false、Pocket 的既有停止约束及其他登记设置保持。客户端 eligible 字段仍限 address、caFile、roleIdFile、secretIdFile。当前切换数为零。

全部已登记客户端及备份完成迁移后，才删除旧 OpenBao、旧 HeptaBao 服务、二进制和可再生中间资产，只保留最新且已验证的 HeptaBao 服务。当前没有执行清理。

已记录的远程认证、非根 namespace、Database/Kubernetes/RabbitMQ、ACME/EAB、插件、seal/root/rekey 等能力缺口仍在 [STATE.public.json](STATE.public.json) 中保留。所选回归通过不能自行证明 OpenBao 2.7.1 全功能等价。

## 可复核证据

本节点包含 **91 个挂载包、1,825 叶、26,529,886 字节**，均已按完整字节、Git blob、SHA256 及树结构核对。[MOUNT-INDEX.public.json](MOUNT-INDEX.public.json) 列出每个叶的身份与 root 核验说明。纯检查器的准备错误、原 Git 不确定状态及仅恢复同一原始返回的处理都保留，不将未知执行重新派发。上一发布为 e07d835dcb201221c8e5f87194de7aae129967ee；本节点之后继续推进实际构建与迁移门槛。
