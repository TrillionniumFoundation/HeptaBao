# R50：4a 源码落盘、AuthBus 启动修复与原始结果恢复

这是持续推进的证据检查点，时间截面为 2026-11-07 01:15:46 UTC。当前仍不能证明 HeptaBao 已全量替代 OpenBao 2.7.1；正式切流为 0 台，旧版清理未执行。工作继续，检查点发布不代表验收结束。

## 本轮已证实的进展

| 范围 | 当前实际证据 | 尚未得到的资格 |
| --- | --- | --- |
| ROG 4a 源码 | 独立完整报告证明 3932 个文件、62,553,956 字节、3770 条提交历史及完整索引一致 | 当前 4a 构建与 252/280 运行测试 |
| Mac 4a 源码 | 原任务实际 exit 0，完整持久输出，7 次原调用及 2 个观察器闭合；摘要为 prepared、目标 commit/tree 正确 | 完整落盘报告正文、正常 89/117 测试和 34MiB 回归 |
| Mac/X230 增量包 | Mac 1253 字节、X230 6815 字节的原二进制内容及完整哈希已独立核验；分别绑定 576→4a、02b→4a | X230 最终实际落盘及当前二进制运行 |
| AuthBus 启动环境 | 添加 33 字节的根目录 literal 读取规则后，Node 版本验证成功；24 个启动标记完整，9 个内置模块和 2 个固定 CAS 辅助模块导入成功 | 实际 SDK、可信凭证、AppRole/TLS/KV/Policy/续期/撤销 |
| 固定 ps 权限修复 | 73 项主审、27 项实际绑定检查和 17 项独立窄审；仅固定 setuid /bin/ps 的同一 primary 身份允许预期 euid 0 | 真实运行；旧 PID 的历史管理关系仍未知 |
| 官方 PKI12 | OpenBao 2.7.1 对照程序已实际闭合并生成固定报告；INFO 已核验 | 完整报告正文的 12 项语义及与当前 HeptaBao 的对照 |

源码正确、任务成功退出、完整报告读取和业务资格是不同证据层。表中未得到的资格没有从旧版本结果或源码检查中继承。

## ROG 构建启动仍未取得回执

原请求的原始 SDK 是超时错误，没有可证明的任务 ID。私有任务列表的第一次读取失败，第二次只得到一行不含 idempotency key 或 digest 的身份元数据，且未遍历完成；它不能证明目标任务是否存在。

随后对固定结果路径只做了一次 file_info。该原操作实际 failed/inactive，原失败载荷经一次 immutable 页取回，明确报 FileNotFoundError errno 2：当时 hb-4a49405b-controls-20261106-r1 目录不存在。这只证明该次路径观察，不能据此断言原 START 从未 admitted 或构建已经终止。

下一步选定当前运行器合同支持的同键精确 conditional admission 路线，正在准备最小独立源码。它可能对账返回已有任务，也可能在原先未创建任务时首次执行。必须保持原请求、原键、digest 和 fingerprint 完全一致，取得新的精确执行授权后才调用一次；原超时记录不会改写。此检查点尚未授权或发出该新调用。

## 已保留并修复的证据处理缺陷

Mac 增量包已经完成原二进制读取，但归档函数仍含旧 successor576 固定键，导致纯归档收尾被拒绝。修复仅替换两个归档键，使用已取得的原载荷，不重发 Native 读取；准备、单次实际应用、前后状态及失败原件都保留。

PKI BODY 原请求已允许 16KiB 分页，接收函数仍按 8KiB 拒绝已收到的 page0。修复只有一个条件表达式：binary_read 接纳 16KiB，旧 INFO/process 页继续保持 8KiB。35 项检查包含实际旧页拒绝/新页接纳及超限反例。一次纯缓存恢复只改变 paused、pending、activeObserver，13 条原调用、原拒绝行和失败历史保持原值。截面时已批准原操作剩余三个页，不重复 page0 或 binary_read；完整正文尚未在根侧资格审查。

源码检查器自身发现的 binding 字段、旧 descriptor、对象结构和说明文字错误也保存为历史。修正这些本地检查不等于远端工作通过。

## 后续验收顺序

1. 取得 ROG 当前构建的真实任务身份及正常发布、default/file/HA 编译和 252/280 运行结果；Mac 核验完整落盘报告后编译正常 89/117；绑定各机器真实二进制。
2. 用当前同一候选在 Mac 与 X230 重跑正式 34MiB 存储迁移、恢复和重启。
3. 在 Mac、ROG、Pocket4 执行真实断主、重新选主、失去多数派拒绝、ReadIndex、持久化与重启，以及保留的 CLI snapshot 回归。
4. 完成实际 ps/reader 修复验证，建立不依赖 J3160 的新可信 AuthBus 凭证来源；真实 SDK 使用同代凭证、同一服务实例完成 AppRole、TLS、KV、Policy、续期及撤销。
5. 按已经固定的客户端与备份登记逐台完成真实凭证读写、重启、回滚和恢复验证，再逐台切流。仅在全部登记项迁移后删除旧服务、二进制和可再生中间资产。

全量 OpenBao 2.7.1 替代还包含已记录的未资格 API、控制面和正式存储能力。有限测试集合通过不能自动关闭这一产品级门槛；已有引擎实现也不能因为尚未完成正式资格而被误称为不存在。

## 证据和使用边界

- [STATE.public.json](STATE.public.json) 是本截面状态和剩余门槛。
- [MOUNT-INDEX.public.json](MOUNT-INDEX.public.json) 列出 112 个不可变公开证据包、1389 个文件、20081703 字节；所有挂载内容已整件读取，所有挂载树由叶子重新计算一致。
- [FINITE-MIGRATION-REGISTRATION.original.json](FINITE-MIGRATION-REGISTRATION.original.json) 保留原有限迁移登记。只有新观察到相关实际客户端、配置或恢复路径才重开登记；没有增加无限的“所有未知备份不存在”门槛。
- [ROG-FIXED-INFO-FAILURE-ROOT-QUALIFICATION.public.json](ROG-FIXED-INFO-FAILURE-ROOT-QUALIFICATION.public.json) 保留固定路径失败的实际解释边界。
- [PROCESS-START-IDEMPOTENCY-CONTRACT.public.json](PROCESS-START-IDEMPOTENCY-CONTRACT.public.json) 保存本次实际可用的运行器合同；它不是新执行授权。

公开 Git 只包含公开请求、代码、公开投影和证据摘要。私有列表原始 SDK、私有 Page 身份、共享名单及凭证正文均未挂载。每个来源自身的 SOURCE-only、历史、实际失败、UNKNOWN 或实际成功标签继续有效。

根 Native 调用数为 0，最多两个 owner lane。截面 A 等待 C 闭合后的执行分配；B 为原 UNKNOWN 保留 lane；C 串行完成原 PKI 页读取后做 Mac 固定 INFO。没有把源代码检查当作客户端切换或删除旧版的授权。
