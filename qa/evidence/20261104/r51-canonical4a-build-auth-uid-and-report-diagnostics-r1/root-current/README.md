# R51：Mac 构建启动、AuthBus UID 修复及 ROG 失败诊断

证据截止：2026-11-07 02:46:35 UTC。任务继续。本检查点不能证明已经全量替代 OpenBao 2.7.1；正式客户端切换为 **0**，旧服务和旧二进制清理为 **0**。

## 本轮实际结果

- **AuthBus 的固定 ps 检查通过真实修复验证。** R3 在 Mac 上成功解析 723 行记录，其中负号 UID 行 1 条；原始词法投影仍保留旧规则会拒绝这一行的事实。当前固定 ps 的父子关系、进程组、有效 UID、WNOWAIT 保留退出、回收、输入描述符关闭与最终文件身份校验全部通过。原始 9 次调用、2 个观察操作、4 页已完整闭合。Root 重放 333 项原始链核验，另核对 10 项跨包原文。R1/R2 失败及旧 UNKNOWN 保持原状。这是固定进程检查的资格，完整 AuthBus SDK 尚待实际运行。
- **Mac 外接 T5 当前候选源码已正式落盘并核验。** 3,932 个文件、62,553,956 字节、全部模式和内容与目标树相符；Git fsck、独立对象、历史与原源码不变检查通过，31 个原始子进程均正常退出并回收。三份构建控制文件及收据也已实际创建、整件回读和校验；发布任务 exit0，原始传输链 63 项核验通过。
- **Mac 正式构建已启动。** 原任务 `mac/1a1b3da94dd-fc05-851a` 的 ACK、输入摘要及完整 64 位指纹吻合，fresh target 的 preflight 已通过，最近原始状态为 running。计划执行 89 个唯一测试、117 次 profile 执行；本截止点还没有当前 Mac 的最终 release、117 或 formal34 结论。
- **ROG release 阶段成功，整个构建／测试任务失败。** 原任务 `rog/1a1b3978da9-fc05-83bd` 终态 exit1，未超时，stdout 3,708 字节完整且持久，stderr 0。已保留正常生产 release 两个二进制的阶段事实；最终测试、文件完整身份及失败原因尚未由详细报告确认。固定报告的实际元数据已取得：91,252 字节，整件 SHA-256 `7be18adad000805344acf09d01b91fbd1ed99e561bfbc97c9faf0fd56a07b250`，0600、1000:1000、单链接、固定版本；正文尚待读取。
- **官方 OpenBao 2.7.1 PKI12 基线原始报告完整。** 12 个实际案例均按原判据通过；过期和撤销后查询的原始 HTTP 400 均保留。当前 HeptaBao HTTP 对照资格尚未完成。
- **X230 两份源码包及最终落盘输入已核验。** 当前版本的 X230 落盘和后续运行仍待执行。

## 当前候选与范围

候选提交：`4a49405b93c45ab1c25ecba11cde63a7ede20dce`；树：`f02dd113d208d79f5275005dc65a5e8aecd0e9d3`。该提交仅含此前记录的三处测试修正，生产源码延续上一候选。历史 `4e808d0` 的 Mac/X230 formal34、Mac/ROG normal61 及 LAN98+12 证据保留，但不替代当前候选的实际回归。

| 用户要求的门槛 | 本截止点 | 下一项实际证据 |
| --- | --- | --- |
| KV2 正式迁移、恢复 | 当前 formal34 尚未完成 | Mac 与 X230 的当前正式二进制、34MiB 迁移、完整备份及恢复 |
| Mac / ROG / Pocket4 HA | 当前真实多机回归尚未完成 | 断主、选主、ReadIndex、持久化和重启 |
| 无 J3160 的 AuthBus | 固定 ps blocker 已通过；SDK 仍未合格 | 当前 Mac 二进制、新可信凭证来源及真实 AppRole/TLS/KV/Policy/续期/撤销 |
| 逐台切换 | 0 台 | 每台真实凭证读写、重启、回滚后再切流量 |
| 旧版清理 | 0 项，未满足条件 | 全部已登记客户端及备份恢复路径迁移完成 |

客户端和备份范围沿用已经核定的有限登记。不会以未观察到的假想客户端扩张门槛；新增实际配置或恢复路径会重新纳入。Mac 五个 agent 的完整模型、provider 等设置须保留，未来连接切换仅涉及已明确的四项连接字段。

## 原始证据与可复核范围

[状态快照](STATE.public.json)、[逐件 Git / SHA-256 清单](MOUNT-INDEX.public.json)、[Root 核验索引](ROOT-QUALIFICATIONS.public.json) 和 [下一步](NEXT-ACTIONS.public.json) 给出当前断点。这里挂载 76 个已经整件读回并重算树的证据包，共 960 份原始文件、13706150 字节；根目录说明文件另计。

关键原件见 [AuthBus R3 输出](../auth-signed-uid-r3-actual-min12/stdout.original.json)、[R3 原始全链](../auth-signed-uid-r3-original67/actual-result.public.json)、[Mac 源码落盘报告](../Mac4a-actual-source-stage-report1/report.original.json)、[Mac 构建输入](../mac4a-actual-build-source28/request.exact.json)、[ROG 最终输出](../rog4a-terminal-release8/STDOUT.original.jsonl) 及 [ROG 报告实际元数据](../rog4a-build-result-info-actual21/INFO.native.original.json)。

SOURCE 检查通过、传输完整、实际执行通过、产品兼容通过分别记录；这些计数不能混为产品案例数量。原始缺 ACK、Git UNKNOWN、旧 INFO 失败与恢复记录均保留。全程 Root 不执行 Native，最多两个 Native owner lanes；本截止点 A0、B0、C1。后续新的 BODY 或运行授权不回写这个截止点。
