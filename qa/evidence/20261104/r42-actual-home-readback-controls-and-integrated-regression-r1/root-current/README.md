# HeptaBao R42：Mac 实测输入闭合、ROG 控制文件与合并候选准备

截至 **2026-11-06 12:38:19 UTC**。任务继续进行。**完整替代 OpenBao 2.7.1、生产切流、全部客户端与备份路径迁移、旧版清理均未获通过。** 本检查点保存本轮原始证据与未决状态，不把源码或传输核验计作功能测试通过。

## 本轮已完成

Mac 的 R2 公共文件发布已成功：原任务 1a1b09ee29e-fc05-71c4 以 exit0 结束，30 个 T5 公共文件及 2 个 HOME 启动控制文件按冻结内容发布，8 个返回的 HOME 文件描述符全部关闭，原辅助进程已回收。独立根复核 97 项通过。之前 R1 的部分创建及未知状态保留。[R2 原始记录](../Auth-HOME-R2-inert-actual106/) · [根资格记录](../Auth-HOME-R2-inert-root97/)

随后完成 3 次元数据观察、4 次正文读取，共 35 次原始调用、21 页不可变返回内容、96,654 字节。outer、candidate 和实际收据全部按实际版本读取，3 个 full9 身份与发布时相符；正文重新拼接、逐字节哈希及冻结来源比对通过。作者的 88 项检查已重演，根独立复核 128 项通过。此结果证明公共输入闭合；真实凭证链仍待运行。[全部 212 件原始记录](../Auth-HOME-R2-fixed-readback-full212/) · [root128](../Auth-readback128-runtime23-build-binder21-root-reviews/Auth-fixed-readback-root128.public.json)

原样复用的 47c30a 派生器已从实际终态、stdout 和实际收据生成唯一的 8,207 字节 AuthBus 运行请求及 2,029 字节 HOME 身份绑定。根源码复核 23 项通过；保持 5 个当前消费者、完整配置与 provider/model 参数、真实注册表所有者断言、TLS/AppRole/KV/Policy/续期/撤销/冷重启/逆向回滚和原 900/1080 秒预算。截止点尚未启动该 worker，资格只会属于当前绑定的 4e808 基线，不能转移给未来合并版本。[实际绑定 SOURCE20](../Auth-HOME-R2-runtime-actual-bound-source20/) · [root23](../Auth-readback128-runtime23-build-binder21-root-reviews/Auth-runtime-source-root23.public.json)

ROG 的 025b 源码发布全量报告已经完成根 41 项复核；正常构建控制文件的公共发布任务 1a1b0ade81d-fc05-7220 也已 exit0，原 7 次调用及 2 个观察完整闭合，根 43 项通过。4 个文件的实际元数据已经收齐，并按冻结派生器生成唯一的正文读取请求。尚未完成四正文接受，也尚未进入正常构建或 149/166 测试。[源码发布资格](../PKI025b-stage-root41/) · [控制文件原始发布](../PKI025b-controls-inert-full52/) · [元数据实际绑定](../PKI025b-fixed4-actual-info-body-binding16/)

## 当前两条传输恢复

| 链路 | 已知原状态 | 截止点的边界 | 下一动作 |
|---|---|---|---|
| 快照输出 | 10 个正文完整闭合，574,522 字节；26 个观察完整收集 | 第 11 个文件 INFO 原操作 37a07e… 已 completed/stored/inactive；其 page0 返回 MCP -32603，正文交付 UNKNOWN；当前 0 call/0 future | 对已知原 operation_id 的同一不可变 offset0/8192 页做单独记录的读取恢复，保留首次错误 |
| ROG 控制文件 | 4 个 INFO 完整闭合；body0 请求已按实际版本固定 | 唯一 body0 admission 返回 MCP timeout，无 operation_id；保留一个 UNKNOWN 通道；body1–3 未提交 | 对相同幂等键及完全相同参数做明确的有限对账；已有绑定与首次接纳两种分支分别记录 |
| Mac AuthBus | 原发布及固定回读均已完成 | 运行 slot 未初始化，0 call/0 future；尚未启动新进程 | 既有读取通路恢复并核实通道边界后执行唯一冻结 worker |

快照的第一页失败记录、原 ACK/status、请求、外部调用意图与已完成输出已一并保存。[快照原始 release20](../Snapshot-file10-INFO-page0-error-release20/) · [根边界核验](../Readback-transport-boundary-root-reviews/Snapshot-file10-page0-boundary-root14.public.json)

ROG body0 的完整错误 SDK、原请求、调用意图、暂停状态和四 INFO 实际绑定均保留。相同错误文本可能具有相同 Git blob；每一次失败都必须由具体 slot、请求、调用键与原始 arm 上下文辨认。没有收到操作 ID 不证明远端未接纳或未执行。[body0 UNKNOWN 原件](../PKI025b-body0-admission-UNKNOWN9/) · [根绑定核验](../Readback-transport-boundary-root-reviews/PKI025b-actual4INFO-binding-body0-UNKNOWN-root12.public.json)

同键入口没有独立的 lookup-only 参数。它可能返回已有绑定，也可能在没有绑定时首次接纳这一个固定只读请求；reused=false 不得倒推第一次未提交。既有公开源码审阅不是当前部署版本的证明。截止点没有执行本次同键对账，原 UNKNOWN 状态不变。

另外两次 Git 归档回读错误已完成只读协调：原 CREATE 的确定 ACK、同一树和原三文件均核实后，恢复原未调用步骤。恢复前后只改变已授权的 arm/phase/paused 字段及必要审计记录，历史错误不删除，也没有重发远端业务。[快照恢复](../Snapshot-fixed23-p0-Git-arm-recovery-GO-root19/) · [ROG 状态查询恢复](../PKI025b-receipt-info-status-arm-recovery-GO-root19/) · [实际前后对比](../Readback-transport-boundary-root-reviews/original-Git-arm-actual-recovery-followup.public.json)

## 一个最终候选的合并边界

以 025b05a340de841b8161c1120344e86eae30eb97 为底座，叠加 49 个实际格式化后的快照相关文件。两份源码树只有 54 个差异路径：49 个快照路径与 5 个较新 PKI/验收路径互不重叠。因此合并应保留新底座中的两处缺失参数修复、PKI 过期/撤销租约的 400 行为、新增回归，以及严格状态码断言。旧版 400/404 归一化不会重新纳入候选。

49 个输出中 26 个可复用已完整保存的相同正文，23 个需要独立读取新的格式化正文。后者当前完成 10 个。完成后预期源码树为 3,930 个受跟踪文件、62,498,221 字节；最终 tree/commit 尚未冻结，也没有构建或功能资格转移。[根合并分析与 54 路径差异](../Integration-and-HTTP12-root-source-reviews/)

精确回归集合已由工作线报告为：原 JWT/PKI 149 个独立用例、快照新增 27 个、保留正常回归 61 个；三组交集为空，合计 237 个独立用例、254 次配置实例。此处是待执行分母；完整集合证明尚待根审阅并纳入下一检查点。当前正常构建的既定分母仍是 149/166，未在执行前悄悄扩大。

## HTTP/ACL 验收修正

保留原 12 个 PKI 用例与 23 个 ACL 用例的期望值。HTTP 报告模块已做两处严格差异修复：每次调用只使用本次新产生且 case_id 一致的记录；若没有唯一的新记录，原始状态码保持 null，避免上一用例的状态被误归给当前失败。原传输、认证、断言与请求语义保持一致。该模块尚未执行，四条失败路径运行检查及实际官方 oracle 仍待进行。

ACL23 的源码上界为 853 次请求，尚不含夹具创建及清理；这不是实际请求计数。官方 OpenBao 2.7.1 二进制及隔离运行夹具必须由实际记录绑定后再运行。[修复 SOURCE5](../HTTP12-case-local-status-source-fix5/) · [根源码与请求上界审阅](../Integration-and-HTTP12-root-source-reviews/HTTP12-case-local-status-root-review.public.json)

## 五道用户门槛

| 门槛 | 已有可保留证据 | 本轮后的必要工作 |
|---|---|---|
| KV2 正式迁移/恢复 | 4e808 基线的 34MiB 正式存储场景在 Mac、X230 各 31/31 | 修复快照 standby CLI 路径，并在最终合并候选上重新验证完整迁移、恢复及冷启动 |
| Mac/ROG/Pocket4 HA | 基线真实三机 98+12：断主、重选主、ReadIndex、持久化和冷重启 | 在合并候选上完成必要局域网回归，覆盖新的快照行为 |
| AuthBus 可信来源 | 不依赖 J3160 的当前所有者链源码、输入发布及独立回读已闭合 | 运行真实凭证、TLS/AppRole/KV/Policy/续期/撤销/重启/回滚；尚无本次运行通过 |
| 逐台切换 | Mac5 与 ROG6 的既有有界调查记录 | 最终候选上逐台真实凭证读写、重启、回滚；补齐 Pocket4/X230 当前客户端；然后才切流 |
| 旧版清理 | 条件与历史资产记录保留 | 所有当前客户端及备份路径完成迁移后清理；截止点未清理生产旧版 |

其他兼容性缺口仍包括 JWT 非 root 角色策略语义、其他认证/provider 路径、外部 secret engines、ACME/EAB/KMS/HSM、rekey/恢复/轮转及运行时插件变更等。源码路由数量、单独分支的测试通过或本轮哈希核验都不能证明这些实际运行能力。

## 证据与恢复

本检查点挂载 47 个已完整回读的证据包，合计 871 个文件、14353547 字节。根索引按每件文件的字节数、SHA-256、Git blob 及完整 Merkle 树重新核验；该索引资格仅表示归档完整性。[完整状态](STATE.public.json) · [逐文件索引](EVIDENCE-INDEX.public.json) · [索引核验](root-index-qualification.public.json)

上一检查点为 3e9ae35a5a6371bd180f3b93248e0c4d4ecf502b，R41 的发布意图、SDK、tree/commit/ref 回读证明也纳入本轮。所有旧失败、UNKNOWN、先前候选与未迁移资产仍保留。全局最多两个 Native 通道，每条最多一个当前调用或归属 future；未知 future 继续占用通道。根执行环境不可用，本轮根工作只进行公开证据处理与 Git 归档。
