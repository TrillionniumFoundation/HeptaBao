# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R30：源码跨机运送已闭合；桌面导入与 X230 发布继续收证

状态候选截点 **2026-11-05T18:08:38Z**。产品固定为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**Mac 当前版本的官方 OpenBao 2.7.1 对照 full34 原始 31 项通过保持有效；全量替代仍未达标，未切换生产流量，也未清理旧服务、二进制、备份或中间资产。**

[本轮机器状态](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/state.public.json) · [本轮完整清单](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/manifest.public.json)。本轮新增证据严格按清单收录；下面的完整 R29 文档逐字保留。清单中的“完整包”指该包所有叶子、字节和 Merkle 关系完整，不代表整个运行场景已经合格。

### 五项目标的当前门槛

| 用户目标 | 已有实际证据 | 尚需完成 |
|---|---|---|
| KV2 正式存储、迁移和恢复 | R29 的当前 Mac full34 原始 31/31：17×2MiB、19 条历史、一次导出/导入、冷启动、HTTP 快照/恢复及三轮历史见证 | 当前 Linux/X230 同版实际回归；仍不能把单机 31 项外推到全部 OpenBao 功能 |
| Mac、ROG、Pocket4 HA | 当前三机控制源码已逐字取回；Mac/ROG 正式构建与正常 61 项已通过 | 当前源码导入完整资格 → 原有 prepare → 当前真实断主/自然选主/ReadIndex/持久化/重启的原 98 项和另列 12 项 |
| 不依赖 J3160 的 AuthBus | 实际捕获 catalog 与三份公共 SDK 源码已读完整；原 namespace 拒绝保持，已识别实际未知 owner 依赖 | 实际 owner/注册实例与安全准入证明、可信 issuer/CA/roles/policy，及 AppRole/TLS/KV/Policy/续期/撤销实际链 |
| 逐台切换 | 旧客户端与备份证据、已有回滚前提保留 | 每台当前真实凭证读写、重启、回滚及流量切换；当前尚无全量切换资格 |
| 清理旧版本 | 未执行删除 | 所有客户端与备份迁移及回滚验收完成后，才执行只保留最新版服务的清理 |

### 1. 两份源码材料的实际跨机运送已通过根复核

原任务 `desktop/1a1acb4e995-fc05-567a` 为 exit0/full/durable/confirmed。完整 124 件包包含 7 个已闭合原观察、11 页不可变结果、3 个已回收子进程及原始命令/流。两份实际目的文件合计 **22,360,554 B**，分别为 22,320,862 B 的完整 bundle 和 39,692 B 的导出回执；目的 full9、相同 FD 全文件 hash、源前后身份、SSH 信任配置和 helper 身份一致。根复核 **174 项**通过。

这完成的是两份已命名材料的运送。桌面 Git 导入、X230 的实际目的文件以及产品运行资格分别核验。[原完整包](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/source2-relay-complete124/) · [根复核](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/root/r30-source2-relay-root-review.public.json)。

### 2. 桌面完整源码导入：原任务成功，资格仍等待独立 core 和全部原命令

Importer 只绑定 20 处已核实输入字面量；29 个完整定义及原 300/Git60/clone90/TERM5/KILL5 预算保留，根 AST 检查 69 项通过。仅提交一次原任务 `desktop/1a1acd0d62d-fc05-571a`，原 ACK 与精确请求绑定一致。

权威任务已为 **exit0/full/durable/confirmed**，stdout0、stderr28,576 B。完整 terminal-scope 文件报告 48.63311454304494 秒内完成，canonical commit/tree/sole parent/root/3,763 历史与 3,914 个实际 Git blob/index 一致；21 个 child 均回收，19 个 exit0、两个 config 无匹配为预期 exit1；三个 input FD、四个目录 FD 和新 source 目录 FD 均报告关闭。

**这些终态报告尚不等于完整 source-import 资格。** 独立固定 `CONTROL/result.public.json` 的全字节回读及 21 个原始命令/流档案在本候选截点尚未完成；core 预期为 36,163 B / `484ebbd31e94213c526bbde8664a516658fbab48a273bace01396a6ca10adb72`。原 LAN prepare 请求 `483231ef…` 保留，未另建控制层，也未执行 prepare/live。

尾部第一次只读 admission 失 ACK；原错误完整保留。根仅批准原 job、原 offset16384、原 limit16384、原 key 的一次对账。它返回 `reused=false`，该返回 ID 的结果已收齐，**第一条失 ACK 的只读 future 仍记 UNKNOWN**；没有重跑 import，也未用新的返回值宣称旧 future 终止。[原部分证据](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-original-partial52/) · [终态范围包](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-terminal-scope5/) · [原只读错误](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-streams1-original-error2/)。

### 3. X230：七个实际输入已绑定，隔离发布任务成功，传输尚未提交

七项输入包括当前 Linux server、normal build/result/61/groups 和完整源码 bundle/export receipt，全部绑定已有的实际 desktop 路径、size、SHA 和版本。原→prebind→ready 两阶段严格差分与三角色 AST 检查通过；合并根检查 **189 项**、66 个完整定义保持不变。该数量是 SOURCE 审阅数，不是产品测试数。

原隔离发布 `desktop/1a1ace08ffa-fc05-576b` 已收到精确 ACK，且权威为 **exit0/full/durable**，stdout1,514 B、stderr0。它仅创建并 compile 三个控制脚本及发布回执；四个固定文件的独立 info/whole body 与所有原观察闭合仍在进行。**Relay 原请求 `9241a86d…` 尚未提交；X230 source-import/full34 都未合格。**

旧 relay `desktop/1a1aa57458d-fc05-4156` 的 UNKNOWN 完整保留。原 effect fence、三次核验、FD 关闭记录和全部预算未改；该 fence 依赖命名空间稳定，不能当作连续原子隔离或旧远端任务终止证明。[prebind](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/X230-seven-inputs-prebind33/) · [ready](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/X230-seven-inputs-ready34/) · [根 SOURCE 复核](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/root/r30-X230-ready-seven-inputs-source-contract-root-review.public.json)。

### 4. AuthBus：实际 catalog 和三份公共源码已闭合；尚未取得实际 owner 执行资格

原 catalog `mac/1a1acb902f1-fc05-5693` 为 exit0/full/durable，stdout8,971 B，九个 FD 全部关闭。实际 ordinal22 是固定公共 SDK tree 下的 `google`；ordinal68 是已知 npm root 下的 `codex`。原 composite namespace 谓词在 22 上仍为 false，未过滤该候选，未改变五个 agent 的模型/flags。Catalog 投影根 21 项、原 catalog/三 infos 链根 92 项通过。

三个原 version-bound body 现均 completed/stored/inactive，合计 **13,569 B**：policy5,718、support4,255、Codex3,596。根 62 项检查独立确认原 SDK/native、单页不可变 payload、完整源码字节、SHA/版本/EOF 及前件闭合关系。根第一次纯检查误将后两件 intent 的前件 blob 引用当成首件 boolean 字段；原错误/原 verifier 保留，仅修根检查字段，未重做任何 Runtime 操作。

实读源码显示，配置优先级、OpenAI routing 谓词、实际注册 options、所有候选及同一 registry 实例均会影响结论。因此不能由 `provider=openai` 或 Codex 默认 priority100 推定实际 winner。下一份独立 proposal 只列三个精确 import 指向的 metadata：`model-runtime-policy-Ca791C2-.js`、`openai-routing-DXJmS9CT.js`、`loader-D8d2EvVh.js`，根源码检查18项；本截点均未提交。Google manifest 文件名未猜测。

旧正文 readset 已在 3 operations/13,569 B 关闭，旧上限不自动授权新依赖读取。后继正文必须依实际 size/version/hash 单独列原量、新增量及累计量；原 fixture 预算不变。配置等价 ledger 和同实例计划仍有未绑定项；未把空配置当成等价配置，未执行 SDK/loader/supports/factory/凭证或 provider 请求。[Catalog/infos 原完整包](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/Auth-catalog-and-three-infos-complete87/) · [三正文原完整包](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/Auth-three-public-body-complete56/) · [最小依赖和等价计划](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/Auth-minimal-owner-plan9/)。

### 5. 当前推进顺序与证据边界

Line A 只收桌面原 importer 的实际 core、原始命令和所有资源关闭证据；闭合后使用已存在的精确 LAN prepare，再以真实 prepared SHA 单独推进原 98+12 物理 HA。Line B 只收 X230 原 inert 的四个固定文件；闭合后推进精确 relay 和实际 X230 source/materialized/destination 证明，再用当前相同构建执行 Linux 存储与恢复。Auth 后继三 metadata 在实际窗口释放后继续。Root0 Runtime，最多两条窗口，每条一次调用与一个已知 owned native future。

当前 CLI 五个窗口、H2 三个窗口、当前 Linux full34、当前物理 HA、AuthBus 真实凭证链、逐台客户端/备份迁移和最终清理均保留为待完成。H2 的 8MiB 范围不代替 34MiB；官方源码的静态 API 计数不作完整运行等价性的分母。所有旧失败、UNKNOWN、旧 normal/QA 身份及回滚材料保留。

---

<!-- R29 document begins below; its complete original bytes are retained as an exact suffix. -->

