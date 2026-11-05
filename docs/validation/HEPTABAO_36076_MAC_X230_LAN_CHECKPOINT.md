# HeptaBao 全量替代推进检查点 R32

时间：2026-11-05T21:01:15Z。当前候选仍为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`，源码树 `eba5e650bd080b8ad41ea52a2bc68867f541d255`；Draft PR #159 尚未合并。

**当前结论：三机 HA 的本轮限定场景已经通过完整核验；全量替代 OpenBao 2.7.1 尚未成立，正式切流和旧版清理均未进行。** X230 的正式 KV2 full34 原始作业已成功退出，结果文件报告 31/31；详细报告和原始读取链仍在接齐，不能提前写成完整资格。

## 五项门槛的实际状态

| 门槛 | 已有证据 | 剩余工作 |
| --- | --- | --- |
| KV2 正式存储与迁移恢复 | Mac 当前版本已完成真实 OpenBao 2.7.1 到 native-v6 的 34MiB 迁移、冷重启、HTTP 快照及恢复；原始 31 项通过。X230 同版正式作业报告 31/31、144.321 秒。 | 完成 X230 90,926 字节详细报告及原始读取链核验，再运行固定的 69 项对照。 |
| Mac、ROG、Pocket4 HA | 当前正常构建的原始 98 项和独立重启后 12 项全部通过；真实杀主、自然选主、失去多数派的拒绝行为、ReadIndex、持久化和重启均有本轮记录。 | CLI 快照保存/恢复/备用节点路径，以及明确的 TLS-ALPN-h2 门槛仍待实际运行。 |
| AuthBus 可信来源 | 已核回公开加载器与路由源码；两份新增注册器元数据完成独立核验，四个版本绑定的源码分块正在读取。 | 确认真实注册入口与所选 owner；继续无需 J3160 的 AppRole、TLS、KV、Policy、实际续期与撤销。 |
| 逐台切换 | 保留已有 Mac 5 项、ROG 6 项的有限观察与 ROG disabled generation203 状态。 | 当前完整客户端集合、Pocket4 manager、X230 实际消费者及各台凭证读写、重启、回滚仍需闭合；尚未正式切流。 |
| 旧版清理 | 旧失败与 UNKNOWN 记录保留，生产旧服务和旧二进制未删除。 | 只有全部客户端及备份路径完成迁移验证后，才执行清理，最终保留最新版 HeptaBao 服务。 |

## 三机 HA：本轮已经证明的行为

原始作业 `desktop/1a1ad3a6dd4-fc05-5919` 使用当前 `4e808` 正常构建和 Mac、ROG、Pocket4 的真实局域网直连端点。主节点 1 的 PID 74905 被 SIGKILL 后，节点 2 自然成为新主；丢失多数派时读写均返回 503，拒绝的写入在三台均不存在。恢复多数派和整组冷启动后，仍使用原始密钥与原数据，不做重新播种。

本轮保存 19 个生命周期版本，其中 17 个版本各含 2MiB 可读载荷，共 35,651,584 字节。后续方向性恢复由 Pocket4 节点 3 提供数据，实际空节点选主结果为 Mac 节点 1；没有强制选主。独立 post-cold 12 项耗时 51.809603 秒，沿用共享 300 秒预算和控制器 2400 秒预算。重启前后三台 committed/applied 均为 67；四个小键在三台通过正常 ReadIndex 读取；原始历史元数据哈希保留，338 个指定密文叶、35,742,455 字节逐一匹配。

资源收尾记录包含 19 次 owned 启动及对应的 19 次停止、7 个 Mac 前台会话关闭、14 个 native/local leader 回收。证据支持原始 5 秒停止期限内的这些已拥有进程收尾；没有声称存在全机文件描述符盘点或逐 FD 运行时账本。

最终资格由独立的业务与收尾核验、原始读取链核验共同组成。原始读取链共 15 个观察、62 个不可变页；档案中的四处归档修正不改变实际运行记录。检查器的断言数量不计作产品用例。此前 `df026` 的失败仍为失败；本轮没有借用 baseline62 或 official30 成绩。

完整资格见 [LAN-complete-qualification.public.json](../../qa/evidence/20261104/r32-X230-source-and-LAN-prepared-runtime-r1/roots/LAN-complete-qualification.public.json)。其范围仍是这一版本的真实三机合成验证环境。native HA 快照导出/恢复、大体积 HTTP 转发、物理断电、磁盘满、长期线性一致性、生产流量迁移与旧生产资产清理不在此资格范围内。

## X230：正式存储运行已成功，归档核验继续

当前源码搬运已经闭合：3763 个提交历史、3914 个源码叶、完整 fsck 与干净工作树；七个产物共 132,647,913 字节。原始 21 个命令中 19 个退出 0，另两个为预期的配置不存在退出 1。此前无法确认终态的旧 relay `desktop/1a1aa57458d-fc05-4156` 仍保留 UNKNOWN；三个有限命名空间围栏不被扩写为它已终止的证明。

官方 Linux OpenBao 2.7.1 可执行文件、原始发布包以及三个控制文件已完成独立元数据和源码绑定。唯一的 full34 原始作业为 `x230/1a1ad5ffad0-fc05-599a`，终态为 succeeded/exit0，日志 complete、durable，终态发布 confirmed。1124 字节实际结果文件报告原始 31/31、耗时 144.321 秒、owned 进程已停止、源码与二进制前后不变。

本检查点已保存这些原件，但尚未把 90,926 字节 summary 和全部读取链的核验标志置真。报告内容预期 SHA256 为 `b9966b600df2f2c681148b63d03dca3bbceabcdff3fb42dc1eb4bae73677ae9f`。继续读取同一作业的版本绑定结果；不为补证据重新运行 full34。固定 comparison69 仍未提交。

Mac 的 full34 31/31 是此前已经闭合的独立资格：17×2MiB、19 个版本、三个正式存储阶段的 57 个历史见证、一次导出与一次导入，各自沿用 360 秒预算，以及 HTTP 快照恢复、删除/销毁/CAS 语义。它没有在本轮重跑，也不单独赋予多机或生产替代资格。

## AuthBus、CLI 与 H2 的下一执行关口

AuthBus 已核验 runtime-policy、openai-routing、plugin-loader 的前一轮公开源码和两份新增注册器的元数据。新增 manifest-registry 为 31,444 字节，plugin-registry 为 181,581 字节，四个既定读取块共 213,025 字节。当前只沿原操作 ID 与固定版本取回这些源码，仍未执行 SDK 诊断、读取诊断私密 capsule 或改动 provider/model/refresh/quota。源码中的条件路由或候选顺序本身不构成真实 owner 的证据。下一改动必须直接解决原入口的实际拒绝点并绑定同实例注册结果。

CLI 准备脚本沿用既有实现，仅绑定当前源码、产物、目录与固定旧失败围栏；独立源码审查和根审查均已通过。其固定请求保留内部 300 秒、外层 330 秒期限，尚未运行。准备结果需要实际创建的目标文件身份、完整 stdout 及关闭后成功终态；单独的 durable 结果文件不能替代这些证据。之后才进入只读 prepare 与 B01–B05 快照、恢复、冷启动和备用节点路径。

H2 保留当前产品 `4e808` 与已构建工具 `df026` 的双重身份。12 个工具输入中有 7 个独立元数据结果，余下 5 个待观察；22 个新目标文件身份均未观察，模板 ready 仍为 false。已确定现有 CLI 准备脚本需要局部增加 owned h2qa 目录及 FD 关闭、第二固定输入目录、精确 FD/文件名/成员集合、H2 carrier schema 与 h2_client 绑定。原五个 QA 文件、H01–H03、固定期限及失败资产保留策略不变；未创建另一层执行控制器。

## 证据保存与恢复边界

本检查点锚定 24 个不可变包、1925 个包内文件、15798161 字节及 646 个包内 Merkle 树。相互包含的历史包会重复计入归档数量；这些数字不是产品测试数。

临时 functions.store 缓存在续接期间丢失。已有原始 SDK、源码、结果和资格文件均沿已知 Git 对象恢复；远端原始作业没有因此重启。新返回先保存到共享文件，再归档。已完成的 whole 检查和资格直接沿用已保存的审查记录；包的 Merkle 目录重新核回。两次读取整个历史大树遇到 Transport closed，改为验证所有被修改祖先的直接树和其余子树身份。此归档读取问题没有被记作产品失败。

下方 R31 文档逐字保留；旧索引中的 JSON 数字原词法文本保持，避免 64 位时间戳被 JavaScript 浮点数改写。后于此冻结点的详细报告、注册器完成结果及新的实机验证归入 R33，并继续推进。

---

## 原始 R31 及此前文档（逐字保留）
# R31：独立源码导入完整验收；X230 控制文件闭合；三机 HA 准备已启动

冻结时间：**2026-11-05T19:02:41Z**。本节是当前结论；下方保留 R30 及更早全文。前一检查点为 [R30 `cd57cb6709f6185295b1ea154415aab50d8c7a2f`](https://github.com/TrillionniumFoundation/HeptaBao/commit/cd57cb6709f6185295b1ea154415aab50d8c7a2f)。

**全量替代 OpenBao 2.7.1、生产切换、旧服务/二进制/资产清理、全部客户端和备份迁移，仍全部为 false。** 本轮关闭的是源码、控制文件和原始证据门槛，尚未把准备任务或传输任务算成产品运行资格。

## 当前门槛

| 门槛 | 已有完整证据 | 尚未完成 |
|---|---|---|
| KV2 正式迁移与恢复 | R29 已完成 Mac 当前 `4e808` 官方 2.7.1 full34 原 31 项：17×2MiB、19 版本、单次导出/导入、冷重启、HTTP 快照/恢复、删除/销毁/CAS及所有权进程停止 | 当前 X230 full34；多机和实际生产迁移 |
| 当前源码供给 | Desktop 独立导入完整验收，3,763 提交、3,914 叶文件、完整 fsck、干净独立 Git 目录、原21命令和全部保存流 | X230 接收端的七文件独立身份、接收回执及原始命令闭合 |
| HA | 已有9份现机源文件完整取证；本轮已唯一启动既有 prepare | 实际5输出及 prepared 全文资格；随后 Mac、ROG、Pocket4 原98项和分列12项真实断主/自然选主/ReadIndex/持久化/冷重启 |
| AuthBus | 既有有限 catalog 与3个公共源正文闭合 | 既定3个依赖 metadata 尚未提交；实际同实例 owner/配置/隔离门槛及 AppRole、TLS、KV、Policy、续期、撤销 |
| 客户端、备份、清理 | 既有历史记录继续保留 | 每台真实凭证读写、重启、回滚和所有备份路径完整迁移；没有清理授权 |

## Desktop 独立源码导入已完整验收

唯一任务仍为 `desktop/1a1acd0d62d-fc05-571a`，权威终态 **exit0/full/durable/confirmed**。实际耗时 **48.63311454304494 秒**，原总体300秒、clone90秒及 Git60秒均未变。独立回执完整 SHA-256 为 `484ebbd31e94213c526bbde8664a516658fbab48a273bace01396a6ca10adb72`。

规范身份为 commit `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`、tree `eba5e650bd080b8ad41ea52a2bc68867f541d255`、唯一父 `1c66541993662f92cf717154e33717abedb2ea74`。3,763 次历史和3,914个实际 Git blob/index 项一致，源目录干净、无 shallow/partial/alternates。原21条命令均已回收且进程组为空；19条 exit0，另2条“配置不存在”探针依原合同 exit1。三个输入文件、四个输入目录和创建的源码目录均有正向 FD 关闭证明。

[完整资格](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-desktop-current-source-import-complete-root-qualification.public.json)与[原始289文件包](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/importer-complete289/STATE.public.json)按同一不可变回执绑定。最终65项内容中，**63项/61,389 B** 来自实际原生完整正文读取；两份 **889,176 B NUL清单**依据明确授权，从已核规范树完整重建，并绑定当前独立 file_info 的完整文件SHA、版本与九字段身份。两份大正文的 **current-host body RPC=0**；没有声称取回了现机正文。原14个大正文请求未提交，其他63项没有被替代。

原始证据共 **12个已返回观察ID、36页**，全部 completed/stored/inactive。原core115中112个非汇总路径保持字节不变，3个汇总文件为后继版本，旧blob保留。Root独立 core91项、最终内容211项及 NUL metadata34项与独立原始链复核按分工合并；这些数据谓词均不是产品测试数量，也没有重复运行同一 peer verifier 来制造额外测试数。

## X230：控制文件已验收；七文件 relay 只具备当前部分证据

原 inert 任务 `desktop/1a1ace08ffa-fc05-576b` 的3份控制程序和回执均已完整取回，与已审源字节相等。10个原始观察ID、14页已闭合，root35项内容/身份语义与独立链复核通过。[完整 inert 资格](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-X230-inert-complete-root-qualification.public.json)只证明隔离发布和编译检查。

随后按[原386B请求的 exact GO](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-X230-exact-seven-file-relay-GO.public.json)仅启动一次 `desktop/1a1ad0a9524-fc05-5839`。原ACK的 digest 和无损十进制 fingerprint 均吻合，权威结果 **exit0/full/durable/confirmed**，stdout368B、stderr0。计划仍是7份公共资产/132,647,913 B，加固定 X230 根目录内独立 Git 导入；没有产品、凭证、HTTP、编译或生产动作。

本冻结只包含[ACK/权威终态有限复核](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-X230-relay-original-ACK-authority-root-review.public.json)及原件。接收端七项独立 metadata、接收回执完整正文、原命令保存流和完整观察链仍在闭合，**X230 源码导入资格和产品资格均未宣告完成**。旧 relay `desktop/1a1aa57458d-fc05-4156` 仍是 UNKNOWN；原三 held-FD fence 的有限稳定命名空间条件不等于连续原子保留或旧远端终止证明。

## 三机 HA：仅启动既有 prepare

Desktop 导入验收后，[exact prepare GO](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-existing-LAN-prepare-exact-GO.public.json)开放原请求 `483231efe2016a8bd72b8aa205fb589b13513f6e`。唯一返回任务为 `desktop/1a1ad1383c9-fc05-5863`，原5argv/key/360秒和原始无损请求身份一致；[ACK有限复核](../../qa/evidence/20261104/r31-source-import-x230-transfer-and-HA-prepare-r1/root/r31-existing-LAN-prepare-original-ACK-root-review.public.json)已封存。

没有新增 launcher、控制层、路径或超时。既有 ROG/Mac 构建路径、10个产物哈希、5个QA源、36个旧证据 fence 和真实自然选主合同保持。冻结时5个实际输出/ prepared 完整SHA尚未独立验收，**live未提交、没有 live GO**。后续实际结果归入 R32，需在实际 prepared 全文闭合后使用原有 live 请求。

## 原错误、范围及后续

- Desktop 首次尾部观察失去ACK，获准同键对账返回 reused=false；首次观察的历史 UNKNOWN 保留。
- 第3批小文件首次 START 错误保留；其同键获准对账实际 reused=true，对应原ID已完整关闭。它与前一事件使用相同通用错误文本，不代表同一个操作。
- core-info 原结果页错误以及 X230 inert 原streams status错误、各自同ID恢复原件全部保留。
- 新增纯 checker 的本地 schema修正和原版/失败记录保留。Root最终65 verifier 的 source_after字段投影在首次执行前按实际schema改正，未执行旧版，也未更改候选或原证据。
- Auth下一步仍仅限源码中真实import指向的3条metadata；没有猜Google manifest、过滤候选、改模型/provider/refresh/quota或触碰J3160。
- 完成准备/传输后继续原产品验证，再处理逐客户端凭证、重启、回滚和备份迁移；旧 OpenBao/HeptaBao 均未删除。

本轮归档 **12 个完整包、609 个文件、5901788 B、221 个包内 Merkle对象**，另有 33 个根级原件/复核及 state/manifest。每个包和引用对象已 whole-byte、SHA-256、Git blob/Merkle核对；前一检查点全部非文档叶节点原样保留。仅2个历史总文档追加当前状态。原始64位整数从未通过浮点重序列化。

---

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R30：源码跨机运送已闭合；桌面导入与 X230 发布继续收证

状态截点 **2026-11-05T18:15:55Z**。产品固定为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**Mac 当前版本的官方 OpenBao 2.7.1 对照 full34 原始 31 项通过保持有效；全量替代仍未达标，未切换生产流量，也未清理旧服务、二进制、备份或中间资产。**

[本轮机器状态](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/state.public.json) · [本轮完整清单](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/manifest.public.json)。本轮新增证据严格按清单收录；下面的完整 R29 文档逐字保留。清单中的“完整包”指该包所有叶子、字节和 Merkle 关系完整，不代表整个运行场景已经合格。

### 五项目标的当前门槛

| 用户目标 | 已有实际证据 | 尚需完成 |
|---|---|---|
| KV2 正式存储、迁移和恢复 | R29 的当前 Mac full34 原始 31/31：17×2MiB、19 个历史版本、一次导出/导入、冷启动、HTTP 快照/恢复及三轮历史见证 | 当前 Linux/X230 同版实际回归；仍不能把单机 31 项外推到全部 OpenBao 功能 |
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

**这些终态报告尚不等于完整 source-import 资格。** 独立固定 `CONTROL/result.public.json` 的全字节回读及 21 个原始命令/流档案在本截点尚未完成；core 预期为 36,163 B / `484ebbd31e94213c526bbde8664a516658fbab48a273bace01396a6ca10adb72`。原 LAN prepare 请求 `483231ef…` 保留，未另建控制层，也未执行 prepare/live。

尾部第一次只读 admission 失 ACK；原错误完整保留。根仅批准原 job、原 offset16384、原 limit16384、原 key 的一次对账。它返回 `reused=false`，该返回 ID 的结果已收齐，**第一条失 ACK 的只读 future 仍记 UNKNOWN**；没有重跑 import，也未用新的返回值宣称旧 future 终止。[原部分证据](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-original-partial52/) · [终态范围包](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-terminal-scope5/) · [原只读错误](../../qa/evidence/20261104/r30-source2-custody-import-binding-and-auth-catalog-r1/importer-streams1-original-error2/)。

固定 core 元数据原结果页0也发生过一次传输超时，原错误和原ID恢复 GO 均保留；已收到同ID恢复成功的报告。独立 core 正文及原始命令仍待完整归档，不因元数据返回而提前取得导入资格。

### 3. X230：七个实际输入已绑定，隔离发布任务成功，传输尚未提交

七项输入包括当前 Linux server、normal build/result/61/groups 和完整源码 bundle/export receipt，全部绑定已有的实际 desktop 路径、size、SHA 和版本。原→prebind→ready 两阶段严格差分与三角色 AST 检查通过；合并根检查 **189 项**、66 个完整定义保持不变。该数量是 SOURCE 审阅数，不是产品测试数。

原隔离发布 `desktop/1a1ace08ffa-fc05-576b` 已收到精确 ACK，且权威为 **exit0/full/durable**，stdout1,514 B、stderr0。它仅创建并 compile 三个控制脚本及发布回执；原 streams 状态读取曾超时，随后同ID恢复为 completed/stored/inactive，原 stdout 的完整 text/hex/双EOF 已核对；原错误保留。四个固定文件的独立 info/whole body 与所有原观察完整归档仍在进行。**Relay 原请求 `9241a86d…` 尚未提交；X230 source-import/full34 都未合格。**

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

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R29：Mac 当前版本 34MiB 正式存储通过；LAN 源码与 AuthBus 输入闭环继续推进

状态截点 **2026-11-05T17:23:16Z**。产品仍固定为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**当前 Mac 的官方 OpenBao 2.7.1 对照 full34 原始 31 项已经全部通过，完整原始证据已闭合。完整替代 OpenBao 2.7.1 仍未达标；未正式切流，未删除旧服务、二进制、备份或中间资产。**

[机器状态](../../qa/evidence/20261104/r29-current-mac34-pass-lan-source-custody-and-auth-sdk-evidence-r1/state.public.json) · [完整清单](../../qa/evidence/20261104/r29-current-mac34-pass-lan-source-custody-and-auth-sdk-evidence-r1/manifest.public.json)。本冻结纳入 **16 个完整归档包、1,450 份包内文件、11,453,391 B、486 个 Merkle 子树**；另有 78 份根审、原始回复、调度与错误记录，以及状态和清单。整文件 SHA-256、Git blob 与目录 Merkle 均已核验。归档完成只说明证据完整，不将源码审查、文件传输或未执行项目升格为产品通过。

### 一、Mac 正式 KV2：当前版本取得实际迁移与恢复证据

唯一任务 `mac/1a1ac9bd07c-fc05-55cf` 为 exit0、output_complete、output_durable、terminal publication confirmed，stdout 297 B、stderr 0，实际耗时 **47.534 秒**。原始检查数为 **31/31**。wrapper、实际 prepare 哈希、官方 oracle、当前源码与当前 server 全部固定，运行前后源码和二进制不变，所有自有测试进程均已停止。

| 已证项目 | 当前任务的实际结果 |
|---|---|
| 数据规模 | 17 个 2MiB 有效版本，逻辑 payload **35,651,584 B**；每阶段包含 19 版历史。 |
| 正式存储 | active native-v6，`heptabao-state-records-v6`，profile `bounded-native-record-state-v6-paged`；native KV2 logical payload **35,655,894 B**。 |
| 迁移 | 原 export 与 import 各一次，均真实完成、未重试；原单操作预算 360 秒。迁移 bundle **35,658,766 B**，SHA-256 `eb60c409df6d00b691ee8797605ef5e827671be1d40c9ea32595e83393997b74`。 |
| 历史与持久化 | import 后、目标冷重启后、快照恢复后共 **3 × 19 = 57** 个 native storage witnesses，payload、删除与销毁状态及时间字段无损匹配。 |
| 快照恢复 | 实际 HTTP snapshot 成功；archive **9,018,321 B**，SHA-256 `baffe549dee36624eda867aa62e94f9b47760315aafd8a3805efd213d9417273`；一次真实 restore 后冷读历史一致。此数值与旧版本 9,007,344 B 的历史结果分别保存。 |
| KV2 语义 | 软删除 payload 可准确 undelete；destroyed payload 仍缺失；data 与 metadata CAS 拒绝及成功计数均按原断言验证。 |
| 原始读链 | 8 个原观察操作全部 completed/stored/inactive；16 个 immutable pages 全量重组，summary 91,727 B、result 1,122 B、driver stdout 209 B、两组 stderr 均完整保存。 |

完整 live 包 [mac-current-full34-LIVE-complete123](../../qa/evidence/20261104/r29-current-mac34-pass-lan-source-custody-and-auth-sdk-evidence-r1/mac-current-full34-LIVE-complete123/manifest.public.json) 含 123 文件、2,235,741 B。根审 [177 项运行契约](../../qa/evidence/20261104/r29-current-mac34-pass-lan-source-custody-and-auth-sdk-evidence-r1/root/r29-mac-current-full34-root-contract-review.public.json) 与 [193 项原始读链](../../qa/evidence/20261104/r29-current-mac34-pass-lan-source-custody-and-auth-sdk-evidence-r1/root/r29-Mac31-root-original-read-chain-review.public.json) 分别通过。作者的 648 项离线证据核验及其最初 basename selector 错误也原样保留；根审最初将已解析 request 对象传给字节比较器的输入错误另存，仅换回同一原始 request 字符串后通过，未修改或重跑产品。

原 31 项、HTTP 15 秒、migration 360 秒、native worker 5 秒、外层 1800 秒均未放宽。专用系统 Git 读取器仅绑定已观察的 `/usr/bin/git`、完整身份、118,640 B、SHA、root:root、0755 与 nlink78，通用单链接 guard 未改。原 Mac standalone Popen 的异常清理限制仍存在；本次通过依赖实际 owned-processes-stopped 证据，不声称具备 Linux affine Owner 的所有保证。

### 二、LAN 原始源码、导出记录与传输前置证据

| 项目 | 本冻结已证 | 仍未授权或未通过 |
|---|---|---|
| 九份 LAN 控制源码 | 9 份源共 357,306 B；9 infos、25 body chunks、34 个返回 operation IDs 全部关闭且原始内容完整。完整包 415 文件；根审 **958 项**。 | 这些源只完成 compile-only 发布，当前三机 98+12 回归尚未执行。source3 最初无 ACK 的只读请求仍保留 UNKNOWN；同 typed request/key 的后继返回 reused=false，不能据此抹去原 UNKNOWN。 |
| 原源码导出 | 原 ROG export 的 27 份 command records 与 54 份 streams，合计 **81 文件/28,080 B**，经六个固定只读批次取齐；根审 **411 项**。25 个命令 exit0，两个 partial-config 查询按原逻辑 exit1，27 个子进程均已回收、无残留。 | 未重跑 exporter 或 Git 命令。导出完整不等于目标源码已导入。 |
| 两个 source-carrier 输入 | canonical full bundle **22,320,862 B** / SHA `bb014971cb243db71e07d04b862fbba2436ceec09d2c1bafa707e4aa558bf5ac`；原 export receipt **39,692 B** / SHA `47feb984dbda306b523071e09107ecade8bda10e712d74e5116a58d164eb027b`，实际原版本已绑定。 | importer 的目标元数据尚待实际传输闭合后绑定。 |
| source-carrier inert | 唯一 `desktop/1a1aca557a2-fc05-561b` exit0/full/durable；3 源只 compile，7 observers/11 pages 闭合，独立源码全文/full9 与 receipt 核验通过，根审 **161 项**。 | 未执行 Git、编译器或产品。receipt 自身 full9 来自独立 info/body，publisher 未输出自身 identity；不补造该字段或汇总 FD ledger。 |
| source-carrier relay | 唯一 `desktop/1a1acb4e995-fc05-567a` 的独立 external intent 与原 ACK 已纳入，typed request/digest/无损 fingerprint 等根审 **9 项**。 | 本冻结尚不纳入完整 relay 结果、目标两文件与原命令闭环；不据 ACK 声称导入、X230 或 HA 通过。 |

ROG normal5 的五个实际构建资产及完整传输闭环仍沿用 R28 的已证记录。旧 Mac/ROG 失败、旧物理三机 91/98 与 post-cold 0/12、旧 X230 relay UNKNOWN、旧 H2 UNKNOWN 均保留。当前 retained-A 修复必须以真实跨机断主、自然重新选主、ReadIndex、持久化和重启结果验证。

### 三、AuthBus：完整 SDK 输入已取得，真实 owner 与凭证链仍需攻克

13 个固定 SDK 正文原操作已全部完成，共 **682,650 B**：loader 6,047 B、selector 673,468 B、registry 3,135 B。根审 **227 项**确认原请求、原 ACK/status、原 immutable pages 和全文身份；第 11 次原 page 超时、第 12 次原 status 超时及原 ID 对账记录均保留，没有业务重放。

实际源码说明 loader 的 onlyPluginIds 参数不能单独证明 registry 是排他的候选集合；selector 的 auto 路径会调用全部注册候选的 supports；registry 的 registration owner 与 harness.pluginId 是两个独立字段。因此既不能移除 ordinal22，也不能强制 Codex 或把静态源码阅读当作实际 owner 选择。

新 catalog reader 源码仅从既有 **195,155 B 私有 capsule** 投影两个原 ordinal 的受限公开 ID/root；三个原值哈希、原 namespace/composite 判据、全部原 guard、5/60 秒、9 FD、原 metadata/read/output cap 均保留。这明确是私有 capsule 读取，不是后续 credential-free SDK 诊断。根审 30 项 AST 与 16 项原来源/精确请求绑定通过。

Mac 主机窗口在全部原 8 observers 关闭后正式交给 Auth，根审 20 项交接记录已封存。catalog 唯一原任务 `mac/1a1acb902f1-fc05-5693` 的 intent 与 ACK 已整件保存、根审 8 项绑定通过；**本冻结不包含 catalog 的实际输出或后三个公开 info 的结果**。条件 GO 仅允许该固定读闭合后依次读取三个已指定公开路径的 file_info，正文须再绑定实际版本。265,740 B 限制的是拟读取正文合计，不冒称 file_info 内部 whole-SHA 也受此字节上限限制。

后续 SDK observer 仍为 unbound SOURCE：公开配置等价性、全部候选和 owner 代码 pin、实际 OS sandbox 拒绝证据、完整 parent/worker 绑定仍缺失。没有授权或执行 SDK import/loader/supports/factory，没有 J3160、provider/model/refresh/quota 修改，也没有新 credential fixture 重放。可信 issuer/CA、AppRole、TLS、KV、Policy、实际续期延长与撤销仍未取得完整资格。

### 四、五个最终门槛

| 门槛 | 本次状态 | 下一项必须取得的证据 |
|---|---|---|
| KV2 正式迁移/恢复 | **当前 Mac 原 31/31 通过**；正式 native-v6、full34、完整历史、cold/snapshot/restore 已证。 | X230 相同当前版本的正式迁移、恢复与回滚；跨机持久化场景。 |
| HA | 当前源码与资产前置证据完整；真实三机回归未完成。 | Mac、ROG、Pocket4 原 98+12，真实断主、自然选主、ReadIndex、持久化与重启。 |
| AuthBus | SDK 原输入完成；catalog 原任务已提交一次；实际 owner 和可信凭证链未通过。 | 实际可信凭证来源、AppRole/TLS/KV/Policy、有效续期和撤销，保留原候选与策略。 |
| 逐台切换 | 未正式切流。 | 每台真实凭证读写、重启、回滚及真实消费者证据；完成所有客户端与备份迁移。 |
| 旧版清理 | 未删除。 | 前四门槛与全部客户端/备份路径完成后，才清理旧服务、二进制和可再生资产，只保留最新版服务。 |

官方 2.7.1 源码的静态 API/声明目录继续只作差距地图，不作 runtime parity 分母。JWT/K8s/OIDC/MFA、外部租约副作用、PKI/ACME/EAB/KMS/Transit custody、rekey/recovery/root generation、插件/namespace/workflow/control-group 等尚未验证或未支持的 owner，仍是完整替代的独立门槛。Mac 的 31 项成功不能代替这些证据。

### 五、冻结、历史和继续执行

本检查点以 R28 `eeeb22dc2804cf5452852ab6caa309df0f67a335` 为唯一父提交，保留原 19,598 份非文档叶项；仅更新本文件与公共索引，新增不可变证据。下方保留 **R28 完整文档原始字节**，索引也保留旧原始整数 token；没有将历史失败、UNKNOWN 或缺失的原 ACK 改成通过。

继续工作使用两个指定 Runtime 窗口，每线最多一个调用/自有 future；根保持 0 Runtime。每次新 dispatch 均先单独完成外部 exact intent，再唯一提交、保存原 SDK ACK 后解析；错误或 UNKNOWN 只对账原身份，不换 key、重置预算或重放业务。当前两线只继续原 source-carrier relay 与原 catalog/固定公开 infos，具体 importer、三机 HA、X230 和真实凭证执行还需完成各自实际输入绑定。冻结后新结果放入后续检查点。

---

## 历史原文：R28 完整保留

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R28：原 LAN 发布确认、normal5 实际传输与 Mac 34MiB 前置输入

状态截点 **2026-11-05T15:59:15Z**。产品继续固定为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**完整替代 OpenBao 2.7.1 尚未达标；未正式切流，未删除旧服务、二进制、备份或中间资产。** Mac 与 ROG 已有 normal61 的实际通过证据；当前34MiB、物理三机HA、官方CLI和真实凭证切换仍分别需要证据。

[机器状态](../../qa/evidence/20261104/r28-original-lan-closure-normal5-copy-and-mac34-prerequisites-r1/state.public.json) · [完整清单](../../qa/evidence/20261104/r28-original-lan-closure-normal5-copy-and-mac34-prerequisites-r1/manifest.public.json)。本冻结纳入 **15 个完整归档包、734 份包内文件、7,575,816 B**，另有 33 份根审、原始 SDK 与调度记录，以及状态和清单。全部文件按整字节校验 SHA-256、Git blob 与目录 Merkle；归档完整不改变 SOURCE-only、partial 或未达标的分类。

### 本轮实际推进

| 项目 | 已证事实 | 仍保留的边界 |
|---|---|---|
| LAN 九源原发布任务 | 原 `1a1ac1641eb-fc05-521f` 已由完整远端 request、原 typed digest、477,056 B stdin 哈希绑定。原任务 exit0/full/durable，stdout5,991 B、stderr0；九份公开源357,306 B只作 create-only/compile-only 发布。原 receipt7,519 B独立全文与stdout语义完全一致。根审114+67+45项。 | 原 process_start ACK仍未收到，未补造ACK或重发。九份源的全部独立读回尚不在本冻结；没有 prepare、启动产品或三机HA实测。 |
| normal5公共构建资产 | 原任务 `1a1ac4bdf19-fc05-5366` 仅提交一次，exit0/full/durable。五个文件共110,287,359 B；源身份前后不变，接收端同FD整文件读回，五个独立目标file_info的大小、SHA、权限及完整版本全部吻合。 | 这是已完成的文件传输，不是目标源码导入、X230验证或HA通过。消费者尚未执行。 |
| normal5命令与清理证据 | 三个实际子进程均exit0、已回收、无残留；远端完成已证，没有cleanup UNKNOWN。三份命令记录、五份实际保存的stream、intent和preflight共18,391 B全部原文取齐。根审214+67项。 | sender stdout原本是到receiver stdin的二进制管道，没有捏造不存在的独立stdout文件；没有宣称汇总FD账本。 |
| Mac当前34MiB前置输入 | 当前原31项QA源码、Macnormal61、保留server及独立官方2.7.1 oracle绑定均已审。六个原file_info全部completed/stored/inactive且原payload完整，根审138项；无传输错误。 | `/usr/bin/git` 实际是root:root、0755、78个硬链接，原通用单链接封装会拒绝。封装原件未改、ready=false；专用系统Git读取器仅获源码提案许可。尚无inert/prepare/live提交。 |
| AuthBus公共SDK源 | 冻结内13个原请求已完整10个：loader6,047 B与selector连续前缀589,824 B。04–10七条原SDK完整重建，根审363项。 | 第11 native read已closed，但原87,804 B payload只有首16,384 B归档，五页缺失；12–13未提交。selector及registry全文、实际selected harness owner均未证明；没有执行SDK。 |
| AppRole续期语义与测试 | 当前固定非周期AppRole的空JSON续期、整数expiry、token/accessor/creation链与产品源码一致。修正模拟时钟并增加max饱和及renew-only错误accessor后，单次纯fake实际10/10通过；原候选与产品字节未改。 | 200不保证expiry延长；同秒或最大寿命饱和可合法delta0。fake没有真实HTTP200/403/204或凭证，实际续期、撤销、inverse与关闭仍待完整链验证。 |

### 原任务恢复没有改变历史错误

LAN最初的process_start MCP timeout、无ACK记录和外部提交意图全部保留。其后只读取原任务元数据、版本固定的原request和stdin，再取得原authority及原输出。实际匹配的typed digest为 `5df3e472d540fcee1b5d2534607d051900f9abd52f979f156e822f7a752802f0`。该恢复证明原效果身份与完成，不代表已经取回丢失的ACK。搜索预览和时间接近未被单独用作任务身份。

normal5原receipt读取 `ba463b00bbd59bf90f034f0c81c9c2f58cd858cec2683e6b240047504571f544` 首次status同样MCP timeout；随后同ID恢复，四页重建25,216 B原SDK payload，得到18,565 B原receipt，未重新发native body read或relay。SDK第10状态超时及第11两页超时也都保留，没有把未取齐的原结果计作完成。

### Mac34MiB的具体门槛

六项实际输入为官方2.7.1 binary与发行归档、当前保留HeptaBao server、实际Homebrew Python、`/usr/bin/git` 和 `/usr/bin/openssl`。原始不安全整数inode及纳秒值均按十进制原值保留，不能经过JavaScript浮点转换后再绑定。五项满足通用单链接检查；Git的78链接是已知输入兼容性问题，不是读取失败或UNKNOWN。

允许后继仅对固定Git路径新增专用系统工具读取器，固定其实际118,640 B、SHA `b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9`、root:root、0755、exact nlink78与完整身份；通用 `fixed_file` 字节保持不变。仍须检查原名、FD、EOF、整文件哈希及前后身份。没有证据证明Git是shim，也未盘点78个alias，不作这些推断。专用后继源码、发布与执行不在本冻结。

原31项业务检查、HTTP15秒、迁移360秒及原outer1800秒不变；独立prepare使用新的60秒预算。Mac原有Popen兼容分支保持，不能冒用Linux affine Owner或有界失败清理结论。旧Mac正式34MiB记录仅供来源核对：逻辑payload35,651,584 B，实际压缩snapshot9,007,344 B，不能称为34MiB压缩归档通过，更不能转移为当前4e808合格。

### 接下来按原门槛继续

1. 闭合LAN九源独立读回，绑定已独立核验的normal5，再分别审查prepare与Mac/ROG/Pocket4原98+12真实断主、自然选主、ReadIndex、持久化和重启。
2. 完成Mac专用Git源码绑定后，依次create-only发布、只读prepare、原31项当前34MiB迁移/save/restore/cold-read/history/CAS验证。X230的同类正式验证仍须其七项输入及原UNKNOWN隔离门槛。
3. 恢复SDK第11原结果页、取得原12–13，再核实实际selected owner；保留enabled插件集合及provider/model/refresh/quota，不靠删插件通过guard。
4. 完成原源码导出81份命令/stream记录、bundle carrier与目标canonical import；独立验证CLI/H2窗口、每台真实凭证链、重启和回滚。
5. 证明所有客户端及备份路径已迁移后再正式切流和旧版清理。当前原生产、旧OpenBao和旧HeptaBao资产均保留。

本冻结时，lineA已获准继续LAN只读回收，lineB已获准按原ID/offset恢复SDK缺页；稍后取得但不在清单中的结果进入下一检查点。下方完整保留R27及全部更早原文，不能把历史截点里的pending误当成本节当前状态，也不能把本节的新事实反写成过去已知。

---

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R27：原始读取恢复、发布回执定位与当前版本验证源码

状态截点 **2026-11-05T15:01:07Z**。产品仍为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**完整替代 OpenBao 2.7.1 未达标；没有正式切流，也没有删除旧服务、二进制或备份资产。** Mac 与 ROG 的 normal61 已有原任务实际证据；它们不能替代当前 34MiB、物理三机 HA、官方 CLI 或真实凭证回归。

[机器状态](../../qa/evidence/20261104/r27-original-read-recovery-and-current-source-closure-r1/state.public.json) · [完整清单](../../qa/evidence/20261104/r27-original-read-recovery-and-current-source-closure-r1/manifest.public.json)。本轮包含 **12 个完整归档包、321 份包内文件、5,031,781 B**，另有 45 份根审、调度意图及原始回执，再加状态与清单。所有纳入分包均整字节验证 SHA-256、Git blob 与目录 Merkle。完整归档中的 partial、SOURCE-only 和 UNKNOWN 保持原分类。

### 本轮真正闭合的证据

| 项目 | 已证事实 | 尚不能据此声称 |
|---|---|---|
| normal5 控制源发布 | 原任务 `1a1abd1f635-fc05-50c9` 为 exit0 / full / durable；3 个公开源及 receipt 的 4 个独立 info、4 个全文全部补齐。79 份实际记录完整，根审 184 项，早先 24 份原记录逐字不变。 | 五项正式产品资产尚未传输；relay 精确请求虽已审，其提交仍暂停。 |
| 当前规范源码导出 | 原任务 `1a1abe371de-fc05-5122` exit0 / full / durable 保持。原 `79cb…` body operation 按同 ID 恢复，4 页重建 53,354 B 原 SDK payload，得到 39,692 B 原 receipt；根审 93 项。 | 不意味着全部 27 个命令的独立记录和 stdout/stderr 已归档；81 份文件的 6 批固定读取仍未提交。 |
| 导出 bundle 独立身份 | 原 `ff387…` file_info operation 的首次状态超时保留；同 ID 恢复到 completed / inactive，原 609 B payload 完整。文件 **22,320,862 B / `bb014971cb243db71e07d04b862fbba2436ceec09d2c1bafa707e4aa558bf5ac`**，完整版本和九项身份字段与发布 receipt 一致，根审 16 项。 | 不能跳过剩余导出日志、carrier、目标端导入或独立读回；没有重新 export 或另起 file_info。 |
| Mac 公共 SDK 源码 | 13 个原固定读取中，归档内 **3 个完整**：loader 6,047 B、selector 前两段共 131,072 B。第 3 条最后 5,883 B 原结果尾页由根端按同 ID 取回；作者 24 项吸纳核验与根端原件逐字一致。 | selector 与 registry 全文未齐；没有导入/执行 SDK，没有证明五个 agent 的实际 selected owner。截点后 04–13 获准继续，但其后来结果不在本冻结内。 |
| 当前官方 2.7.1 CLI Phase B 源码 | 新后继绑定当前 4e808 / normal61；原 44、7、9 与新增 same-root 1 分开核对。严格 8+4+4 hunks，4 份原 QA 源及控制器不变；作者 143 项静态检查、14 个选定 receipt predicate case 和根审 39 项均通过。 | 仍是 SOURCE-only：4 个产品槽为空，ready=false，prepare/live 未授权，5 个当前 CLI case 未运行。旧 2 个 B01 UNKNOWN、6 个 fence 和原预算保留；不能冒充 34MiB 或 HA 通过。 |

导出来源的 canonical commit/tree、3,763 个提交历史、无 shallow/partial/alternates/grafts 的发布证据已进入原 core 审查；目标端独立导入仍是单独门槛。bundle 的 file_info 是全文件哈希和身份观察，不是已经完成目标端 source import。

### LAN 源发布：丢失 ACK 仍须绑定原任务

九份公开控制源的 create-only / compile-only 请求 `70f27390d318755075562482091b3bf27946b37d` **只提交过一次**，key 为 `heptabao-4e808-postcold-inert-r1-57cb2b31-7ee5ee82`，原 outer timeout 60 秒。process_start 返回 MCP timeout，未取得 ACK。原错误、提交前外部 intent 和精确请求均保留，不能由此推断未发布、已失败或已清理。

原请求的 typed RequestBinding 摘要已用本轮 normal5 的实际 ACK 作正控核验，目标 digest 为 `5df3e472d540fcee1b5d2534607d051900f9abd52f979f156e822f7a752802f0`。这证明原请求的定位摘要，不证明目标任务已执行。

durable inventory 两次只读观察为 8,513 与 8,542 条 desktop 身份；旧 opaque cursor 返回明确的 snapshot-changed 拒绝，原件保留。目录项不含 key/digest/argv，而且 process_status 本身不向调用者返回原 key/digest。因此时间接近、候选 ID 或单独的 exit0 都不能作为原请求身份依据；没有拼造 cursor、补造 job ID 或重提 process_start。

随后在已观察 worker jobs 根下，对固定时间前缀的 `request.json` 作原 digest 的有界内容搜索。实际扫描 9,800 个 entries、103 个合规文件、341,337 B，在所选授权 regular/single-link 文件范围内完整结束，只返回一个路径：

`1a1ac1641eb-fc05-521f/request.json`

搜索先匹配完整行，再返回行首 512 B；这条预览被截断且不含 digest。它仍只是**待核候选**，不是完整请求证明。截点归档内仅有候选 request.json 的独立 file_info ACK 和首次同 ID status timeout，原 operation 为 `db7ae88f198bd69bb3cbde693ce78fdf7618649ebee7096d26e28c478ba28ec1`。其后同 ID 恢复、版本固定全文、stdin 独立哈希及原 job authority/streams 必须另行归档。

实际原 request 需要与已审 executable/args/cwd/timeout/空 env 归一规则及 digest 对齐；原 stdin 应为 477,056 B / `2fa460dc1a032ca1f1e453dd4845e80a8e937dcc47e6bc5477b2301fa267f610`。身份和终态未闭合前，normal5 relay 继续 HOLD，LAN prepare/live 均为 false。

### AuthBus 修复边界

完整 loader 证明实际入口为 `loader.t`，并且显式 `onlyPluginIds` 会影响 scoped-load 集合，即使 scope 字符串为 all。删除不符合 npm-root guard 的 enabled plugin 会改变加载输入；不能由此证明它未被选用或不相关。

原 Mac WAL 任务的 `actual_finite_harness_code_root` 失败保持已知 exit1 / full / durable；原 guard、私有 capsule 和清理事实保持不变。当前只有源码读取与审查，不能把 configured model 当作实际 selected harness，也没有接触 J3160、provider、refresh 或 quota。原续期增量仍为未绑定 SOURCE：同一 token 的前后 lifetime/expiry 与真实 renew/revoke 尚未验证。

只读传输调度在截点明确改为最多两条读线、每线最多一个 native read future：原 LAN 身份恢复与原 SDK 固定读取可独立推进。每条仍须完整原 payload、hash/version 和 completed/inactive 后才进入下一 native read；保留原 key、原 ID、原 offset，二次未明则停止该线。这个调度变化不修改任何产品测试期限、业务请求或资格门槛，也不授权新的产品 process_start。

### 五项用户门槛的当前结论

| 门槛 | 当前判断 | 下一项实际证据 |
|---|---|---|
| KV2 正式存储 | 当前源码已有 active-native 全历史写入和 native-large HA 路径；旧文档所说的缺失不能直接套到当前代码。当前 4e808 的完整 34MiB 正式迁移/恢复仍未运行。 | 在已验证当前二进制及精确官方 2.7.1 oracle 下，保持原 31 checks，完成迁移、快照、恢复、冷启动和回滚。单机这条验证不以 desktop 传输或物理 LAN 运行作为语义前置。 |
| 物理 HA | 当前 Mac / ROG / Pocket4 的 98 项及单列 12 项冷启动验证尚未执行。历史 df026 的 91/98 失败仍保留。 | 原真实断主、自然选主、ReadIndex、持久化与重启回归；不得强行选主或延长期限来补通过。 |
| AuthBus | 公共 SDK 3/13 读取已闭合；selected owner、可信 issuer/cluster/CA/AppRole/Policy 及真实续期撤销未闭合。 | 完成剩余原源码读取，建立精确运行闭包与可信凭证来源，再验证原真实凭证流程。 |
| 逐台切换 | 没有正式切流。Mac5/ROG6 是有界旧观察；Pocket4 manager 与 X230 当前 consumer 仍有缺口，ROG disabled generation203 保留。 | 每台真实凭证读写、重启、回滚和原样恢复完成后才切流，并核对所有客户端与备份路径。 |
| 旧版清理 | 条件未满足，未删除旧 OpenBao/HeptaBao 服务、二进制、备份或可再生资产。 | 所有客户端、当前备份路径及恢复证明完成后，再执行明确的旧版清单清理，仅保留最新版服务。 |

官方 2.7.1 的源码路径/字段枚举仍不是运行时全量兼容分母。Native auth/secret/lease、外部系统副作用、PKI/KMS/Transit custody、rekey/recovery/root generation、插件与管理工作流的未资格范围保持原记录。没有通过移除 guards、缩减原断言或混用历史版本结果宣告全量替代。

---

## 以下为 R26 及更早正文的逐字历史保留

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R26：KV2 路由复核、续期证据增量与原始读取归档

状态截点 **2026-11-05T14:04:34Z**。当前产品仍是 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / `eba5e650bd080b8ad41ea52a2bc68867f541d255`，Draft PR #159 未合并。**完整替代 OpenBao 2.7.1 仍未达标；逐台正式切流和旧版清理条件均未满足。** 本轮补齐可核查的读取原件、修正部署与续期验证源码，不把源码审查计作真实凭证、恢复或 HA 通过。

[机器状态](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/state.public.json) · [完整清单](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/manifest.public.json)。本轮冻结 **11 个完整归档包、791 份分包文件、6,226,961 B**，另含根审、独立交叉审查及上一轮发布回执。文件完整字节、SHA-256、Git blob 与目录 Merkle 均核验。包内的“部分实际结果”仍是部分结果；SOURCE-only 仍未运行。以下以截点所列不可变对象为准，截点后的同 ID 对账进入下一轮。

### 已取得的实际证据与边界

| 项目 | 已证事实 | 仍缺的证据 |
|---|---|---|
| Mac normal61 原始日志 | 原61项通过保持；47个读取操作的560份原件完整，47 ACK、47 closed status、135成功 immutable页重建；根审2237项均通过 | 第一份Cargo日志27/27块完整；第二份20/27块、327680/438208 B，余7块未提交。两次历史直接RPC不确定性和一个原结果页超时原样保留 |
| 当前 normal5 控制源码发布 | 唯一任务 `1a1abd1f635-fc05-50c9` exit0/full/durable，stdout1520 B/stderr0；三份公开源码仅发布并compile检查。sender独立info闭合；根审57项、peer175项 | 其余3个独立info与4份正文均未提交；无relay GO，无产品或LAN执行资格；该发布器没有逐FD台账，不补造台账 |
| ROG 当前 canonical 导出 | 唯一任务 `1a1abe371de-fc05-5122` exit0/full/durable，完整534/0双流；原终端报告exported、owned stopped与原期限内发布；独立回执info为39692 B | 本截点归档中的原body-read79cdb…尚未取得正文，2次status与1次page超时原件全部保留。bundle-info与27命令的81份记录/流未提交；carrier/importer仍未绑定 |
| Mac SDK 元数据 | 三份公开loader/selector/registry的独立版本、大小和SHA与原捕获一致，3操作均closed，根审35项通过 | 13条固定正文请求只冻结未提交，总682650 B；未执行SDK，未观察5个agent实际selected owner |
| 控制器连接 | 首次本地effective_config也超时，后一次仅本地公开DTO已返回；两次原SDK分开保存 | 本地DTO不证明任何目标主机可达，不自行关闭原body-read。只释放原ID对账窗口，未重发exporter或binary_read |

[Mac原件根审](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/mac-cargo47/root-review.public.json) · [normal5根审](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/partial-and-renewal/normal-root-review.public.json) · [export读取链根审](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/partial-and-renewal/exporter-root-review.public.json) · [连接复查](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/runtime-connection/recheck-observation.public.json)。

### 本轮已完成的源码工作

**KV2 当前路由校准。** 对当前canonical的13份文件逐字核SHA并作重点路径检查，确认active-native全历史写入与native-large HA接入代码已经存在。普通小JSON active-native导入仍受root/单节点限制；large路径包含HA读证明、finalization、提交与最终交付边界。当前large上限为64 MiB包、4 MiB记录、4194304语法节点、深度128。旧文档中的“尚无active writer”“HA一律拒绝”等描述不能作为当前缺失实现的证据。该结论仅为源码路径检查，当前候选34 MiB迁移、save/restore、cold读与回滚实际闭环仍待执行。[完整路径说明](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/current-kv2-route-map.public.json)。

**续期验证增量。** 四个最小hunk把原单次token文件读取移到KV观察前，各增加一次pre/post lookup-self；绑定同一token、accessor与creation identity，核TTL/实际到期时间。原空JSON renew、revoke204与撤销后403保留，原HTTP10、共享900秒等预算没有扩展或重置。到期时间相同或下降时先完成原撤销和两次inverse，再报告未证延长；200响应本身不够。公开报告仅含数值、枚举和身份一致布尔，不导出token或accessor。作者8组纯mock、独立28项AST检查及根四hunk正逆核验通过；**未运行完整模块、未建立新运行根或请求，BINDING_READY=False，selected-owner问题仍未解决**。[候选合同](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/authbus-renewal-unbound-source/CONTRACT.public.json) · [独立审查](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/authbus-renewal-independent-peer/review.public.json)。

**Mac外接盘部署提案修正。** Mac服务、二进制、配置、数据和备份提案统一落到 `/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-authbus-registration-r1`；home下的client credential generation位置保留。历史T5 UUID已绑定，12个Mac投影字段变更，其他主机提案不变。该修改仍需真实新根、issuer/cluster/CA/AppRole/Policy和注册回执验证，不能以历史磁盘观察替代当前准入。[根审](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/authbus-p01-t5/root-review.public.json)。

**X230 当前候选运输源码。** 五份源码已完成当前候选迁移与原差分正逆核验，原期限保持；新的relay在新ROOT建立前、端点启动前及清理后检查固定旧UNKNOWN命名空间与marker，三个只读FD保持至原收尾。该保护是顺序held/named观察，未宣称跨所有指令的原子保留。7个实际输入槽仍为空，无冻结可执行请求或GO；旧relay `1a1aa57458d-fc05-4156` 仍为UNKNOWN。[根审](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/current-x230-source/root-review.public.json) · [独立围栏审查](../../qa/evidence/20261104/r26-kv2-source-renewal-and-original-read-closure-r1/current-x230-source/fence-peer-review.public.json)。

### 五道门槛仍按实际结果判定

1. **KV2：** 当前4e808的正式34 MiB历史迁移、持久化、snapshot save/restore、重启cold读与回滚必须全部实际闭合。
2. **HA：** 当前Mac/ROG/Pocket4真实断主、自然选主、ReadIndex和重启仍未运行；上一候选df026的物理LAN是91/98、post-cold0/12失败，保持失败，不能由两平台normal61替代。
3. **AuthBus：** 原Mac隔离WAL任务为明确exit1，触发actual_finite_harness_code_root；失败原件与清理已完整归档。公开诊断显示两个enabled owner中的一个不满足原命名空间条件，但5个agent的实际selected owner仍未知，不能据此跳过检查。还需不依赖J3160的真实可信凭证和完整TLS/AppRole/KV/Policy/续期/撤销证据。
4. **逐台切换：** 各机当前真实凭证读写、重启及回滚尚未全部合格，Pocket4 manager与X230当前消费者范围仍待核，正式流量保持未切换。
5. **旧版清理：** 所有客户端、所有备份路径和OpenBao2.7.1原生功能范围尚未全部完成迁移。旧服务、二进制及中间资产暂未删除；清理只在这些条件满足后执行。

官方2.7.1源码清单已固定，但词法423声明、720操作等数量不是运行兼容率分母。JWT/Kubernetes/OIDC/MFA、外部动态租约与副作用、PKI/外部密钥托管、系统生命周期和插件等原生owner门槛仍列在机器状态中，既有保护不得移除来制造通过。

### 接续顺序

先完成原79cdb…同ID对账并保存原页，再分配有界读取窗口：三份SDK的13条固定正文、normal5剩余独立info/正文、当前export bundle/原命令流。随后完成canonical carrier/import、LAN准备、X230实际绑定与正式34 MiB/凭证/恢复验证。任何原UNKNOWN不换key重放，产品与QA工具资格不互相转移，原期限不放宽。本检查点完整保留上一轮正文及JSON历史。

---

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R25：两平台 61 项核心通过；Mac 准入失败已定位，当前产物与源码分发继续推进

状态截点 **2026-11-05T13:20:28Z**。当前候选为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`，树 `eba5e650bd080b8ad41ea52a2bc68867f541d255`。**完整替代 OpenBao 2.7.1 仍未达标；没有正式切流，也没有清理旧服务、二进制或备份资产。** 本轮仅追加证据并更新两个状态文档，不修改产品源码。

[机器状态](../../qa/evidence/20261104/r25-normal61-harness-diagnostic-source-distribution-r1/state.public.json) · [完整清单](../../qa/evidence/20261104/r25-normal61-harness-diagnostic-source-distribution-r1/manifest.public.json)。本轮冻结 **12 个完整包、431 份分包文件、6,902,491 B 原文**，另含根审、精确操作授权与上一轮发布回执。全部文件核对完整字节、SHA-256、Git blob 和 Merkle；已缓存的同一不可变原件重新计算哈希，不冒称全部再次联网获取。截点后任务结果进入后续检查点。

### 本轮新增实际证据

| 边界 | 本轮能证明的结果 | 仍未证明的范围 |
|---|---|---|
| ROG normal61 | 原任务 `1a1ab76cee8-fc05-4e13` exit0/full/durable，61 个独立实际名称、48 个自有命令收尾；根审147项及18项预检补证通过 | 其余完整命令流和大 Cargo 日志独立归档尚未全部完成 |
| Mac normal61 | 延续 R24 已核的61项；第一个完整 Cargo 日志 440,534 B 与构建回执一致；两份日志已恢复47/54段 | 第二份日志余7段；旧直接读取异常仍原样保留 |
| QA12 工具分发 | 原任务 `1a1abb3fe28-fc05-4fef` exit0/full/durable，12文件/4,892,547 B 的发送与同FD接收回读哈希全部一致，3自有进程退出 | 独立目标文件元数据已完成7/12，余5项；工具身份df026不授予产品4e808资格 |
| 当前源码 exporter 准备 | 原任务 `1a1abb9785a-fc05-5029` exit0/full/durable；源码15,364 B与995 B回执完整独立回读；6只读操作、8原始页闭合，根审78项通过 | 后续源码导出仅已单独放行，本冻结包不含导出ACK、实际bundle或完整导入 |

ROG 新增“同一原始A计划在B之后重新发布”回归命令用时约0.777秒；暖态/冷态发布分别85/92毫秒，原每请求15秒上限未改变。它与 Mac 的同名回归共同验证当前测试修正，不能覆盖未执行的物理多机、客户端或备份门槛。

QA12 第7份独立 metadata 的首次只读 operation_start ACK 超时被保留；获准按同key、同typed arguments对账后返回 **reused=false**，新获得的操作身份及完整原始payload已经闭合。没有把该结果称作“找回原已执行操作”，也没有推断首次超时请求是否执行。原两个直接 file_info 超时不被覆盖。

### Mac AuthBus：失败闭合，具体拒绝条件已由只读诊断证明

原当前运行 `1a1abb090b9-fc05-4fc5` 的完整91,043 B stdout、空stderr和权威终态均已核对：**exit1 / InputRefused / 无超时**。它在输入准入阶段停止，0 owned worker phases、0生产服务操作；2个外层子进程、1个嵌套diskutil和28个外层描述符均闭合。之前的捕获成功，7连接、11游标、46捕获描述符与6公开代码描述符也已关闭。完整失败48件包和146项原作者无损复核、14项独立绑定检查均保留；实际失败未改写成通过。

随后仅运行一次精确只读诊断 `1a1abcc26f6-fc05-50a4`，读取同一已保留的195,155 B私有捕获文件。诊断 **exit0/full/durable**，输出8,353 B公开结果，9描述符关闭、72元数据查询、4次读、约0.005913秒，未重跑捕获、SDK、登录、刷新或任何业务：

- 原注册表含75个插件、2个启用的harness owner。
- 原第一个owner（registry ordinal22）的标识类型/正则、绝对路径和规范化路径条件全部为真，唯一失败项是 **rootInOriginalNpmProjectsNamespace**。
- 第二个owner（ordinal68）与已固定的Codex路径一致，全部原条件为真。
- 五个agent的实际选择器均未执行；它们实际选中的harness仍未知。不能据此宣布第一个owner未被使用，或删除这项检查。

根审14项绑定和原96项校验复跑通过。根审还发现诊断说明字符串写成loader.r；原固定worker实际调用 **loader.t → selector.o → registry.r**。该文字误差单独记录，原source/stdout保留，不触发重跑。下一步读取已经固定路径、长度和哈希的三个公开SDK原件，用实际调用链形成有界准入修复。

### 当前分发、H2与物理LAN准备

当前normal5源码已绑定本轮ROG的5份真实产物，合计110,287,359 B。根审95项：只改21个固定绑定字面值、8个diff hunk，其余源码和42个定义不变。精确inert准备已放行，完整实际准备包尚未纳入本轮；relay未放行。

LAN源码已绑定两平台10个实际构建哈希，根审75项通过。launcher只有10个空pin填入实际值；8个其他源码逐字未变，227个运行定义、36个原围栏、原98项与独列12项冷重启检查和全部时限均保留。仅9个控制源码与回执的inert准备已放行；**控制机的当前规范源码完整导入尚未证明，prepare/live均未放行**。

当前独立源码exporter、carrier和importer继续使用原限时及独立新目录。已审carrier/importer保持未绑定；实际bundle与export receipt的size/SHA/version未产生，不能先填推测值。H2仍需当前产品产物、工具分发与规范源码导入全部闭合后再准备和实跑。它的单机三进程测试不能替代Mac/ROG/Pocket4真实多机验证。

### P01可信注册与逐台切换

公开投影实际执行仅使用8份已归档公开输入；24,624 B投影源码、328,295 B输入和104,595 B输出已完整核对。根审30项、76个精确原证据指针通过。历史配置中Mac为5个agent、ROG为6个、Pocket4主机为2个；X230消费者数量仍未知。5/8/5/4是服务定义条目数，不是当前运行实例数。ROG禁用配置、服务hold及历史失败保持原样。

投影列出了9份公开注册/hold回执引用、2个有界依赖读取方案和10步新生产发行契约；它们不等于9份独立备份，也不证明现有生产集群/CA/AppRole注册已经可用。所有实际发行值仍为空，真实lookup-self前后TTL/到期时间证据仍缺。Mac方案中将正式server/config/data放在home的建议已被根审退回修正：正式服务、数据与备份继续绑定外接T5，home客户端凭证文件另行管理。原未执行方案和输出保留。

正式切换仍需每台真实凭证读写、持久化、重启与严格回滚；X230新传输必须持续绑定原UNKNOWN relay围栏并使用新目录。全部客户端和备份路径迁移完成前，不得将旧资产清理当作已完成工作。

### 完整替代的剩余门槛

继续完成当前源码导出/传输/完整导入、normal5和LAN准备回读、QA12剩余元数据及H2实跑，再执行当前三台物理主机的98+12项回归。34MiB正式迁移与恢复、官方snapshot CLI保存/恢复/备用节点/冷读、真实AuthBus可信发行及续期时效、逐台切换/回滚和备份恢复仍分别验收。

官方2.7.1的完整源码契约归档沿用R23；词法声明或路由数量不代表运行覆盖。JWT/Kubernetes/OIDC/MFA、外部动态租约、PKI外部签名/ACME、重密钥与恢复、可变插件和非默认命名空间等原生所有者仍缺完整资格。原有拒绝条件继续保留，完整替代结论仍为false。

以下原R24文档逐字保留；历史截点不得覆盖以上当前状态。

---

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R24：Mac 61 项记录及 QA 工具归档闭合；AuthBus 新实跑失败，尚未全量替代

状态截点 **2026-11-05T12:33:29Z**。本节只冻结已经回读的完整原件。当前候选仍为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`，源码树 `eba5e650bd080b8ad41ea52a2bc68867f541d255`。**没有正式切换生产流量，没有删除旧 OpenBao、HeptaBao 服务、二进制或备份资产。** 本轮检查点仅更新两个状态文档并追加证据，不修改产品源码。

[完整机器状态](../../qa/evidence/20261104/r24-normal61-qa-closure-wal-admission-r1/state.public.json) · [完整证据清单](../../qa/evidence/20261104/r24-normal61-qa-closure-wal-admission-r1/manifest.public.json)。本轮包含 23 个完整证据包、1086 份分包文件、22,719,526 B 原文，以及根审、精确运行授权和原始回执。各包均核验完整字节、SHA256、Git blob 与 Merkle；相同不可变 Git 原文可从已验证缓存重新计算完整哈希，不冒称全部重新联网取得。

### 实际通过与运行边界

- **Mac normal61：** 61 项实际记录、48 个命令记录和 94 个小流已独立核对，根审 380 项通过；48 个自有子进程均收尾。server、seed、libtest 三份保留产物已用独立 file_info 绑定完整 SHA、版本和 0500/501:20/单链接。第一个 Cargo stdout 已恢复 440,534 B、438 个实际事件，匹配构建回执；第二个日志和全部只读操作链仍在收齐。原两个直接读取异常保持历史状态，没有重跑产品。
- **ROG normal61：** 原唯一任务 `1a1ab76cee8-fc05-4e13` 已有 exit0/full/durable/confirmed 权威终态，stdout 2,220 B、stderr 0。执行者报告原 60 项与新增 1 项通过；本截点尚未纳入完整核心包的根审，资格不由报告自动授予。
- **QA R3 工具：** 190 文件全归档、12 命令/24 流、两份 75-event Cargo JSON、18 个闭合只读操作和 33 个原始页已根审 384 项通过。六个组件仍共用原 30 秒命令。工具身份固定 df026，不转移成当前 4e808 产品资格。
- **QA12 准备：** 三个控制源码及一份回执独立整件回读，6 段固定版本读全部闭合；另一审查者完成 166 项源码检查。12 文件、4,892,547 B 的精确搬运已单独放行，实际搬运结果待归档。尚未运行 H2 产品场景。
- **H2 双身份：** 根审 109 项通过；工具 df026/historical60 与产品 4e808/current61 分开约束。根审找到的真实模板路径错误已经修正，原错误模板和修正证据保留。四份当前产品产物仍待绑定；准备和实跑均未放行。
- **当前 LAN：** 三个绑定文件的最小改动经过根审 64 项，227 个函数定义及原 98+12 分母、36 个约束不变。当前候选真实 Mac/ROG/Pocket4 断主、自然选主、ReadIndex 和冷重启仍未运行。

### Mac AuthBus/WAL：准备已通过，真实运行已失败

31 个落盘文件、32 段固定版本响应、596,491 B 原文全部闭合；准备任务 exit0/full/durable，0.259 秒，唯一 diskutil 子进程和所有描述符均关闭。Mac 与 QA12 准备的独立根审合计 288 项通过。

随后仅提交一次冻结请求 `db1c0badddf800b253a5476cdb1ab49f2cabf543`：原任务 **`1a1abb090b9-fc05-4fc5` 已返回 exit1/full/durable，无超时**，stdout 91,043 B，stderr 0。本截点正在收齐这份输出与自有进程清理，不提前推断失败原因，不重新提交原业务，也不扩大原 1080/900/600 秒及子步骤限制。准备成功不抵消实际失败。

生产信任仍是独立门槛：实际地址、集群、CA、AppRole 与策略来源尚未闭合。已有续期脚本只证明 renew-self 返回 200，未观察前后 TTL/到期时间，不能声称完成续期时效验证。P01 正按已观察的主机和注册回执制作具体公开投影；禁止用隔离 fixture 的 CA/RoleID/SecretID 填生产字段。

### 接下来必须完成

继续收齐并诊断原 Mac 失败，针对真实实现问题提出最小后继源码；收齐 ROG 原 61 项及产物后，推进当前产物和完整规范源码的 create-only 传输，再绑定 H2 和真实 LAN。X230 原 UNKNOWN relay 围栏保持不动，新的传输必须使用新命名空间与已合格的当前 Linux 产物。34MiB 正式迁移、snapshot CLI 保存/恢复/备用节点/冷读、每台真实凭证写读/重启/回滚，以及全部客户端和备份迁移仍是切流与清理的前置条件。

官方 OpenBao 2.7.1 的 242 份完整源码契约归档沿用 R23：423 个词法声明、720 个声明操作、1,064 字段和 128 个注册点是源码清单，不是运行时覆盖率。JWT/Kubernetes/OIDC/MFA、外部动态租约、PKI 外部签名/ACME、重密钥与恢复、可变插件、非默认命名空间等原生所有者仍缺资格。不能通过删除拒绝条件宣称完整替代。

以下原 R23 文档完整保留，供历史审计；其状态不得覆盖本节截点。

---

# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

## 当前 R23 检查点：Mac 61 项核心实测通过，QA 六组件和 X230 围栏闭合；全量替代仍未达标

状态截点为 **2026-11-05T11:30:02Z**。本节冻结已到达并独立回读的原证据；截点后的产物元数据、完整命令归档、ROG 终态和后继执行进入下一检查点，历史失败和 UNKNOWN 均保留。**没有正式切换生产流量，没有删除旧 OpenBao、HeptaBao 服务、二进制或备份资产。**

[本轮完整机器状态](../../qa/evidence/20261104/r23-retained-a-normal61-qa-fence-official271-r1/state.public.json) · [证据清单](../../qa/evidence/20261104/r23-retained-a-normal61-qa-fence-official271-r1/manifest.public.json)。本轮新增 2099 个分包文件，分布于 53 个完整证据包，原文共 37,734,246 B；另保留根审脚本、结果、源码发布原回执和完整官方源码归档。所有分包均核对完整字节、SHA256、Git blob 及 Merkle 树。

### 当前候选与已取得的实际结果

当前候选为 `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`，源码树 `eba5e650bd080b8ad41ea52a2bc68867f541d255`，[草稿 PR #159](https://github.com/TrillionniumFoundation/HeptaBao/pull/159) 未合并。相对于唯一父提交 1c665，仅修正新增回归用例：保留第一次实际产生的 A 迁移计划，在 B 之后重新发布该 A。独立再次迁移相同 V5 内容会生成新的随机 object_address_key，不能充当原 A。生产逻辑、原 30 项断言及原 15 秒请求预算均未因此放宽。

| 路径 | 原任务及实际证据 | 本截点结论 |
|---|---|---|
| Mac T5 源码 | 41 命令、82 流、两个完整 NUL 清单、14 个固定版本大流分块；T5 UUID 已验证 | 源码导入通过，全部 3914 个文件逐路径、mode、blob 与当前提交一致 |
| ROG 源码 | 56 命令、112 流及相同两个完整 NUL 清单；独立仓库、旧源码保持 | 源码导入通过；两机完整归档合计根审 722 项通过 |
| Mac 当前 normal61 | 原任务 `1a1ab60127b-fc05-4d18`，exit 0/full/durable；核心 63478 B，SHA `02422f0070827e4940ae819d117b80ead30b993dba5ec9fe4a1aee21f286c113` | 原 60 项及新增 A→B→A 一项实际通过；48 个 owned 子进程均回收，6 个旧合格文件及 4 个旧失败文件完整身份和全文保持 |
| 新增 A→B→A | 新项记录、stdout、stderr 已独立整件回读；warm 435 ms、cold 477 ms，原请求预算 15000 ms | 通过。整项含 setup/断言用时 16.7216 秒，不能把它错误地当作单次读取超时 |
| ROG 当前 normal61 | 精确请求取得唯一 ACK：`1a1ab76cee8-fc05-4e13`，reused=false；外部 intent 已在提交前独立保存 | 已启动，原 12000 秒及全部子预算保留，终态未收入本截点 |
| QA R3 | 原任务 `1a1ab68bbb6-fc05-4d8a` exit 0/full/durable；六个实际组件全部通过，12 个子进程、输入 FD、9 个别名读取 FD 及 iterator 全部闭合 | 仅 QA 构建/六组件核心通过，已释放共享 target 给 ROG；六测试共享一个原 30 秒命令，不是六份 30 秒 |
| X230 旧运输围栏 | 原任务 `1a1ab637c5e-fc05-4d3a` exit 0/full/durable，53.414886 ms，10 个 FD 一次关闭；固定 ROOT 独占创建，2709 B marker 独立元数据和固定版本正文匹配 | 精确围栏范围通过；没有启动运输、网络、子进程。旧 relay `1a1aa57458d-fc05-4156` 仍为 UNKNOWN |

Mac release 构建 259.883 秒、libtest 构建 450.369 秒，保持正常默认 feature 与原 profile。Mac 核心根审 112 项通过；**48 个命令的全部原流、三件 retained artifact 的独立 file_info 尚未收入本截点，因此本节未给 WAL/LAN 执行资格。** QA R3 核心根审 83 项通过；动态捕获本次 Cargo 两别名的新 inode，全文比对后创建独立单链接 retained 文件。剩余 22 个命令流与完整 Cargo JSON 仍在归档，不据核心摘要宣称已经完成全部工具资格。

### 保留的失败和未决状态

旧 1c665 Mac normal61 仍记录为“原 60 项通过、新增一项失败”；其中两份 Cargo 大 stdout 的首次完整读回发生 MCP 超时，未重放构建，缺口仍保留。QA R2 仍为 generic single-link 校验拒绝 Cargo 两硬链接的真实失败；后来观察到两别名不改写该失败。R3 还实际抓到取消信号在 handler 恢复过程中被遗漏的反例，最终修复在两原 handler 恢复后再次检查取消，原反例和修复后结果均保存。

X230 固定窗口定位在第 03 窗发现原 R2 围栏，04–12 窗未提交。原 R2 围栏已恢复为 exit 1/full/durable 的已知失败，只关闭已打开的两个 FD，没有创建 ROOT 或 marker。最新拒绝 tuple 未被记录，不能臆测具体哪一字段变化。新 R3 仅对四个共享祖先目录使用 dev/ino/uid/gid/mode 对象身份；旧 control、新 ROOT 和 marker 的完整九字段检查保持。新 ROOT 保留期间可以阻止精确旧 relay 再越过必须的 ROOT.mkdir；它不证明旧进程已经终止。

最近一轮真实三机结果仍为旧 df026 的 **91/98，后续 0/12 未进入**，34MiB（35651584 B）数据实际参与，但这不是当前候选的全 HA 通过证据。原 B01 两个 UNKNOWN、Mac 旧 capture 的内部未决状态及旧 provider/config baseline 均未被重放或改写。

### OpenBao 2.7.1 全量范围已经明确，仍需实现和实测

官方 v2.7.1 的精确提交为 `a5db72cef75c24b920ade02065b18dd8eb666bac`、树 `3a8ba726d8d557a5f9b3f2ed28b406da33632182`。已完整核验 242 个 Go 源文件的字节、双 hash 和树成员关系；6328 个树条目、939 个 Merkle 也已核实。V3 清单保留 **423 个声明、720 个声明操作、1064 个字段、128 个注册/生命周期位置**。这些是源码词法清单，**不是运行时覆盖率分母，也不是 720 项已通过测试**。V3 只纠正 189 个 family 行，反向恢复后其他语义完全一致。

完整清单、完整源码语料和重现依赖分别归档为 gzip/base64 与 tar.gz/base64；具体字节、SHA256、原 V2 数据和初次失败/修正见机器清单及 `official271/persistence-receipt.public.json`。原文件里创建时的 persistence-pending 标记保留；新的归档回执说明实际保存形式，没有冒称另建了未创建的原始 Git blob。

当前 14 个原生能力门槛源文件与 1c665 内容一致。仍需补齐 JWT/Kubernetes/OIDC/MFA/password-policy 的持久化 owner 和冷恢复语义；数据库/Kubernetes/RabbitMQ 外部 lease/effect owner 与 UNKNOWN 对账；PKI ACME/EAB/外部签名及 transit 外部托管；rekey/recovery/root-generation/rotation/raw/system 生命周期；可变插件目录、provider 协议和非默认 namespace/workflow/control-group 等状态。必须实现这些所有权、持久化、撤销和恢复语义，不能删掉当前拒绝 guard 换取绿色结果。

### 接续动作与清理前置条件

继续回收唯一 ROG normal61 终态，完成 Mac 原始命令/产物资格，然后将当前产物绑定到 WAL、H2、34MiB 迁移/恢复与原 98+12 三机断主、自然选主、ReadIndex、持久化及重启验证。所有预算和失败判据保持，禁止强制选主、刷新 deadline 或用新 key 重派 UNKNOWN。

AuthBus 仍需可信生产 cluster 地址、CA、AppRole 凭证来源和完整 AppRole/TLS/KV/Policy/续期/撤销证据。临时 fixture 生成的 SecretID 不等于已经完成生产可信来源。每台主机必须先完成真实凭证读写、重启与回滚，再切流量。Pocket4 manager、X230 当前 consumer、完整客户端与备份迁移仍未闭合；Nov2 capture/Nov3 transport 的九份回执是一条备份链，不能当作九次当前完整备份。ROG 已停用 generation203 及模型/provider/refresh/quota 状态保持。所有客户端与备份路径完成迁移后，才执行旧服务、二进制和可再生资产清理。


## 当前 R22 检查点：同内容根发布修复已形成候选；WAL 十场景与 QA 进程归属实测闭合

状态截点为 **2026-11-05T09:06:41Z**。本节及机器索引冻结该时点已收到的证据：Mac 新源码导入和 Linux QA R2 构建都已取得唯一启动回执，终态尚未收入这个快照。之后收到的终态、完整命令归档和后继运行归入 R23，不回填本节。**完整替代 OpenBao 2.7.1 仍为未达标；没有正式切流，也没有删除旧服务、二进制或恢复材料。**

### 这次已闭合的工作

- **同内容根发布修复形成新候选。** 候选提交 `1c66541993662f92cf717154e33717abedb2ea74`、完整源码树 `94ced21a63ff9aaca4538c0d4796efea2150e632`，见 [PR #158](https://github.com/TrillionniumFoundation/HeptaBao/pull/158)。3914 个文件、358 棵 Git 树、62,224,861 字节均独立重算。修复要求热、冷两条同根快捷路径同时满足当前 HA 游标；旧游标即使仍覆盖同一内容根，也必须走原有完整安装路径。新增 A→B→A 回归用例；原有 60 项主机回归以及三机 98 项和重启后 12 项分母保持独立。格式化器实测原件及 169 项根核验闭合，不能据此声称产品回归已通过。
- **Mac 当前 WAL 读取约束完成十场景真实合成验证。** 原主机作业退出 0、输出完整且持久化；1 个卷检查子进程和 10 个读取子进程均回收，70 个父进程文件描述符闭合，十组写入器、游标和持有描述符均闭合。用例覆盖真实 WAL/SHM 写入拒绝、缺失旁文件、打开失败、WAL/主库/SHM/父目录变化、扫描拒绝和超限记账。根独立核验共 300 项。该证据不等于真实私有凭证捕获、整库备份、所有 ABA 情况或跨代理原子快照已经完成。
- **当前 AuthBus WAL 调用链的 SOURCE 审查完成。** 112 件来源文件、22 个源文件及静态输入逐字核对，206 项根核验闭合。失败尝试及内部资源账本需要保留，不能用外层进程退出代替内部资源回收证明。原 45 秒捕获、3 秒查询及其他容量、阶段和总时限均保留。相关惰性安装和真实调用请求尚未提交；须等待新候选 Mac 正常回归的实际服务端制品凭据，再作最小绑定。
- **Linux QA 短命令进程归属修复获得真实组件证据。** 三个实际 Linux 组件覆盖运行中正常退出、已成僵尸的成功退出和退出码 129；三个子进程组和描述符均回收。原有 18 个纯组件与新增 7 个假 OS 组件单独保留。QA R2 的惰性安装已取得权威退出 0；创建的 8 个输入与独立文件元数据及完整内容散列相符。4208 字节安装回执是用原始权威 stdout 保持整数精度地重建后，与独立元数据散列比对成功，明确不冒称重新读取了回执正文。三个额外只读正文操作仍为 UNKNOWN，原记录保留。
- **两平台新源码导入控制链已逐字审查。** 原有正常回归体、时限、旧 df026 六文件前后保护及清理路径不变；新增保留文件读取器在打开和关闭异常下保留完整账本。13 个假 OS/FD 组件和同行审查证明源级边界，不能转写为远端实测。Mac 导入已经获得原请求的唯一启动回执。ROG 导入原提交仍无作业回执；固定路径结果报告 55 个子进程回收、完整源码校验成功，独立读取的 bundle 也已闭合，但这些材料不能替代原作业的权威终态和原始流。
- **逐台迁移计划和备份路径已形成有边界的清单。** Mac 五个、ROG 六个、Pocket4 两个既有代理的历史证据分别保留；ROG 最新停用状态优先于旧活动记录。生产地址、集群、CA、角色及 SecretID 发放、策略和服务管理证明仍未绑定。X230 当前客户端分母未知，隔离的官方对照容器不是删除授权。现有备份链仅覆盖已登记的那一次捕获、运输和恢复，不能外推为所有主机的当前备份。

### 仍然阻塞正式替代的门槛

1. **候选运行资格未继承。** 当前已完成主机 60 项回归的仍是旧 df026；新候选必须在 Mac、Linux 分别完成原 60 项加新增 1 项，保留实际二进制、原始流和所有进程闭合记录。本截点的 Mac 导入与 QA 构建仅有启动回执；PR #158 的所观测 CI 作业仍在排队。
2. **三机真实故障回归仍失败。** 最近一次 Mac/ROG/Pocket4 实测为 91/98，重启后 0/12 未进入；34MiB 数据与已恢复根是部分事实，不能抵消缺失的七项。必须在新候选上重新完成自然断主、选主、ReadIndex、持久化和重启；不强制选主，不扩大既有时限。
3. **两个提交身份尚未闭合。** X230 原中继及其后继围栏存在缺失回执，ROG 新源码导入原提交也未找到作业 ID。进程列表分页在变化，只能视为不完整观察；一次固定路径 ENOENT 不能证明原提交未执行。两组独立已知成功回执已验证请求摘要算法，接下来只允许有界只读定位，不能通过换键或重新提交取得“干净”结果。
4. **真实 AuthBus 与逐台切换尚未执行。** 必须重新建立不依赖 J3160 的可信凭证来源，完成 AppRole、TLS、KV、Policy、续期、撤销，再逐台完成真实凭证读写、重启和回滚。生产绑定尚空，当前记录不得视为切流许可。
5. **OpenBao 2.7.1 全量分母仍开放。** 官方 2.7.1 源码提取、416 个词法路径、旧 2.6.2 对照集和既有 69 项表面测试均不等于全量行为覆盖。正式存储迁移与恢复、官方 CLI、全部实际客户端及备份路径需要逐项闭合，之后才能进行旧版清理。

### 证据完整性与下一步

本检查点挂载 **20 个原件包、752 个文件、19,099,770 字节、184 棵包内 Merkle 树**，另存 **78 个根核验、状态和清单文件**。所有包均完成完整正文读取、Git blob/SHA-256 校验和树根重算。上一检查点正文及旧索引的原始字节保留；只新增本节、更新顶层时间并追加 R22 状态，避免旧整数被重序列化。

可复核入口：[状态](../../qa/evidence/20261104/r22-same-root-wal-qa-source-closures-r1/state.public.json)、[完整清单](../../qa/evidence/20261104/r22-same-root-wal-qa-source-closures-r1/manifest.public.json)。后续先收敛已提交的导入与 QA 构建终态，再启动已完成准备的新候选正常回归；并行修复实际失败、有界定位未知提交、绑定当前 WAL 流程。所有失败与 UNKNOWN 继续保留，不用成功的后继运行覆盖。

## 当前 R21 检查点：完整源码导入闭合；三机失败定位到同根游标；WAL 惰性落盘完成

状态截点为 **2026-11-05T07:40:18Z**。此处冻结该时点之前的主机终态和 CI 观察，之后完成的原件回读与根核验随包保存。R22 的新元数据观察、WAL 十场景实际执行和后继修复不回填本节。**完整替代 OpenBao 2.7.1 仍未达标；尚未正式切流，也没有删除旧版资产。**

本包将先前分散的源代码、请求、权威终态、完整输出、不可变读取页和独立核验收束为 **16 个证据子树、914 件文件、15,138,112 B、102 个子树 Merkle**，另附 62 件根证据、状态及清单。入口为 [R21 状态](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/state.public.json) 与 [R21 清单](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/manifest.public.json)。R20 和更早记录保留其原始失败、UNKNOWN、时间、整数和作用范围。

### 一、资格按源码和产物分别绑定

本轮 Mac、ROG 与 Pocket4 的实际服务产物仍绑定提交 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`、树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`。Mac/ROG 原 60 项正常构建资格沿用已闭合的各自证据，但不能赋予后继代码。

新 CI 候选为 `6d02ceca629163e1c07480fa1f21520434407143`、树 `09aa45b9439741780961c2af76680c27e0773d08`，唯一父提交为 `19ba09ab5c494f25a3531749b0b99fc5c651d56c`。其增量只是最终 cold gate 调用后的 rustfmt 换行：3,912 个文件不变，唯一文件增加 9 B，仍按值传入 `gate`。该候选的 CI、原生构建、LAN 和 X230 资格均须单独成立。

### 二、正式源码导入的完整证据已闭合

导入作业 `1a1aa422e15-fc05-3ffa` 的 R2 完整包包含 291 件原件。根核验覆盖 22 个已关闭的读取操作、99 页原始不可变 SDK、21 条命令记录及 42 份完整 stdout/stderr，并从实际 Git tree 与 stage-0 index 的 NUL 分隔记录重建全部 3,913 个文件、358 个 Merkle、62,212,769 B，精确得到 df026 源码树。

原 21 个子进程全部回收，公开源代码和独立目录描述符均已关闭；原 clone/Git/总时限不变。根侧 1,068 项读取来源检查与 11,821 项命令、对象、索引及树检查通过。首次 index 分块请求未带 expected_version；随后分块显式绑定，所有返回版本与完整重组字节、独立元数据及 canonical Git 树相符。证据没有把首次请求改写成已预绑定。

详见 [完整源码包](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/source-import-r2-full/manifest.public.json) 与 [根核验](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_source_import_r2_full_root_review.public.json)。

### 三、三机实际断主、恢复及冷启动：91/98，后续 0/12

LAN 唯一实际作业 `1a1aa914172-fc05-4473` 已权威终止：exit 1、完整持久输出、无外层超时。本轮观察到真实自然选举；Pocket4 节点 3 提供密文，Mac 节点 1 成为实际空数据 leader 并恢复。Mac 已读回 17 个有效大版本、19 个历史版本对应的 35,651,584 B 载荷；从本轮实际集合重建 338 个密文 leaf、35,742,486 B，并验证各 leaf 的大小和 SHA。

方向准备 witness 的 CAS=0 写入返回 200，同 scope 删除返回 204，Mac 精确读和删除后缺失也已确认。该 witness 既不计入原 98 项，也不计入后续 12 项。

ROG 节点 2 随后的一次 `sys/unseal` 在 **10,289.344 ms** 返回 503；原请求预算为 15 s。原 98 项中 91 项已执行且通过，缺失 7 项如下，未用后来的根检查替代：

- `missing_cipher_all_hosts_readindex`
- `missing_cipher_remaining_nodes_unsealed`
- `native.complete`
- `report_excludes_runtime_secrets`
- `source_and_binaries_unchanged`
- `synthetic_metadata_absent`
- `synthetic_metadata_cleanup_once`

后续冷重启 12 项未进入。49 次变更意图均有唯一返回：39×200、8×204、2×503，无 transport UNKNOWN，无变更重试。98 份意图及结果公开原件经 7 个读取批次逐字、SHA、版本与序号闭合；这不等于所有 GET 都已有独立原件，也不把 HTTP 返回解释为持久提交证明。

16 次服务启动与 16 次停止按节点和 PID 一一对应；6 次 Mac 前台会话的远端与本地直接子进程均回收，观测到的受控进程组为空，原 5 s 停止预算满足，隧道子进程为 0。测试独占窗口已释放。详见 [实际 summary](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/lan-live-actual/core/summary.json)、[受控进程闭合](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_lan_owned_closure_root_review.public.json) 和 [49 对请求边界根核验](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_lan_boundary_root_review.public.json)。

#### 公开阶段日志给出了可修复的具体分支

在服务已停止后，只读取本轮 ROG 节点 2 固定日志的元数据，再用源代码绑定的封闭字段提取器投影正常构建的公开阶段码。作业 `1a1aaa6142c-fc05-4599` exit 0、完整持久 stdout 55,402 B，输入 42,620 B，6 个描述符均关闭，耗时约 1.4 ms；原 15 s、2 MiB 输入、128 marker、64 KiB 输出及 64 bucket 上限保留。

最后一个完整 timing scope 的 12 个 bucket 未触及上限。`committed_root`、`local_selection`、`local_root_binding`、`local_root_identity` 均完成，`current_cursor` 在 5 µs 失败，出口仍余 3,717,085,098 ns；该 scope 没有进入 replica install 或 materialization。

这是对精确 df026 源码的分支推断：LocalSelection 已成功解码并配对相同的本地 HA cursor，通过较宽的 covered_by；随后同根快速路径仍因更严格的当前 publication/generation 相等检查拒绝。该证据没有读取私有 cursor 值，也没有 request ID，不能仅凭相邻顺序把日志行与 mutation 49 做密码学绑定。后继修复应保留最终 strict cursor、真实 owner、ReadIndex、CAS、持久化和原时限，专门验证同内容根被较新提交再次选中的情况。本时点尚无修复实际资格。

详见 [提取器实际原件](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/lan-cold-projector-actual/stdout.original.json) 与 [独立根分析](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_lan_cold_projector_actual_root_review.public.json)。

### 四、H2 验证客户端：惰性落盘通过，构建在 Cargo 前被拒绝

8 份固定输入的惰性落盘与独立读取已闭合：作业 `1a1aa7c3dff-fc05-439c` exit 0，80 件完整包、7 个读取操作、26 页不可变 SDK、268 项根检查。Cargo.lock 首块请求未预带版本，完整字节、各返回版本及独立 file_info 相符；其余源码的独立版本读取与 producer 的完整身份分开记录。

随后唯一构建作业 `1a1aa9fa851-fc05-4547` 在 `canonical_before` 阶段失败：第二个短 Git 命令读取 tree 时，原进程身份守卫观察到空 cmdline 并拒绝。`source-before-tree` 仍记为 incomplete，原 `command_outcome_unknown=true` 保留。两个直接 Popen 子进程实际 wait 返回 0、已回收且组为空；这不能把原身份守卫改判为通过。

Cargo、六个客户端组件和任何产品 HTTP 请求均未开始。原 600/660 s 总预算、各阶段和清理预算保持，后继需修复短命令 custody 的证明顺序。详见 [失败原件](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/qa-build-known-failure/actual/result.public.json) 与 [根核验](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_qa_build_failure_root_review.public.json)。

### 五、Mac AuthBus：WAL 读取实现与惰性落盘完整闭合，实际信任证明仍待后续

新方案只增加固定 registry 表的 WAL-aware 只读路径；原五个 agent 数据库的 immutable 查询实现和原零 WAL 约束保持。新 registry 路径要求真实只读 VFS/SHM、精确单键与 indexed SEARCH，保留原 1 MiB 单行、8 MiB 显式读取及返回量、3 s 查询和 45 s 捕获限制。SQLite 内部页面 I/O、全部 ABA 与跨库原子性仍未被这些边界证明。

53 件最终源码包修复了返回行拒绝前的预算记账、公共代码 FD 的失败闭包，以及 synthetic 父进程实际接入已验证 native ownership 链的问题。根侧四类纯账本重放与作者完整输出逐字相同；该纯重放不代替真实 SQLite 测试。

惰性作业 `1a1aa8cc28f-fc05-444b` exit 0，耗时 0.222805 s。唯一 diskutil 子进程已回收，全部 T5 描述符关闭，原 27 个 anchor 身份字符串一致。13 个实际文件完成 **13 份独立 file_info + 13 份显式 expected_version 的完整正文读取，共 176,462 B**，与原 carrier 源码/文档及回执逐字对应。完整实际包 112 件、7 个 Merkle，根侧 64 项核心及 107 项补充检查通过。

原候选回执在 final cleanup 前写出，`ok=false`；最终 stdout 与权威 exit 0 记录 `ok=true`。共同的 26 个 JSON 值保留原始 token 并完全相同，候选回执从未被当作最终资格。一次 SSH capacity 拒绝明确没有提交子进程，原件保留，之后只完成同版本的公开读取，未重放 publisher。

截至本节时点，W01–W10 真实 synthetic 和新的当前私有凭证捕获尚未提交；原 current capture 的失败、未完整返回的库账本和更早 UNKNOWN 保持。AppRole、TLS、KV、Policy、续期、撤销及五个实际客户端的当前完整链尚未完成。详见 [最终源码](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/mac-wal-final-source/manifest.public.json)、[完整实际读取](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/mac-wal-inert-full/manifest.public.json) 与 [根核验](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_mac_wal_full_root_review.public.json)。

### 六、X230：原运输 UNKNOWN 不变；独立 effect fence 已知在写入前失败

原运输作业 `1a1aa57458d-fc05-4156` 仍为 UNKNOWN，未改 key 重放。固定元数据观察已完成 42 次 metadata 调用及 8 个 FD 关闭，未读取正文；两次顺序缺失观察不等于原子预留。

独立 fence 作业 `1a1aa8a6fb0-fc05-4428` 权威 exit 1，在 `bind_fixed_directory` 的完整身份比对拒绝。原代码顺序将该拒绝定位到首次读取 `/home/qian-qi`，但原结果没有给出当时改变的具体字段。仅打开并关闭 `/` 与 `/home` 两个 FD，7 次 metadata 调用、0 正文、0 mkdir 尝试、0 marker、0 子进程与网络。原 ROOT 未被该次执行观察，不能据此声称其当前缺失或旧运输从未运行。

该失败的写入前终态已完整闭合，后继需新的有限观察与单独绑定请求；截至本节时点仍无新运输准入。旧 495 源码上的 full34/69 成果不转授给 df026。详见 [fence 失败包](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/x230-effect-fence-known-failure/manifest.public.json) 与 [根核验](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_x230_fence_failure_root_review.public.json)。

### 七、CI 原始失败与新候选分别保留

| 对象 | 实际结果 | 当前证据含义 |
|---|---|---|
| PR154 head | server lib 3,720 通过、2 失败、8 ignored | 两项 503 的内部唯一原因仍未确定 |
| PR154 merge | workspace 通过，Clippy 失败 | 不覆盖 head 的原失败 |
| PR155 head / merge | 两条完整 workspace 都通过，Clippy 都失败 | head 为 3,722 通过、0 失败、8 ignored；不据此倒推历史失败根因已修 |
| PR156 head / merge | 相同一处 rustfmt 失败 | 编译、workspace 和 Clippy 均未执行 |
| PR157 | 新 head 6d02、新 merge 4741ed；run 41987962107 最近观察为 queued | 只有源码增量审查，尚无新 CI 通过结论 |

PR157 的完整源码树、父提交、生成 merge、唯一 9 B 差异及两份原 formatter 日志均已核对，并有独立 peer。没有本地 Rust/rustfmt 执行声明。详见 [CI 根观察](../../qa/evidence/20261104/r21-complete-source-lan-cursor-qa-wal-inert-r1/r21_ci_root_observation.public.json) 与 [PR157](https://github.com/TrillionniumFoundation/HeptaBao/pull/157)。

### 八、剩余五道门槛的当前结论

| 用户门槛 | R21 结论 |
|---|---|
| KV2 正式迁移与可恢复存储 | 完整源码与正常构建基础已闭合；同根 publication 进度缺口待修复，新候选跨主机回归仍缺 |
| Mac / ROG / Pocket4 HA | 本轮 91/98、后续 0/12，ROG 冷解封失败；仍未完成全三机冷重启和 ReadIndex |
| 不依赖 J3160 的 AuthBus | 固定 WAL 路径与实际惰性读取闭合；十场景、当前真实凭证及 AppRole 全链仍待后续 |
| 逐台切流 | 每台当前真实凭证读写、重启、完整逆操作和精确生产目标绑定尚未全部完成 |
| 清理旧版 | 客户端及备份路径迁移未全部证明，清理资格未成立，实际删除为 0 |

OpenBao 2.7.1 的完整行为分母仍在补齐。固定的 69 项、416 个词法 route 声明或旧 2.6.2 corpus 都不能替代 2.7.1 全部注册条件、字段、操作和语义。结构性准入清单的 15 个安全维度、11 个正确性维度与 11 道必需 gate 仍有未闭合项。


## 当前 R20 检查点：导入核心证据闭合；X230 运输保留 UNKNOWN；QA 元数据完成

更新于 2026-11-05T06:29:38Z。**全量替代 OpenBao 2.7.1 仍未达标，尚未正式切流，也没有删除旧版。** 主机实际验证仍绑定 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`／树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`。本轮进一步区分已核实的导入、发布和元数据事实，与尚不能取得权威结论的 X230 运输；没有把成功的准备步骤当成业务资格。

[完整状态](../../qa/evidence/20261104/r20-source-core-x230-unknown-qa-metadata-wal-r1/root-review/current-state.public.json)及[证据清单](../../qa/evidence/20261104/r20-source-core-x230-unknown-qa-metadata-wal-r1/root-review/packet-manifest.public.json)固定本轮截止时点。新增 6 个完整包，共 192 个文件条目、2,867,636 字节、40 个包内 Merkle 目录；另有 25 个根审查、完整 CI 日志及索引文件。R19 的正文、原始索引大整数文本、既有证据和历史失败／未知均保留。R19 的全树复算证明和两次 recursive fetch 传输失败原件也随本轮保存；没有把失败的 recursive fetch 写成成功读取。

| 工作线 | 已取得的实际证据 | 当前边界及下一步 |
|---|---|---|
| desktop 正式源码导入 R2 | 原作业 `1a1aa422e15-fc05-3ffa` 权威 exit0、完整持久输出。42件核心包的4个原生读取操作、12页不可变原SDK、完整27,827字节末流均根审通过。21个命令对应21个已回收进程组，均无残留；3个输入文件、4个输入目录及新源码目录FD均有关闭账本。 | 原核心报告52.567秒／300秒；零前置bundle、3,757提交、完整fsck、3,913文件实体化。**63份原始command/stdout/stderr日志仍在最终归档核验**，本检查点不授LAN prepare。 |
| X230 7文件源码与惰性发布 | 实际绑定源34件完整包已核；inert原作业 `1a1aa4fa1ba-fc05-40c1` exit0、完整持久输出；3份源码与回执的整字节及独立9字段身份一致。根独立运行原remote-command纯函数和receiver实际5个参数guard，正确实参通过，缺失／错误／多余参数均拒绝。 | 此阶段只发布和compile-check，未执行传输或产品。原sender90秒、receiver／relay300秒、clone90秒、Git60秒、outer360秒及5+5秒清理预算均保持。 |
| X230 实际运输 | 唯一提交 `1a1aa57458d-fc05-4156` 返回 `launch_unknown`；首次及06:19:41以后原job状态查询均在private-job-directory处报该job的FileNotFoundError。四个固定公共intent/result逐路径读取均为通用读取错误；desktop、X230健康检查均可认证连接。31件完整有限对账包已根读回。 | **仍为UNKNOWN，没有权威终态或all-owned-stopped证明。** 文件读取错误不等于明确不存在，健康不等于执行成功。没有重派、换key或signal；7目标产物、X230正式34MiB及69比较均未取得本版本资格。 |
| H2 QA 前置元数据 | 六个固定只读操作全部闭合；47件／419,215字节、8个Merkle的完整包通过42项根检查。四工具及machine-id哈希元数据、原preflight和normal60两收据均保留；normal60的48,188字节与已合格原件逐字相同。 | target五字段来自原preflight，仅为历史身份；后续builder须在Cargo之前核对当前身份。实际QA inert、构建、6组件和H2协议用例尚未执行。 |
| Mac 当前注册库 WAL | 新registry-only只读路径的设计和固定SQLite 3.53.4参考源码已核。W03明确区分SHM数据打开被拒的CANTOPEN路径，以及可打开但索引不可靠时的READONLY_CANTINIT heap-index路径。 | 仅授实现及10个公开合成case／4组ledger组件的源码准备，尚无host执行或新的私有采集。旧采集失败及库内关闭账本缺失仍保留为UNKNOWN。 |
| LAN 与官方 CLI | 既有9份实际LAN控制源的惰性发布资格保持；98项原序列、独列12项及原32个证据围栏不变。Phase B原B01–B05源码保持。 | LAN prepare等待正式导入全部原日志；真实断主、自然选举、ReadIndex、持久化／重启和官方CLI后继仍待执行。两个旧B01 UNKNOWN不被替代。 |

### X230 的恢复边界

原job缺少权威终态，不能通过重发相同运输或换一个key解决。当前仅审查一个**create-only目录占位**方案：绑定原控制源与父目录真实身份，在原工作目录确实不存在时用原子mkdir争取唯一目录入口；若任何条目已存在即拒绝，不读取或改动旧工作目录。根据已固定relay源码，必须先成功创建该ROOT才可能进入运输子进程；占位若先成功，可以阻止迟到的运输越过这个入口。

这只是待完成的源码方案，**没有创建占位，也没有授予新运输请求**。它不能补造原job终态或清理证明，不能保证其他写者今后不删／改名目录；原relay异常收尾还可能调用一次ps，因此也不能宣称“旧作业此后不再执行任何子进程”。后续必须分别取得实际元数据、占位的权威结果、持续命名空间条件和新验证自身的目标准入。

### AuthBus 只读 WAL 与失败账本

新路线只针对固定installed-plugin注册库，计划使用 `mode=ro&cache=private&vfs=unix-posix&readonly_shm=1`，并将该路线WAL容量明确限定为5,969,912字节。原五代理零WAL路线、1MiB单行、8MiB显式读取／返回总量、3秒单查询和45秒capture预算保持。不会将SQLite的底层页读取量冒称为已计量的8MiB范围，也不会把内部C调用或WAL重试当作可逐调用硬中断。

W03只是SHM读取依赖的否定对照，单独不能证明参数被识别；还需实际sqlite_source_id、固定可用VFS和W01在实际拒写沙箱内的成功读取。当前没有新的runtime资格。新失败envelope须在异常路径也返回已登记FD与已返回连接的关闭账本；连接未确认关闭时，不提前关闭同inode的held FD来释放POSIX锁。原immutable函数若connect未返回handle，其内部连接尝试和FD不能从外部补记为“0”或“已全部关闭”；旧未知不会被新账本追溯改写。

### CI 与完整 2.7.1 分母

PR153的exact head和prospective merge现均已完成：完整locked Rust workspace步骤通过，strict Clippy均因 `service_native_v6_ha_read.rs:464:68` 的最后一次冗余借用失败，后续门槛跳过。新取得的head原始日志为2,946,416字节。PR154的merge也已完成workspace并在同一Clippy处失败，完整原日志2,867,575字节；其head以及PR155两条通道在06:24:17快照仍在workspace。已审单hunk修复候选PR156（`19ba09ab5c494f25a3531749b0b99fc5c651d56c`）两条通道当时仍queued。没有取消、重定向或重跑原run，也没有将df026的主机结果重标为后继版本资格。

当前CI中名为OpenBao 2.7.1的官方比较通道明确执行bounded corpus，并断言 `full_openbao_compatibility=false` 和 `production_qualified=false`。它本身不能关闭全量替代。15项安全、11项功能／正确性及11项必要gate仍须逐项取得当前候选证据；既有59-surface／472-fixture表仍属于2.6.2。2.7.1的route × operation × configuration × lifecycle证据、全部真实客户端与备份路径迁移、每台凭证读写／续期撤销／重启／回滚、真实生产目标绑定和正式切流均未被本轮宣布完成。旧OpenBao和旧HeptaBao资产保留至这些条件真实满足。

---

## 当前 R19 检查点：ROG 正常 60 项闭合；Mac 当前采集保留失败与未知；正式源码及产物运输推进

更新于 2026-11-05T05:57:12Z。**全量替代 OpenBao 2.7.1 仍未达标，尚未正式切流，也没有清理旧版。** 主机验证继续严格绑定 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`／树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`。Mac 与 ROG 的正常默认特性构建均已通过原 44 项、既有 7 项和新增 9 项，共 60 项。这个范围不替代真实多机 HA、当前凭证、正式迁移、官方 CLI 或完整 2.7.1 验证。

[本轮完整状态](../../qa/evidence/20261104/r19-rog-normal60-current-wal-source-transports-ci-r1/root-review/current-state.public.json)与[全部证据清单](../../qa/evidence/20261104/r19-rog-normal60-current-wal-source-transports-ci-r1/root-review/packet-manifest.public.json)固定截止时点。26 个完整包包含 919 个文件条目、18,571,429 字节、128 个包内 Merkle 目录；独立根审查和原始失败、未知、请求修正及 CI 完整日志一并保留。R18 及更早正文与原索引大整数文本保持原样。

| 工作线 | 本轮实际结果 | 仍需取得的证据 |
|---|---|---|
| ROG 正常构建 | 唯一作业 `1a1a9f65382-fc05-3a6c` exit0、完整持久输出；22 组 listing 与22组运行同60个名称；46 owned child 全部 reaped／空组；182件全包根审完成。 | 当前候选的 X230 34MiB、官方 CLI、真实 LAN 与 H2 协议层验证。 |
| Mac 当前五代理采集 | `1a1aa2ac597-fc05-3e8f` 明确 exit1；child 为 `current_input_size_bound`，已尝试生产只读访问，但没有返回 capsule。三实际子进程均自然结束并收口，四项内核拒绝检查通过。 | **采集观察仍 UNKNOWN**；异常未返回库内 FD／SQLite connection 关闭账本，不能用外层关闭声明补足。五代理消费者与 launchd 阶段未开始。 |
| Mac 有限元数据 | 唯一 `1a1aa3a3d6c-fc05-3f7d` exit0；46叶／22父目录，354次元数据操作，46登记FD全部once-close；没有文件正文读取或 SQL。 | 当前只有 registry WAL 的5,969,912字节不满足原0上限。这不定位旧失败的确切叶，也不清除 UNKNOWN。须先证明新的只读 WAL 路径与失败账本。 |
| 正式源码导出／运输 | 23,429,893字节独立 bundle，零前置依赖，3,757提交及完整fsck；ROG导出166件、desktop运输57件均根审闭合。 | 新源码实际导入的全部原始命令日志与末流根审尚未完成。 |
| desktop 导入 | R1 因启动请求漏self SHA，在实际第519行第一条guard退出；0输入FD、0子命令。R2只补该参数并使用新key，源、目录、预算、guard不变；已收到exit0及完整core。 | R2尚处于完整原始日志根审阶段，不以core报告直接授予LAN资格。generic批量读取失败也不等于目录不存在。 |
| 五份正式产物运输 | `1a1aa3d9c57-fc05-3fc0`；110,397,866字节、4.216759545秒完成publication；5独立目标file_info和4份原始receipt全字对应；3owned child收口，42件全包根审通过。 | X230的7文件实际绑定、传输与正式34MiB／69比较候选执行。旧495的结果不能重标为df026。 |
| Mac／ROG／Pocket4 LAN | 9份实际绑定控制源码已惰性发布并完整回读；原98项、独列12项与32个历史围栏保持。 | 等待正式source import闭合后prepare，再执行真实断主、自然重选、ReadIndex、持久化、重启及额外冷恢复。尚未prepare/live。 |
| H2 QA／官方CLI | H2源码及6项固定只读元数据请求已审；ROG normal60先决条件完成。Phase B源码保持原B01–B05。 | 实际QA构建与6组件用例、单连接TLS/ALPN/H2流结束证明及官方CLI运行尚未完成；旧两次B01 UNKNOWN仍在。 |
| CI | PR153合并候选完整Rust workspace步骤通过，随后因finalgate冗余借用被strict Clippy拒绝；后续步骤skipped。 | PR154／155在05:38:40快照仍运行workspace。新PR156在05:53:31快照queued，尚无编译或执行资格。 |

### 源码与 CI 后继的范围

仅测试代码的 `c133d7e7b8a1df5f0be8f4337893f234c6ccede2` 修正两项既有 Clippy；`e69e52f28c653d28c5ae36dbbf6eb51b844536bc` 将并发 donor tail 的次序断言绑定实际 dispatch 提交顺序，并保留原 wire 集合、完整数据／根／ReadIndex、容量、14秒期限和清理断言。旧失败没有改记成功，也没有凭旧日志推断唯一历史调度次序。

新候选 `19ba09ab5c494f25a3531749b0b99fc5c651d56c` 是 e69 的单父后继，树 `73ba0c7fdf333b41d3944c5ee58b477026ff2d82`。只有一个生产源码 hunk、14字节减少：最后一次调用把 `gate` 按值传给既有 `FnOnce` 参数。原冷持有者、提交ReadIndex见证、期限检查、此前所有可变借用、timing phase及错误映射不变，未加lint抑制。3913文件中3912逐项不变，358个Merkle树已独立复算；作者与独立peer只授源码范围。

[草稿 PR156](https://github.com/TrillionniumFoundation/HeptaBao/pull/156) 的 head 为19ba、base为 `7b4a59bdd72218c1e779eb32754a682cf465af7a`，prospective merge `f03d524a83968adb88e5d3713dd584e6a1743deb` 的树等于head且双父已核。完整资格run为41976736304、trust run为41976736244，当前快照均queued。任何后继都不能继承本轮df026主机执行资格。

### 仍不能省略的总门槛

2.7.1 admission manifest 实际有 **15项安全、11项功能／正确性、11项必要gate**；其验证器只检查声明结构，不能证明全集。现有 complete-surface corpus 仍标2.6.2、59 surfaces、472 fixture cases，exact-current独立执行数为0。须补足2.7.1的 route × operation × configuration × lifecycle证据，不能由60个单测或69项有限比较推出全量替代。

每台仍须完成真实可信凭证、TLS/AppRole/KV/Policy、续期撤销、重启与回滚，再绑定真实生产目标并切流。所有客户端和备份路径完成迁移之前，旧OpenBao、旧HeptaBao服务／二进制及中间资产均不进入删除步骤。本检查点没有J3160调用、provider请求、强制选举、未知业务重放、预算放宽、生产切换或旧版删除。

---

## 当前 R18 检查点：Mac 正常 60 项与公共原生沙箱探针闭合；Linux 正式构建完成，后续回归继续

更新于 2026-11-05T05:03:04Z。**全量替代 OpenBao 2.7.1 仍未达标。** 本轮主机候选保持 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`、树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`。Mac 已完成正常默认特性构建及原 44 项、既有 7 项、新增 9 项共 60 项验证；ROG 正式发布构建完成，完整测试仍在原唯一作业内运行。仅测试代码的后继 `c133d7e7b8a1df5f0be8f4337893f234c6ccede2` 已建立独立草稿 PR154；没有把 df026 的主机结果改记为后继版本执行结果。

[本轮完整状态](../../qa/evidence/20261104/r18-mac-normal60-native-probe-ci-r1/root-review/current-state.public.json)和[全部证据清单](../../qa/evidence/20261104/r18-mac-normal60-native-probe-ci-r1/root-review/packet-manifest.public.json)固定本轮范围。22 个完整证据包包含 690 个文件条目、11,393,480 字节和 109 个 Merkle 目录；另附独立根审查、CI 原始完整日志、源码差分与精确请求。R17 及更早的文件、正文、失败和未知结果保持原样，原 JSON 的大整数文本没有通过浮点重序列化。

| 工作线 | 本轮已取得的实际证据 | 尚需闭合的门槛 |
|---|---|---|
| Mac 正常构建和回归 | 作业 `1a1a9eb00ff-fc05-39a5` 权威 exit 0、完整持久输出；60 个实际测试名称和全部清单一致；46 个子进程 exit 0、回收且进程组为空。两次 Cargo 原始事件与 180 件正式测试原件已核对 | 这是该版本的正常构建与指定回归资格；尚未覆盖新版本局域网 HA、当前凭证与生产切换 |
| Mac 完整源码 | 35 个命令及全部流原件闭合；两个实际 NUL 索引均与 canonical 的 3,913 个路径、模式和对象一致 | 与构建及后续测试继续保持同一源码和产物绑定 |
| ROG 正常构建 | 新建独立缓存，保留旧路径缺失的真实失败。发布构建用时 1,333.762 秒，小于原 1,800 秒；Cargo exit 0、归属进程组回收。server 为 110,339,520 B，SHA256 `7540cfb7e691fe5bea2515df3c35d8f31cdc42f05d5c9f2199c8464182de40b2` | libtest、原 44＋7＋9 和完整权威终态仍待；没有扩大原 1,800／3,600／12,000 秒预算 |
| Mac 公共沙箱探针 | R1 原生 ABI 和嵌套进程部分通过后在拒绝检查中已知失败；R2 补上唯一精确祖先目录读取规则后实际 exit 0。四项写入／网络拒绝均返回 errno 1；三组子进程自然 exit 0、流与 FD、T5 均关闭；源码和工具前后身份一致 | 仅公共前置探针通过。真实当前凭证、SQLite 捕获和五个实际 AuthBus 客户端尚未运行；旧 PID11754 的历史归属未知不被改写 |
| X230 与源码运输 | 原 31 项和双侧 69 项入口已生成新的未绑定模板；原 driver、13 个模块、15 秒 HTTP 和 360 秒迁移预算不变。独立源码导出入口已实际发布，导出作业 `1a1aa13e7fd-fc05-3c99` 已确认启动 | 实际独立 bundle、Linux 完整 60 项资格和精确运输收据齐全后，才能绑定新二进制并运行 |
| H2、官方 CLI 与三机 HA | 独立单连接 H2 客户端及六个组件案例、新三机与官方 CLI 后继入口已经形成可审查源码；保留原全部预算和测试分母 | QA 客户端实际构建、组件与真实 H2，独立官方 CLI 五窗口，以及 Mac／ROG／Pocket4 真实断主、选主、ReadIndex、重启都尚未通过 |

### CI 真实失败与后继的界限

PR152 的 head 完整 Rust 工作区通过，随后严格 Clippy 在测试代码发现两项问题。后继 c133 仅将等价错误谓词改为 `is_err()`，并用 `ManuallyDrop` 保持遗弃映射的无析构语义；3,912 个其他叶子完全不变。PR154 的 head／merge 均已通过前九步，仍在执行完整工作区测试，不能称为 CI 全通过。

PR152 的 prospective merge `ae18cbdd8b29dbf612588ea81aa22cbbf6a33952` 另有一个真实工作区失败：donor-tail 测试将最后四条服务端接收顺序作为尾部补取证明。原日志保留了失败、行号和整个运行。当前源码调查区分调度提交顺序与四个 TLS worker 的接收顺序；没有证明唯一的历史交错，也没有忽略失败、降低断言或放宽时间限制。该项修正和重新资格验证仍需完成。

### 继续执行顺序

先完成同一 Linux 作业的正式 60 项与全部原件，再完成独立客户端、源码／产物运输和新 X230、LAN 验证。Mac 当前凭证入口继续采用已通过公共探针的原生进程观察，绑定实际 df026 产物；外层服务管理仍保留原归属检查。所有现有生产地址、CA、AppRole、策略、服务监督及客户端／备份路径必须有真实绑定；每台完成实际凭证读写、重启、逆向回滚后才切流量。

本轮没有生产初始化、unseal、载入或切流量，没有删除旧服务、二进制或备份；没有 J3160、模型、provider、刷新或配额请求。完整 API／操作／配置／生命周期分母、全部当前客户端与备份迁移仍未闭合，因此“只保留最新版 HeptaBao 服务”的最终状态仍未达到。

## 当前 R17 检查点：Mac 与 ROG 同源导入已完成；Mac 正常构建运行中；ROG 缓存缺失与 Mac 沙箱进程阻断已形成确切证据

更新于 2026-11-05T04:19:24Z。**全量替代 OpenBao 2.7.1 仍未达标。** 统一候选仍为 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`，树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`。Mac 和 ROG 已各自实际导入、检验完整源码；新候选的正常产物、44＋7＋9 项回归、真实 H2、官方 CLI 和三机 HA 尚未完成。此前版本的通过继续保留在原范围内。

[本轮完整状态](../../qa/evidence/20261104/r17-dual-source-public-probes-r1/root-review/current-state.public.json)和[证据原件清单](../../qa/evidence/20261104/r17-dual-source-public-probes-r1/root-review/packet-manifest.public.json)保留可复核出处。本轮挂载 25 个整件证据包，共 522 个文件条目、7,365,004 字节、97 个 Merkle 目录，并补入独立根审查、两次后续残留观察及 CI 原件。R16 之前的文件、失败、未知结果和历史正文均保留。

| 工作线 | 本轮实际证据 | 下一步与边界 |
|---|---|---|
| Mac 正常候选 | T5 UUID 在任何候选写入前验证；24,337 B 离线包完整校验后排他创建；源码导入 4.181 秒、35 个归属子进程全部回收、完整 fsck 通过 | 正常构建作业 `1a1a9eb00ff-fc05-39a5` 于 04:15:58 UTC 仍为 running；尚无 release、libtest 或新测试通过结论 |
| ROG 正常候选 | 导入 16.223 秒、50 个归属子进程全部回收；150 份命令／输出原件与 27 份原 SDK 已闭合；两份实际 NUL 索引各 3,913 项与 canonical 树逐项相同 | 首次构建在旧缓存路径解析处已知失败，Cargo 尚未执行；准备新的独立缓存入口，保持原预算 |
| Mac AuthBus 前置条件 | 新公共对照证实系统 ps 的 Popen 返回 errno 1；同字节普通权限副本已启动但 exit -9，随后完成回收。本轮所有子进程、FD、T5 和源码／工具前后围栏闭合 | 普通副本不能作为可用替代。下一步研究原生只读进程元数据接口；不复制系统工具、不修改签名、不放宽沙箱 |
| H2 与官方 CLI | curl 的固定实际版本输出确认 HTTP2 能力；独立审查发现它不足以单独证明严格不重试及线路 EOS，正在准备独立 Rust H2 客户端和真实 fixture | 尚无新 H2 产品请求；小 fixture 将与正式 34MiB、官方 CLI 五窗口分开计量；原 B01 的 ALPN 和服务端完成边界仍未知 |
| CI 与全量范围 | 新建草稿 PR153，给 df026 的 head 和 prospective merge 启动独立完整资格任务；PR152 保持原 head 和原任务 | 04:16:29 UTC 两个 PR 的四个 job 均前 9 步通过、完整 workspace 测试运行中；strict Clippy 和其余门槛待完成 |

### 源码导入已核验，正常产物仍待取得

两台工作树均为 3,913 个文件、62,212,769 字节，完整叶索引 SHA256 为 `e7fee633b64acffd6520587c85ff6f4206e0b12c7db42a0cdeb36dff66350d54`。旧495源码保持不变，新仓库没有 alternates 或共享对象硬链接。ROG 的实际 ls-tree 与 ls-files 原始 NUL 数据分别为 450,325 B 和 438,586 B，14 个版本固定的二进制读取块全部闭合，派生 Base64 归档也从原块独立重算。Mac 当前已核核心结果和完整终态，35 命令的所有逐件原始日志仍需归档。

Mac 采用现有目标缓存；固定锁文件实际存在，launcher 仍必须通过空闲目标及非阻塞排他锁检查。release 和 libtest 各 1,800 秒、原测试组各 600 秒、外层 8,280 秒均保留。新增7项与9项各在独立600秒总组预算内，并夹紧同一外层绝对期限；launcher 到 runner 保持同 PID exec，不重置外层起点。

ROG 首次构建 `1a1a9d78f65-fc05-3884` 为明确 exit1、完整持久日志，stdout 0 B、stderr 693 B，失败发生在 TARGET.resolve，早于 admission 目录创建、Git freeze 和任何 Cargo。路径字面与先前已运行的原 launcher 相同。随后一次只读诊断实际核对 25 个固定路径：只有 target、其 release 和锁文件为 ENOENT；父 runtime、Cargo home、精确1.98工具链及旧3cb保留产物仍在，三份旧公共结果共39,172 B保持原完整SHA。没有扫描替代目录、重建旧缓存或删除旧文件。新缓存方案尚未执行，原1800/3600/12000秒预算不变，未来结果会明确记录新缓存条件。

### Mac 两轮公共探针各自保留原结论

第一轮 devnull 探针证明原策略拒绝读 /dev/null，而仅补充该固定路径读规则后，打开、字符设备、EOF和关闭均成功。随后嵌套 diskutil 的 Popen 返回 PID11754，但 custody 捕获和清理均在 PermissionError 处中断；**其原始 custody、退出码和 reap 仍未知**。外层三个归属进程已收尾，不足以补成嵌套进程成功。之后独立只读观察发现该 PID 不在，并在两份数值投影中均未发现 PID／PPID／PGID11754 的行；这些是后续时点的无残留证据，不替代原退出记录。

第二轮 ps 对照作业 `1a1a9e1e367-fc05-390e` 使用同一 patched policy、同一45秒共享期限和60秒外层。系统 ps 在 Popen 阶段被拒绝且没有返回子进程；新副本返回PID26981，communicate得到exit -9，子进程已reap、双流关闭、双流均为空。本轮三个外层归属进程全部exit0并回收，group为空，无信号发送；源码和系统工具前后完全相同，所有FD和T5句柄闭合，整体0.373秒。整体正确保留为**已知失败**，四项 kernel 拒绝检查未执行，不计作通过，也不据此断言唯一setuid、签名或实际spawn分支原因。该新探针没有读取当前数据库或凭证，也没有启动consumer。

### 仍需完成的用户目标

原 X230 在495上的31项、17个大值活动版本、19个生命周期版本和35,742,423 B恢复证据保留。三机原B2的91/98和最后ROG冷解封失败仍未关闭；源码观察器与H2修改必须由新正常产物和真实请求证明。所有客户端、当前备份路径、独立可信凭证来源、精确生产API／CA／角色凭证／策略／监督器绑定，以及每台真实读写、重启和逆向回滚仍是实际切流前的必需工作。

本轮未初始化、解封或装载生产目标，未切流，未删除旧服务或二进制；未调用J3160、模型、provider、refresh或quota接口。69个既有案例／13类仍只是已测范围，2.7.1全部路由、操作、配置和生命周期的覆盖分母尚未建立。最终只保留最新版 HeptaBao 服务的目标仍在执行中。

## 当前 R16 检查点：统一候选已冻结；H2 工作线程修正待实际资格；Mac 拒绝发生在当前凭证采集之前

更新于 2026-11-05T03:34:14Z。**全量替代 OpenBao 2.7.1 仍未达标。** 新统一候选 `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`（树 `424463ccd2310ddc1e7b2bbcd7b7af29ae58c825`）已冻结并建立独立源码分支。它以当前 PR152 的 6304 为父提交，纳入正常构建所需的原 fresh-ingress 观察、冷读静态阶段、H2 工作线程修正及相应组件测试。3913 个文件、358 个 Merkle 目录已整件核验；父树3908个文件不变。Mac 和 Linux 的新构建及运行结果尚未形成，旧版本的通过不转移到此候选。

[本轮完整状态](../../qa/evidence/20261104/r16-cold-h2-candidate-mac-sandbox-r1/root-review/current-state.public.json)和[证据原件清单](../../qa/evidence/20261104/r16-cold-h2-candidate-mac-sandbox-r1/root-review/packet-manifest.public.json)保存可复核出处。R15 全部旧文件与历史记录保留；下方各历史段落的“当前”仅指其原始时点。

| 门槛 | 本轮已获得的证据 | 仍须完成 |
|---|---|---|
| KV2 正式存储、迁移和恢复 | 保留 X230 在495上的原31项、17个大值活动版本和19个生命周期版本；原 Phase B Git 导入21命令的63份原始日志已补齐，tree/index3911项一致、完整fsck通过 | 新统一产物上的正式迁移、官方2.7.1 CLI 保存/恢复/重启、当前生产数据及全部备份路径 |
| 三机 HA | 冷恢复原控制流和预算不变，新加20个静态观察阶段；保留原B2 91/98失败和已验证的338文件/35,742,423 B恢复事实 | 新产物实际断主、自然选主、ReadIndex、持久化、重启及最后节点冷恢复；观察器源码本身不算关闭故障 |
| H2 / 官方 CLI | 已定位 fresh-ingress 内该错误的唯一源码生产点为 blocking-worker guard；H2 原调用处于 Tokio entered worker，新源码把同一同步调用交给实际join的独立线程，guard不变；6个组件已写入 | 明确协商h2的真实KV2及原生快照，再独立完成官方CLI原五窗口；旧B01的完成边界仍未知，旧日志缺少ALPN/请求ID关联 |
| Mac AuthBus | QA20目录成员修正已实际完成；R4唯一实际运行已知exit1，当前生产数据库尚未打开，consumer/service未启动，归属子进程/FD已关闭 | 公共小探针确认/dev/null读权限缺口，再按新鲜目录和新的确切载体完成真实当前凭证、TLS/AppRole/KV/Policy/续期/撤销及逆向恢复 |
| 逐台切换和旧版清理 | 四台当前有限配置与历史备份范围的边界继续保留；ROG禁用状态、Pocket隔离通过、X230未确认标准consumer均未改写成生产就绪 | 完整客户端/备份分母、精确生产API/CA/角色凭证/策略/监督器绑定、每台读写重启回滚，然后切流及清理 |

### 新源码与真实运行的区别

ROG 已实际运行固定 rustfmt，对4份输入完成4个 exit0 子进程并回收；原仓库未读写，没有 Cargo 编译和产品运行。最终文件的完整字节、工具前后身份及格式化差异均已验证。冷读2个新组件、原有实际冷缺失/损坏修复案例和H2的6个组件将作为独立9项执行，原44项与既有7项保持原分母。

H2修改保留原825字节 Service dispatch 内容、原Instant、原容量归属和实际线程join；spawn失败或过期不进入Service，不重试业务，不放宽 blocking-worker guard。其线程资源成本仍必须由实际测试评估；“每连接最多32”不能改写成全局最多32。源码说明能解释拒绝机制，但没有足够旧线路记录证明B01当时确实协商了H2，也没有证明新CLI已通过。

Mac公开子报告为1299字节、SHA256 `40261a24a49390ba21d3225ac01b16394cbf4cda54b6f3808cd5f47e2d2c3161`：PermissionError、当前生产读取未尝试、命令列表为空，错误发生在命令登记之前。原沙箱只允许写/dev/null，而Popen的stdin=DEVNULL需要新开读描述符；这是可检验的具体缺口。由于原件没有errno和精确阶段，目前不把它称为已证实唯一原因。外层已经读取冻结凭证来源并构成私有投影，不能声称整个R4都没有读取任何凭证材料。新的探针仅针对公共代码、固定工具和自有新目录，不复放R4，也不读取当前生产数据库。

### CI、范围和下一轮条件

PR152仍为草稿，head保持6304。03:27:52 UTC所见两个job的格式和前9步通过，完整锁定workspace仍在运行，strict Clippy和剩余门槛待完成；未取消或重跑。新df026分支没有继承这两条CI资格。已有69个实际案例/13类只能证明其有限范围，旧“complete surface”语料目标仍为2.6.2，插件注册数不是2.7.1全部路由、操作、配置和生命周期的覆盖分母。

本轮挂载13个完整子包，共515个文件条目、12,539,392字节、95个Merkle目录，以及独立根审查、源码来源和SDK原件。所有既有未知结果、已知失败、真实凭证/客户端/备份范围缺口继续保留。当前未初始化、解封或装载生产目标，未切流，未删除旧服务/二进制，也未达到只保留最新版服务的最终状态。


## 当前 R15 检查点：原日志定位到更具体的失败路径；Mac 目录缺项已观测；CI 测试 lint 修正已提交

更新于 2026-11-05T02:53:56Z。**全量替代 OpenBao 2.7.1 仍未达标。** 本轮完成新 Phase B 的实际 stage、prepare 和唯一 B01 运行；B01 返回 503、归档不存在、服务端完成边界仍未知，后续保存/恢复及冷启动没有执行。HA B2 的完整 49 对请求原件已闭合，原节点日志进一步提供冷恢复和请求计时证据。Mac 的两个公开源码父目录及读取容量身份问题已经形成窄修正源码，但追加作业在 QA 成员集合检查处退出，实际没有写入或读取私有凭证。新 CI 源码只改八个测试文件，已发布到 PR 152 的草稿分支。

[本轮完整状态](../../qa/evidence/20261104/r15-cold-diagnostics-phaseb-mac-ci-r1/root-review/current-state.public.json)与[证据原件清单](../../qa/evidence/20261104/r15-cold-diagnostics-phaseb-mac-ci-r1/root-review/packet-manifest.public.json)保存确切出处。R14 的全部旧文件与历史记录保留；下方历史段落中的“当前”仅指各自时点。

| 门槛 | 新的实际证据 | 当前未完成部分 |
|---|---|---|
| KV2 正式存储、迁移和恢复 | 保留 X230 在 495 上独立原 31 项、17 个大值活动版本及 19 个生命周期版本的已有结果；3cb 正常产物在 desktop 的 stage 和 prepare 已实际通过；新 Phase B 原 69 对 HTTP 记录完整 | 官方 CLI B01 保存返回失败且输出归档不存在，B02–B05、当前生产迁移及全部新备份路径仍未完成；原生 V6 归档不等同 OpenBao 状态归档互操作 |
| Mac / ROG / Pocket4 HA | B2 原 91/98 通过；338 个引用文件、35,742,423 B 的 Pocket4→空 Mac 主节点恢复及 17 大值版本保留有原件；49 对请求均有已知传输结果；同一原节点日志的安全计时投影已完成 | node2 冷解封仍是已知 503，7 项原检查缺失，另列 12 项未执行；完整恢复后重启回归尚未通过 |
| AuthBus 独立凭证来源 | 40 个公开代码别名、43 个父目录和全部目标元数据核对完成；只对两个实测父目录建立精确例外，私有输入守卫和读取容量不变；QA 有界元数据观察实际完成 | Mac 当前凭证捕获、五 agent 消费、TLS/AppRole/KV/Policy、续期/撤销、重启及反向恢复仍未进入；此前 Pocket4 的独立结果不转移为 Mac 资格 |
| 逐台切换 | Mac、ROG、X230 既有有限观察继续保留；本轮所有业务测试作业均已终止并回收其拥有的资源 | 当前所有客户端、服务包装层及备份尚未完整盘点；逐台真实凭证读写、重启和回滚未全部完成，尚未切流 |
| 旧版清理 | 新增失败原件、具体修正及诊断均保留，未将未知或未执行项目改成通过 | 所有客户端与备份迁移的前提未满足；旧 OpenBao、旧 HeptaBao 服务、二进制与中间资产均未删除 |

### 1. HA：同一停止日志补齐正常计时，保留具体因果边界

B2 的 49 对原始请求共 39 个 200、8 个 204 和 2 个 503。一次 503 是原 quorum 拒绝，最终一次是 node2 冷解封；没有未知传输结果，也没有重放。16 个启动过的服务身份、6 个 Mac 前台会话均已闭合，原停止预算未增加。原独立 128 项、独立 98/98 与本次 91/98 分开保留。

第一次只读投影取出了 6 条原有正常标记。后继解析器对精确 495 源码增加正常请求计时的封闭字段集合；源码复核发现 cold 路径也会调用 `codec/open_committed_read`，因此在未运行的 39 对版本上仅追加这一对，最终封闭为 40 对。原稿、单行差分和实际选定组件结果均保留。

唯一后继诊断作业 `1a1a997c484-fc05-3636` 返回 exit 0，完整输出 50,742 B。原日志仍是 37,545 B、相同 whole SHA256 与全部十项身份字段，原 6 条标记逐对象一致；新增 99 条计时由 96 条 health 和 3 条 ordinary 组成，73 行未选择内容没有输出。6 个 FD 全部关闭，实际约 1.8 毫秒，仍在原 15 秒预算内。

最后两条记录分别是第 177 行 unseal 503（state、barrier、record root、activation 均为 false），以及第 178 行 ordinary 503 计时。后者总耗时 9,414,388 微秒，ReadIndex 为 31,924 微秒，changed-root recover 为 9,369,972 微秒，final witness 与该 scope 均记录 completed，退出时原期限仍余 4,580,997,890 纳秒。**这些是同一原日志内相邻的具体记录；ordinary 类别与行顺序本身没有提供请求 ID 或路由关联。** 没有 failed 桶也不能证明后续本地状态加载成功。冷加载中未记录正常阶段标签的本地选择、根绑定、安装、物化和最终检查仍需继续区分。

### 2. Phase B：真实保存失败，安全日志将范围缩小到 fresh-ingress closure

3cb 正常构建的本地 stage 作业 `1a1a96c027d-fc05-3519` 和 prepare 作业 `1a1a97d2685-fc05-3584` 实际通过。绑定 SHA256 为 `778697b6…`，prepare 结果 SHA256 为 `155f4d30…`。独立源码导入中的全 fsck/3,911 blob 核验属于此前独立导入，不能记作 prepare 再次运行。

唯一 live 作业 `1a1a983309e-fc05-35aa` 在约 20.86 秒完成正常 V5 种子到原生 V6 的测试设置，84 个动态不变量通过。实际主节点 1 上的 B01 官方 CLI 保存随后 exit 2，用时约 231.68 毫秒，没有超时，输出归档不存在。节点 1 审计新增 request 61 / response 62，状态为 503；观察器没有认证审计 MAC，也没有观测 CLI 响应的 HTTP framing，所以服务端完成边界仍标 UNKNOWN。私有 CLI stderr 仅保留 178 B 的尺寸及摘要，正文没有读取。B02–B05、冷重启与重放均为零。

全部 69 对设置/前置 HTTP 请求均早于 B01：66 个明确长度响应、2 个正确无正文的 204，以及一次连接前失败且未发送请求。所有请求的原 15 秒预算均满足。84 个拥有身份的子进程全部回收，19 项输入前后精确一致，最终清理无错误。公开原件的固定字面量扫描为 150 成员、9 个输入、129 变体、零命中；这不是通用秘密检测证明。

新的只读诊断仅访问节点 1 已停止的 4,577 B 日志，严格绑定原十项元数据与 whole SHA256。唯一作业 `1a1a99b05aa-fc05-364b` 实际 exit 0，输出 12,843 B，7 个 FD 全关，约 1.9 毫秒。第 9 行的已观察失败是 `fresh_ingress_same_root_closure / fresh_ingress_read_refused`，该步 7 微秒，原期限仍余 14,993,533,703 纳秒；第 11 行计时记录该步 failed，此前 permission、runtime、storage、ReadIndex 与 enrollment 阶段均已推进。对精确 3cb 源码的 20 个公开固定 Display 字符串逐一计算摘要，只有 `HaError::InvalidCluster` 对应的 `HA cluster configuration is invalid` 精确匹配原 reason SHA。此检查点尚未把该枚举指定为唯一内部 guard，也没有凭 ordinary 标记将它自动关联为 B01 请求；B01 的 UNKNOWN 原判定不变。

### 3. Mac：公开路径修正保持窄范围，当前阻塞在完整 QA 清单

公开元数据观察确认原父目录规则仅拒绝 `/opt/homebrew/lib` 与 `/opt/homebrew/Cellar`。后继输入库只在原先冻结的 40 项公开代码语境内，绑定这两个父目录的完整九项身份；所有一般路径和私有输入规则维持原约束。另一个具体错误是把同一公开文件以不同读取上限登记时，将上限也算进“文件身份相同”；修正分开比较身份与上限，实际 8 MiB / 256 MiB 以及总量限制继续执行。

R4 追加的计划仍只有三个新文件，旧的 18 份源码和三个公开文档均须原样保留。实际作业 `1a1a98ec7b8-fc05-35fb` 在最先执行的 QA 复合检查处 exit 1，错误为 `exact_qa_members_no_unlisted_entries`，零新增文件、零私有输入、零业务进程；唯一 diskutil 子进程和所有持有描述符均已闭合。21 项旧文件身份检查和 9 个运行目录缺失检查尚未到达，不能将它们标记通过。

后续单次有界元数据作业 `1a1a998e315-fc05-363f` 只观察固定 QA 目录，不递归、最多 32 成员。实际目录共 20 项：原 18 项全部存在，162 个旧文件身份字符串逐项不变，另有 3,405 B 和 4,691 B 的两个普通文件。目录完整身份稳定，但相对原 18 项清单的 count 和 set 均为 false。44 次显式元数据调用、6 个目录 FD 与 iterator 全部闭合；没有读取文件正文、私有凭证、网络或启动子进程。该观察说明当前清单不完整，不追溯改写此前复合谓词究竟哪一项失败。下一修正必须将有既有出处的旧公开回执精确纳入保留集合，并保留严格的追加前后成员检查。

### 4. CI：旧完整测试已通过，八处测试 lint 修正进入新草稿提交

旧 e5de554f 的 head 与 prospective merge 两条 CI 均完成格式检查和整个 locked Rust workspace 测试，随后同时停在相同的 18 个测试代码 Clippy 诊断。完整两份终态日志已保存，原先仍在进行中的日志快照不再被当作挂起或终态结论。

新提交 `6304a898192bfdf7eabec3c4ea40f7166e59a137` 只更改八个测试文件，其他 3,903 个 blob 不变；namespace 模块的生产代码前缀逐字相同，没有增加 lint 忽略、产品逻辑改动或延长预算。改动保留断言语义：等价长度条件、显式 Err 断言、静态类型别名、请求参数分组，以及用于故意 unwind 的原测试语义。固定 rustfmt 作业的八个 stdin 子进程全部 exit 0 并回收，格式化结果逐件完整回读。

截至 2026-11-05T02:47:18Z，新 run `41955523659` 的 head/merge 均已通过格式检查，正在运行完整 workspace 测试。新的 strict Clippy 及后续全部接受门槛仍待结果。PR 152 继续保持 draft/open/unmerged；495、3cb 与 6304 三条源码边界的运行资格不互相继承。

### 5. 证据范围与下一步

本轮归档 23 个完整证据包、903 个包内文件项、20,944,737 B，逐包核对 whole bytes、SHA256、Git blob 身份和 126 个目录 Merkle。原始 SDK/native payload 和不安全整数的原文均保留。检查点只新增本轮记录并更新顶层时点，旧索引字段及既有证据文件继续保留。

继续推进的具体工作是：将 Mac 两份原公开回执加入完整保留清单并完成真实凭证闭环；精确区分 HA 冷加载的未计时失败段；核清 fresh-ingress InvalidCluster 的触发 guard 并修正其执行边界；等待新 CI 的原流程终态。随后仍须执行每台当前凭证读写、重启、回滚、客户端及备份迁移和正式切流。既有 69 条、13 类官方 2.7.1 有界语料与旧 59 条 2.6.2 语料均不是完整 2.7.1 的 route × operation × configuration × lifecycle 分母，完整替代资格保持 false。


## 当前 R14 检查点：完整源码已独立导入；HA B2 恢复通过后在 node2 解封失败；Mac 当前输入受目录守卫拒绝

更新于 2026-11-05T01:56:28Z。**全量替代 OpenBao 2.7.1 仍未达标。** 本轮把 3cb 的正常构建源码与产物带到 desktop，并完成独立 Git 导入；HA B2 实际原 91/98 通过，真实 Pocket4→Mac 恢复及 17 个大值版本保留通过，随后 node2 冷启动解封得到已知 503，新增 12 项尚未进入。Mac 完整 18 件测试源码的修正、审查、实际落盘与逐字回读已完成，五 agent 当前凭证闭环作业已实际启动并在公开源码父目录校验时拒绝，尚未读取私有凭证或启动消费者。生产初始化、解封、载入、切流及旧资产删除均未进行。

[本轮完整状态](../../qa/evidence/20261104/r14-ha-prepare-source-import-mac-caller-r1/root-review/current-state.public.json)与[原件目录清单](../../qa/evidence/20261104/r14-ha-prepare-source-import-mac-caller-r1/root-review/packet-manifest.public.json)提供确切来源。既有 R13 及更早证据继续保留；下方历史内容中的“当前”均指各自记录时点。

| 门槛 | 本轮实际推进 | 尚未成立的资格 |
|---|---|---|
| KV2 正式迁移与恢复 | 23,335,023 B canonical bundle 和原出口收据已传入 desktop；独立源目录实际完整 fsck 3,755 commits、逐件核验 3,911 tracked blobs，21 个 Git 子进程及所有持有 FD 已回收 | 新 Phase B 的 stage、prepare、真实官方 CLI 保存/恢复尚未执行；原 21×3 命令日志的独立归档仍在补齐。当前生产迁移与新异机备份未完成 |
| Mac / ROG / Pocket4 HA | B2 原 91/98 true；真实自然选举、故障转移、ReadIndex、全节点既有冷启及 Pocket4→空 Mac 主节点密文恢复均有本轮结果；338 个引用文件/35,742,423 B 恢复校验通过 | node2 后续冷解封返回 503，7 项原检查缺失，恢复后另列 12 项未进入。B2 资格为失败；此前独立 98/98 和 128 项结果不相加冒充本轮完成 |
| AuthBus 脱离 J3160 | 18 件完整源码仅修正 3 处已知连接问题，其他 15 件逐字不变；15 个新文件实际 create-only 落盘、6 件旧源码 54 项身份值不变；实际 OpenSSL help 确认重复 -addext 选项 | Mac 作业 1a1a968c3e6-fc05-3501 已知 exit 1，公开 SDK 父目录校验拒绝，具体哪一层仍待只读定位。当前凭证来源、真实消费者、续期/撤销、冷启与反向恢复仍必须以本轮实际终态为准；QA launchd 不代表生产 KeepAlive 资格 |
| 逐台切换 | 已有 Mac / ROG / X230 有限观察及本轮源/凭证守卫继续保留；ROG 当前配置变化仍单列 | 全部客户端、服务 wrapper、当前备份与逐台真实凭证读写、重启、回滚未全部完成，尚未正式切流 |
| 旧版清理 | 历次失败、来源、控制源码与现场证据完整保留 | 清理前提未满足；旧 OpenBao、旧 HeptaBao 服务和二进制均未删除 |

### 1. 真实 HA B2：准备成功，恢复后 node2 解封出现已知 503

B2 先通过独立 inert 与 prepare。prepare 绑定 49503322 / 1d4211f9 的正常 Mac/Linux 二进制、10 个构建文件与 28 个既有比较证据；实际 prepared SHA256 为 9fb7bb1054a554357232c8847e36b1a20d2339455a4f6ea7a2c1f37885c1f5af。唯一 live 作业 1a1a95f8b98-fc05-34b1 返回 exit 1，日志完整、持久化，无超时或自动重试。

准备阶段新增的一次 owned CAS=0 写入和一次 metadata DELETE 分别返回 200/204，Mac 逐值读取和 data/metadata 缺失确认完成。新前沿实际走原 higher-term 分支，从 (term=2,node=2,index=61) 前进到 (3,3,66)，准备耗时 19.7806607009843 s，在原 60 s 内；新 same-leader 分支本轮没有实际覆盖。之后真实选出的空主为 Mac1，密文源为 Pocket4，17 个大值版本和所有引用文件均恢复通过。

随后序号 49 的 node2 /sys/unseal 返回已知 503，耗时 9423.826 ms；错误为 node_2_native_cold_unseal_failed，尚未确定内部原因。49 个已记录变更 intent 对应 49 个已记录响应，unknown transport count 为 0；完整 98 个变更边界原件及 SDK 仍在收集，不能将 summary 事件当作全部 HTTP 或最终提交状态。根审独立核对 16 个启动身份各自有对应停止记录、6 次 Mac 运行的本地和远端 group 均空且 leader 已回收、全部原 5 s 停止期限满足，故释放 HA 窗口。

[B2 终态核心原件](../../qa/evidence/20261104/r14-ha-prepare-source-import-mac-caller-r1/ha/postcold-b2-terminal-core/summary.json) · [根审与清理结论](../../qa/evidence/20261104/r14-ha-prepare-source-import-mac-caller-r1/root-review/ha-b2-terminal-core-root-review.public.json)。原 2400 s、另列 300 s、HTTP 15 s、admission 8 s 均未增加；未强制选举或重放解封。

### 2. 3cb 源码已实际传输并形成独立 canonical 工作树

源码传输作业 1a1a94b59e2-fc05-33df 成功，发送端、接收端及 relay 三个 owned group 全部回收，原 300/90/10 s 边界保留。standalone import 作业 1a1a9579588-fc05-346f 成功，35.39883295306936 s 内完成本地 bundle 导入、完整历史/树/索引/逐文件字节检查与 fsync；独立新目录为 normal-phaseb-ingress-observer-source-r1。21 个 Git 命令中 19 个 exit 0，两个既定 absent-config 查询 exit 1，均属原合同；未联网 Git、未编译或启动产品。

根审已核完整 core、权威终态、输入身份、FD/进程回收和分块 stderr。21×3 命令日志的独立原件归档另行完成，不用重复 import 代替。Phase B stage/prepare/live 的 34 件具体源码及精确请求已冻结，根已全文审查 create-only stager、逐字核对 8 个 carrier 成员和精确请求，并严格逆向验证其 14 处字面量替换还原旧源码。Mac 清理完成后已准许唯一 local stage，截止本记录尚无 ACK；prepare/live 未准入。binding 与 prepare 的两个未来 SHA 必须由实际前置步骤产生。旧 B01 FAIL_UNKNOWN 原件保留，新流程不得重放旧根或放宽原预算。

### 3. Mac 完整源码已审查、落盘；真实运行在公开 SDK 目录校验阶段拒绝

修正的三个问题分别为：临时 socket 的一次性关闭与 unknown 汇总、移除未使用且未包含在 18 件来源中的旧 helper 名、对齐一个 model digest 消费者与原捕获器的末尾换行。原 capture 库、全部私人输入守卫、CAS 和业务期限均未改。13 个 socket 局部检查与原 36 个跨模块检查均只属于源码检查，不当作真实消费者证据。

实际 inert 作业 1a1a95b43fe-fc05-3490 exit 0，0.24171037506312132 s 完成；15 个新文件逐字回读，6 件旧源码不覆写，T5 27 项身份锚与 UUID 保持，唯一 diskutil 子进程及全部 FD 已闭合。三个 MCP response snapshot 明确为缓存对象快照，其中 native payload 原字符串保真，不声称原 RPC wire 序列化。实际 OpenSSL req -help 返回 exit 1、完整 stderr 2459 B，广告了 -addext；这仅证明选项存在，不证明 TLS 证书已生成。

根审之后唯一启动当前五 agent 作业 1a1a968c3e6-fc05-3501，精确请求 bd112cd7 与冻结源码 proposal 完全相同，reused=false。该作业实际在 0.25087299989536405 s 后返回 exit 1/full/durable，无超时或未知结果。19 个公开来源记录、15 个 alias 已通过，InputRefused 堆栈指向 readonly_input_parent_custody_or_exact_held_anchor；原 errorCode 为 null，具体失败目录尚未记录，因此不能说成已证源码 hash 变化。私有冻结输入、生产 SQLite、消费者与服务均未启动。唯一 diskutil 子进程及 T5、输入和外层 FD 全部关闭。四个可信凭证来源、900 s 剩余有效期、不可变 SQLite 捕获、真实 native SDK、QA launchd 冷启和反向恢复仍待实际完成。新外层 900 s / supervisor 1080 s、manager 600 s / cleanup 60 s、每阶段 120 s、捕获 45 s、native 15/8/3 s 均保持原合同。

### 4. 版本、CI 与全量分母

已获限定运行证据的 49503322、单独正常构建 44＋另列 7 通过的 3cb87391、PR152 当前 e5de554f 分开记录，资格不继承。CI 41937740513 在 2026-11-05 01:53:06 UTC 仍为两条 workspace 测试 lane 执行中；fmt 已通过，严格 Clippy、实际新布局大小、后续门禁与完整 CI 尚无通过证据。

OpenBao 2.7.1 范围续稿保留旧 59 项属于 2.6.2、69 项只覆盖 13 个 family 的事实。官方 registry 名单与路线映射只提供下一步依据，仍不是 route × operation × configuration × lifecycle 的完整运行分母。当前 credential/service/backup 迁移、全量替代、生产切流及旧版清理布尔值全部为 false。

本检查点新增 26 个证据包、596 个包内文件条目、11302670 B，逐 blob SHA1/SHA256 和 113 个包内 Merkle tree 已核；原始纳秒整数与原文不通过 JSON.parse/stringify 重写。状态文件和索引新增段是派生说明，旧检查点索引字段保持原值，仅顶层 as_of_utc 更新。

---

## 以前的检查点（按原文保留）
## 当前 R13 检查点：Mac owned SQLite 7/7、源码导出与三产物传输通过；完整替代尚未达标

更新于 2026-11-05T01:07:56Z。**本轮完成了 Mac 七项 owned SQLite 回归、六个系统工具的实际文件绑定、3cb 完整 canonical 源码导出，以及三个正常构建产物向 desktop 的传输。ROG 的 46 项固定观察全部完成，但旧配置 pin 已失配，因此该作业仍如实记录为退出 1。全量替代 OpenBao 2.7.1 的资格仍为 false。** 当前未进行生产初始化、解封、载入、切流或旧资产删除。[本轮完整状态](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/current-state.public.json)保留逐项来源和候选版本。

| 门槛 | 本轮实际推进 | 尚未成立的资格 |
|---|---|---|
| KV2 正式迁移与恢复 | 3cb 正常产物仍绑定原 44＋另列 7；完整 23,335,023 B Git bundle 已导出，三个公开运行产物已实际传到 desktop | canonical bundle 尚未传入并独立导入 desktop；新 Phase B stage、prepare、真实 CLI 保存/恢复及当前异机备份仍待完成。旧 B01 UNKNOWN 原件继续保留 |
| Mac、ROG、Pocket4 HA | 新 B1 的完整 SDK 与 45 对变更账本已全部核验，失败位置明确；同 leader 新前沿的狭窄准备方案已按确切 OpenRaft 源码审查 | B1 原 83 通过、15 未执行，新增恢复后冷启 12 项尚未进入；修订版还须重新完成真实原 98＋另列 12 |
| AuthBus 脱离 J3160 | Mac R2 实际 7/7，通过最后源文件/runtime 再核验；六个系统工具实际文件 pin 已收齐 | 七项只触及 owned SQLite fixture；五 agent 当前凭证捕获、实际消费者闭环、launchd 重启与回滚尚未执行 |
| 逐台切换 | ROG 46 个固定条目、17 轮 metadata pass、4 个查询和最终进程检查均已完成；当前配置变化获得独立二次核实 | 有限清点不等于所有客户端已迁移。每台真实凭证读写、重启、回滚及正式流量切换仍未完成 |
| 旧版清理 | 原失败、UNKNOWN、旧服务和可恢复资产均保留 | 所有客户端与备份路径迁移条件尚未成立，尚未达到“只保留最新版 HeptaBao 服务” |

### Mac 七项实际回归的范围

R2 inert 作业 `1a1a916944c-fc05-3131` 和 synthetic 作业 `1a1a918c6cf-fc05-3143` 均为权威退出 0，输出完整、持久化，无外层超时、取消或重试。七项实际耗时 0.23113099997863173 秒，小于原 45 秒 controller 限额。七项依次覆盖：sidecar 缺失、空 WAL/SHM、拒绝非空 WAL、拒绝 rollback journal、拒绝超大行、已持有 inode 漂移拒绝，以及真实 immutable SQLite 连接拒写。实际打开并关闭的连接数为 `[1,1,0,0,1,0,1]`。第六项命中了原生产库的 `current_input_fd_name_or_metadata_changed`，未放松任何 hold/verify 定义；第七项及最终再核验本次确实执行。[根审阅](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/mac-r2-actual-root-review.public.json)与[原始七项输出](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/mac/sqlite-r2-synthetic/stdout.original.json)保留完整证据。旧 R1 的 5 通过、1 失败、1 未执行继续作为独立失败记录。

六个公开系统工具已逐个取得 regular-file 完整 SHA-256 和九字段身份，合计哈希 3,878,912 B；`/bin/ps` 实际 mode 为 04755，`/sbin/mount` 为 0555，未把它们假定为普通 0755。[工具观察包](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/mac/public-utility-observations/)是独立时点的文件观察，不能宣称原子快照或共享库验证。Mac 当前配置二次观察仍为 34,851 B / `ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d`。完整 outer 和 peer 审查仍在源码阶段，生产输入没有因为七项测试通过而自动获得执行资格。

### 完整源码导出与实际产物传输

3cb 导出作业 `1a1a928b8b0-fc05-321b` 退出 0，core 耗时 3.3535300320072565 秒 / 原 300 秒。27 个具名 Git 子进程全部已回收且无残留，其中 25 个退出 0，另外两个 `git config --get-regexp` 以退出 1 明确表示不存在 partial 配置。完整 strict fsck、3,755 个 commits、唯一父链、源 HEAD/tree/refs/origin、非 shallow、无 alternates/grafts/partial 及前后 clean 检查均通过；没有构建、启动产品进程、联网或导入 desktop。bundle 为 23,335,023 B，SHA-256 `25020ee42fe92f95c9408cb937dc507430f18b84fdaef7ec438a0a233de1438b`，零 prerequisite。[151 件原包](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/snapshot/canonical-export-actual/)和[全量根审阅](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/phaseb-3cb-source-export-full-root-actual-review.public.json)包含原 SDK 分页、27 组 record/stdout/stderr 与精确字节绑定。

传输作业 `1a1a92c7f34-fc05-3248` 退出 0，耗时 2.3843565040733665 秒 / 原 300 秒。仅传输 server（109,074,848 B / `437723d26976b23628a5b5058b4b89e00923b8e0f1b9604045a47e8e34459da0`）、794 B native report 与 3,200 B release report。三个文件的源端、传输流和目标同一 fd 读回大小与哈希逐项相等；原 SSH trust pin 和控制源文件前后不变。三个本地 owned group 与两个远端 endpoint 均完整关闭，unknown=false。[38 件原包](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/snapshot/artifact-transport-actual/)与[根审阅](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/phaseb-3cb-artifact-transfer-full-root-review.public.json)支撑这项传输资格。它尚不构成 canonical 源码导入或新 Phase B 运行成功；旧 B01 `1a1a8177aec-fc05-2da5` 的 UNKNOWN 没有被重放或改写。

### ROG 当前配置变化的实际证据

ROG inert 作业 `1a1a92b2b52-fc05-3236` 已退出 0。实际有限清点 `1a1a933167b-fc05-3294` 在 0.10996575400349684 秒内完成原 46 项观察：19 项 read-verified、25 项 metadata、2 项经父目录校验的缺失；17 轮 pass 没有错误，计划 434 次 metadata 调用实际执行 430 次，少的四次源于这两个已验证缺失。四个查询的投影全部完成，连同最终 ps 共五个 owned 子进程均已回收。读取合计 147,072 B / 41 次，没有 SQLite 连接、服务写入或产品接口请求。

该作业仍正确退出 1，唯一失配项为 `f001` 的旧配置 SHA。当前配置为 21,229 B / `6e3659907327039243c60a10b2925edb51e83e4c73f0925c60279ae6a8169819`，独立后续 file_info 获得相同完整哈希和精确 version。当前六 agent 为 main、azi2、azi3、azi4、azi5、zbj-llm-runtime，primary 均为 `codex/gpt-6.1-sol`；AuthBus enabled=false、generation=203，gateway 当前 inactive/dead、MainPID 0，原 hold dropin 不变。没有推断修改者，也没有恢复旧配置或启动 gateway。[完整实际包](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/inventory/rog-current-readonly-actual/)含原 authority、三页 streams、完整 stdout、根审阅与两台当前配置的独立元数据。后续迁移必须重新绑定这份当前状态，不能把旧 pin 改写为本次已经匹配。

### HA 失败解析与下一轮必须证明的事实

B1 完整 107,216 B summary、退出/launch 文件、权威状态、分页与终端字节已经全部闭合；45 对变更结果均有观察，最后一次只读 health GET 则仍为 response_observed=false。前者 unknown=0 不会被外推为所有 HTTP 请求均已知。[完整原件审阅](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/ha-b-complete-raw-root-review.public.json)保留此区别。停止的 ROG 当时是 follower，Pocket leader 与 Mac 的 committed/applied 仍停在 61；普通停止 follower 不会自然产生新提交。

确切依赖为 OpenRaft 0.10.0-alpha.34，上游 tag commit `dfee06ca9a8193f061149ce784caa6bcbe92a0c4` 的文件成员、完整 tree 与 495 产品 TypeConfig 已核对。当前 advanced LogId 的完整顺序是 `(term, node_id, index)`，pre-vote 会拒绝较旧的完整日志，且不持久写入 vote/term。新方案仅为“同一 leader、vote 不倒退、完整 LogId 与 index 严格增长”添加狭窄分支，保留旧 higher-term 分支；一次 owned CAS0 witness 和一次同 key metadata DELETE 必须各自有已知结果，Mac 实际读值与缺失要验证，任何 unknown 立即停。它仍受原 60 秒方向准备和 2,400 秒 controller 限制，不强制 leader、不重放未知变更、不调整原 98 名称或历史计数。上游 tag 绑定也不冒称机器 Cargo registry 缓存的物理字节证明。[根源码语义审阅](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/ha-same-leader-root-source-semantics.public.json)只接受这个准备方案；真实 Mac 选主、ReadIndex、密文持久化及恢复后冷启仍须运行取得资格。

### CI、版本隔离与证据连续性

截至 2026-11-05T01:06:04Z，PR #152 的 `e5de554f5dfe99f0de30012122fe3e248fb60532`、run `41937740513` 两路格式检查均通过，完整 workspace tests 仍在执行。尚无本候选的新 Clippy 终态或布局实际测量，不使用旧提交的测试成功替代当前资格。[本次读取的原 jobs payload](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/ci-current-e5-jobs.original.json)按原字节保存；旧失败和原命令/阈值保持不变。

已通过的 LAN/KV2/Pocket AuthBus 仍绑定 `49503322`，观察器正常构建绑定 `3cb87391`，PR 当前头为 `e5de554f`。全 2.7.1 表面分母、当前生产数据/备份迁移、逐台真实消费者重启和回滚都尚未完成。本轮附加 16 个不可变证据包、423 个包内文件条目、4,062,776 B，重算 73 个包内 Git tree；[逐件索引](../../qa/evidence/20261104/r13-mac-sqlite7-utilities-source-transfer-r1/root-review/packet-manifest.public.json)记录完整 blob、大小和 SHA-256。原 JSON 纳秒整数保留原始 token，没有普通 JSON 重序列化。此前检查点字段和所有旧证据继续保留。

---

## 历史检查点（截至 R12，以下原文保留）

## 当前检查点：ROG 正常构建 44＋7 通过；新 HA 停在方向准备条件，完整替代仍未获资格

更新于 2026-11-05T00:24:38Z。**本轮已经补齐 ROG 观察器候选的正常构建和原始证据，原 44 项测试与另列 7 项测试分别通过；Mac、ROG、Pocket4 的新回归在方向准备阶段得到明确失败，原 83 项通过、15 项未执行，新增恢复后冷启 12 项尚未进入。全量替代 OpenBao 2.7.1 的资格仍为 false。** 当前没有生产切流，也没有删除旧服务、二进制或恢复资产。[本轮机器可读状态](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/root-review/current-state.public.json)记录每项结论的来源、版本与未完成项。

| 必须完成的门槛 | 当前有证据支持的结论 | 仍须完成 |
|---|---|---|
| KV2 正式迁移和恢复 | 既有 X230 正式 31/31、34 MiB 活跃历史、19 个生命周期版本仍绑定 495 候选；新 3cb 正常构建已经产出实际 server/seed | 实际快照 CLI 的旧 B01 仍为已保留的 UNKNOWN 失败；新入口仅完成实际产物绑定源码。当前生产数据与最新加密异机备份尚未迁移 |
| 三机 HA | 既有两轮原 128/128 与 Pocket→空 Mac 原 98/98 分别有效；新脚本的九源落盘与 prepare 已真实通过，四份 build 回执逐字匹配 | 新作业 `1a1a9094b62-fc05-30ab` 退出 1：在原 60 秒内未观察到更高提交前沿；恢复和新增冷启尚未执行，须修正准备协议并重新获得完整原 98＋另列 12 资格 |
| AuthBus 脱离 J3160 | 既有 Pocket 两 agent 当前消费者闭环保留；Mac T5 五源 inert 真实通过，卷身份和所有 owned 回收已核验 | Mac owned SQLite R1 为 5 通过、1 失败、第 7 未执行；R2 最小测试接入修正已审，并仅按条件准入 owned 验证；尚无七项运行通过。五 agent 凭证捕获、完整 outer、launchd 重启与逆向恢复尚未完成 |
| 逐台切换 | X230 新有限只读清点退出码 0；Mac 的 canonical crontab 缺失观察已有独立原件 | 有限清点不等于整机所有客户端均已迁移；ROG 清点、每台真实凭证读写/重启/回滚及正式切流仍未完成 |
| 旧版清理 | 所有旧现场及备份证据继续保留，失败和 UNKNOWN 均未改写 | 全部客户端和备份路径迁移条件尚未成立，不能将清理或“只剩最新版服务”记为完成 |

### 新正常构建证据与候选版本

`3cb873919170cc77101b27f6a3ab9e98f41f8d93` / tree `7f4d48a647a81ca96e8a24a0a057c2c829459060` 的唯一作业为 `1a1a8b55dda-fc05-2f85`。原 44 个名称与六组原 600 秒限额逐项核验；7 个新增测试严格取自执行源码中的固定名称，另有共享 600 秒限额，实际 0.589543348 秒。28 个独立 owned 子进程全部退出 0、已回收且无残留。release 构建为 666.305 秒 / 1800，libtest 构建为 1080.554 秒 / 3600；整体时间戳差的原整数为 1,812,535,687,089 ns。[根审阅](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/root-review/normal-r3-root-full-original-review.public.json)和[完整 243 件原包](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/snapshot/r3-normal-full-terminal/manifest.public.json)包含全部 child stdout/stderr/record、两份 Cargo 全文、24 份完整 native SDK payload 及 88 个不可变分页。原始 stdout、字节 hex、SHA-256、Git blob 与实际名字均已对齐；工具分页元数据没有被用来冒称客户端 HTTP 交付证明。

| 用途 | 精确版本 | 资格边界 |
|---|---|---|
| 已验证的 LAN/KV2/Pocket AuthBus 正常产物 | `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` | 保留各自已经实际完成的有限范围 |
| 新观察器正常产物 | `3cb873919170cc77101b27f6a3ab9e98f41f8d93` | 44＋另列 7、默认 features、正常构建；尚无新快照 CLI 运行通过 |
| Draft PR #152 当前头 | `e5de554f5dfe99f0de30012122fe3e248fb60532` | 新 CI 正在执行，尚无完整终态；不继承其他提交的运行资格 |

新 3cb server 为 109,074,848 B，SHA-256 `437723d26976b23628a5b5058b4b89e00923b8e0f1b9604045a47e8e34459da0`；seed 为 101,143,984 B，SHA-256 `bdbf53cfebc25d3932aaba3bf608e0459e3399c513bbdeafecde5659eb688689`。新 Phase B 的源码计划绑定这些实际产物；seed 只作为第二构建产物记录，没有擅自加入原主程序未调用的执行路径。[新输入方案](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/snapshot/fresh-phaseb-actual-input-source/manifest.public.json)仍为源码阶段。

### CI 的实际失败与最小修复

旧 `6d3040a` 的 run `41907498576` 两路完整 workspace tests 通过，但严格 Clippy 各报 1,619 个 `result_large_err`：其中 1,616 项对应至少 208 B 的 Response，3 项对应至少 224 B 的恢复 admission failure。保留的 [原始日志](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/ci/original-clippy-failures/)没有被删除或重分类。修复只将私有可选 LocalRedirect 放入 Box，保留取出所有权、序列化拒绝和原期限，并新增两项布局回归；没有调整 lint 阈值、工作流或编译检查命令。

`fab39e28` 的下一轮在两路格式检查中暴露同一处换行差异，后续步骤均被跳过。已按 Rust 1.98 原始输出精确换行提交 `e5de554f`，表达式 token 不变，另外 3,910 个文件及 mode 不变。[格式失败及修复证据](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/ci/response-format-failure-and-fix/response-rustfmt-review.public.json)完整保留。新 run `41937740513` 的 head、merge 均已通过格式检查，在 2026-11-05T00:09:15Z 观察时进入完整 workspace tests；trust-boundary run `41937740490` 已成功。当前仍不声称新 Clippy、布局实际大小或完整 CI 通过。

### 恢复后冷启动与 Mac 当前凭证的剩余工作

[HA prepare 原包](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/ha/postrecovery-prepare-actual/manifest.public.json)的实际摘要 SHA 为 `95162142c09439603c1cc8564f43080b10944696aebe45b31ecdf2ad66263578`。原 98 项名称逐项等于既有成功运行，新增 12 项单列；原 controller 2400 秒、HTTP 15 秒、admission 8 秒不变，新增冷启阶段共享 300 秒且受原 controller 截止限制。只有在恢复密文的同一新现场仍保留历史时，捕获实际引用叶集合、停止三节点、重新启动并验证持久化与 ReadIndex，才能填补这个缺口。没有强制 leader，没有把 98 与 128 相加成唯一案例数，也没有把旧的恢复前冷启算作这 12 项。

本次实际已在 `owned_missing_cipher_leader_recovery` 阶段报 `direction_new_committed_frontier_not_observed`。停止 ROG 前它不是 leader，applied/committed 均为 61；固定 60 秒内的 190 次有限观测没有满足新前沿条件。原 83 个通过项与 15 个 missing 恰好组成原 98 项，新增 12 项为 0；这不是已经进入密文恢复或新增冷启后的失败。权威终态退出 1、输出完整持久化、无外层超时和自动重试。5 个 Mac foreground session 的本地与远端进程组均已回收为空，所有已启动服务都有对应停止事件，tunnel 为 0，源码、构建与 24 个旧围栏不变。[根侧终态及清理审阅](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/root-review/ha-b-root-known-failure-core-review.public.json)和[45 对实际变更请求原件](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/ha/postrecovery-live-mutation-originals/)已保留；后者的 unknown=0 只针对变更账本，不能外推到最后未观察到响应的只读健康 GET。

Mac R1 的 [实际失败原包](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/mac/sqlite-owned-synthetic-r1-failed/manifest.public.json)显示第六项实际返回 `absence_not_reopened_as_present`：测试先持有主文件，再经另一入口重复登记 sidecar 缺失状态，因此提前拒绝，尚未触及预期的 inode 漂移校验。作业退出 1，实际 0.287810625 秒，unknown=false，owned descriptors 与 SQLite connections 已关闭；第七项真实只读连接拒写，以及最后的 runtime/source 再核验未执行。R2 只修正该测试接入并使用新 owned attempt 目录，生产 capture 的 hold/verify 定义保持原样。完整差分、六份输入与旧五源九字段身份已审核，追加源码的唯一 inert 已获 ACK；后续 owned 七项仅在该 inert 完整终态证明满足条件时才获准执行，尚无七项实际通过结论。新 manager/server/phase 首包仅是[源码](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/mac/manager-r3-source-first-packet/manifest.public.json)，完整 outer、capture materializer 和实际 launchd 观察尚未获得运行资格。

### 清点、兼容范围和证据连续性

X230 的固定 18 项、7 个 owned 查询已真实完成；AuthBus proxy 当前 loaded、disabled、inactive/dead、MainPID 0。存在的 OpenBao 2.7.1 oracle 容器为 network none、无挂载和端口映射，这个事实不能单独授权删除。Mac canonical `/private/etc/crontab` 的独立缺失观察，也没有被改写为原 38 项原子清点成功。

OpenBao v2.7.1 官方 tag 的 commit 为 `a5db72cef75c24b920ade02065b18dd8eb666bac`，其实际 commit tree 为 `3a8ba726d8d557a5f9b3f2ed28b406da33632182`。本轮是 30 份一手源码的有限审计；旧 59 项 ledger 仍针对 2.6.2，既有 69 案例仍是 13 个模块族的有界 corpus，均不构成 2.7.1 全表面分母。映射勘误只补正三处既有案例所属关系，没有增加测试数量，也没有取消 native profile 的拒绝边界。[审计与勘误](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/compatibility/official271-map-erratum/)保留旧件与新件。

本轮附加 41 个不可变证据包、835 个包内文件条目、20,036,992 B；109 个包内 Git tree 已重算。数据按原始 blob 引用挂入，纳秒大整数和原始 SDK 字节没有经过普通 JSON 重序列化。分析缓存丢失后，通过既有 operation id 恢复原 payload，没有重新提交业务作业；新根验证 helpers 明确采用新身份。未恢复的临时 RPC 错误元数据及旧根侧 25/6 纯组件原 exec 文件没有冒称为已找回。[完整包索引](../../qa/evidence/20261104/r12-normal-observer-current-clients-postcold-source-r1/packet-tree-index.public.json)列出每个路径与对象身份。

## 以下为 2026-11-04T22:21:01Z 及更早的冻结记录

下面保留旧检查点正文；其中“当前”“尚未”等词以各自原时间为准，不覆盖上述新状态。

## 当前检查点：Pocket→空 Mac 恢复 98/98；当前 Mac 清点完成有界观察，完整替代仍未获资格

更新于 2026-11-04T22:21:01Z。**正常默认构建的三机方向回归已真实完成：Pocket4 节点 3 为密文来源，空 Mac 节点 1 实际成为 leader，原 98 项全部通过。恢复解封 9,452.187 ms，保持原 15 秒请求限额。全量替代 OpenBao 2.7.1 的资格仍为 false。** 已通过的范围不能替代恢复后冷启动、实际快照 CLI、逐台服务切流及全部客户端与备份迁移。

本次运行仍绑定产品 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` / tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`。诊断代码后续提交 `3cb873919170cc77101b27f6a3ab9e98f41f8d93` 尚未通过新构建与运行资格；主 PR 保持 `6d3040a2dbd06661a67f5c62df259ff446eb8515`。未初始化或切换生产服务，未删除旧服务、二进制、凭证或恢复资产。

| 必须完成的门槛 | 本次新增证据 | 剩余缺口 |
|---|---|---|
| 正式 KV2 迁移和恢复 | 既有 X230 31/31、三机 34 MiB 历史与三份导出继续有效；本次跨 Pocket→Mac 恢复 338 个实际引用密文叶，35,742,393 B，逐叶 SHA/大小匹配 | 当前生产数据与备份迁移；恢复成功后、历史尚存时的全节点冷启动 |
| 三机 HA | 原 98 个唯一检查全部通过；真实断主、自然选主、ReadIndex、多数派拒绝、原冷启与指定恢复方向均有原件 | 恢复后的另一次冷启、其余未覆盖故障和完整运行资格 |
| AuthBus 无 J3160 | 既有 Pocket 当前消费者闭环继续有效；Mac 当前五 agent、配置/凭证哈希、7 条服务查询完成有界观察 | Mac 五 agent 实际 SDK/native、launchd 生命周期、完整回滚；ROG/X230 当前客户端与恢复路径 |
| 逐台切换 | 当前 Mac 输入和实际服务状态有只读证据；测试源码已明确隔离、原顺序、local/raw/effective 回滚要求 | 每台真实凭证读写、重启、回滚及正式流量切换；生产保管与解封安排 |
| 旧版清理 | 失败、未知结果和历史恢复材料全部保留 | 所有客户端及备份完成迁移、当前恢复可用后才能删除旧版 |

### Pocket3→空 Mac1：实际恢复与清理均已核验

实际 job `1a1a88ffe46-fc05-2f1b`、fixture `ec3bcae2abef07e7f6828be221adcdb4` 权威终态 succeeded/exit 0，输出完整持久。六件核心原件和 106 件操作意图/响应 metadata 已逐件核验完整字节、SHA-256、Git blob 和目录 Merkle；原 98 个名称唯一、集合精确相同且全部通过。53 对记录均有响应，未知结果与重试均为零；其中一次原预算 12 秒、52 次原预算 15 秒，全部在界内。该 53 是记录的操作边界数量，不能当作包括所有被动查询在内的 HTTP 总次数。[原始摘要](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/ha/direction-r3-live-core/summary.json) · [完整操作原件清单](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/ha/direction-r3-raw-boundaries/manifest.public.json) · [独立终态审核](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/root-review/r10_direction98_r3_live_root_terminal_review.json)

新增加的只读角色准备总预算 60 秒，实际 7.521225980948657 秒。先停 ROG 后，Mac/Pocket 的真实多数派推进：ROG 停机 committed 为 term2/node2/index61，Mac 停机 committed 为 term3/node1/index62，同时观察到 Mac applied62。停机读取验证持有 FD、逐层目录名、文件身份和完整日志；它不读取应用 state machine，也不以日志观察代替 ReadIndex 权限。后续真实选举仍单独检查，未强制选主。

Mac 恢复前隔离 442 个密文叶，恢复后实际引用的 338 个叶共 35,742,393 B，逐叶 SHA/大小一致；104 个未引用隔离叶未被误算为缺失。19 个保留历史版本和 34 MiB 大载荷通过核验；其他节点解封及三机 ReadIndex 通过。六次 Mac 前台会话的本地 SSH 与远程 native 子进程均已回收且组内为空，保留原 5 秒停止边界；最终三台自有 server 全停、隧道子进程为零，二十项旧输入 fence 未变。

**这轮仍不证明“恢复之后再冷启仍能读取恢复历史”。** 原 execute 次序先 full_cold_restart，再 missing_cipher_leader，最后 finish_application 删除测试 metadata。终态目录里的删除已经被确认；直接重启这些旧目录只可能证明删除不复活，不能用于读取已删除历史。新增 B 方案将在全新 fixture 中、恢复成功后且原删除之前加入独立共享期限的三节点冷启，保留原 98 判据和最后删除顺序。B 尚未运行。旧 R2 方向失败 87/98 仍是失败；也不能把本次 98 与既有 128 相加称为独立 226 项。

### 快照 blocker：编译失败已解释，原 503 内因仍未关闭

旧诊断构建 job `1a1a87f578a-fc05-2ee0` 为已知失败，Cargo 在 62.09384498698637 秒以 101 退出，未超原 1,800 秒限额，唯一子进程已回收。44 项与额外 7 项均未开始。完整 384,196 B stdout 的六个原 SDK chunk 已拼回原字节；27,914 B stderr 与 child/core/authority 一致，包含 27 个 E0277 和一个 E0308。[失败构建原件清单](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/snapshot/normal-build-failed-actual/manifest.public.json) · [完整字节重建审核](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/root-review/r11_observer_failed_build_root_raw_reconstruction.json)

原因是新增观察器闭包的错误类型被推断为 str，而原函数及 ? 路径要求 String。后续 `3cb8739` 只增加显式 `Result<Option<NativeV6IngressRead>, String>` 局部类型，一行增加 45 B，其余 3,910 个源码叶不变。此修复只解决编译问题，不解释先前快照准入 503。bf0 的旧 source-stage、失败原件与产品资格缺口均保留。

3cb 的 R2 公共源码准备已有唯一实际 ACK `1a1a8a17dcd-fc05-2f48`；本检查点尚未纳入完整 stage 终态的 root 审核。新 build 未发出：独立源码审查发现保持整字节不变的 c46 runner 仍在第 19/20 行固定 bf0/ac4027，第 155 行会拒绝新 launcher 传入的 3cb/7f4d，早于 output 创建、intent 和 Cargo。下一控制版只改两个身份 literal 并更新固定输入链，保留全部函数、44/7 分母和原预算；旧 R2 根和控制文件不覆盖。[执行器身份阻断](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/root-review/observer-r2-independent-blocker.public.json)

Phase B 方案的两个 binding 文件名已修正为原 guard 要求的 `binding.private.json`，权限仍为 0600。新 binding 只更新四个产品身份 literal；61,210 B 主控制器及其他三个 helper 完全保留。新产物 hash/大小仍为 null、ready=false，尚未执行 transport/prepare/live。此前 B01 仍为 FAIL_UNKNOWN，无有效 archive、无重放；准入发生在 archive writer 之前已获证明，内部失败原因仍未找到。[新绑定方案](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/snapshot/fresh-binding-r2-source/PLAN.public.json)

### 当前 Mac：37 项有结论，系统 crontab 单条仍需补证

实际只读清点 job `1a1a88a785a-fc05-2f00` 使用完整 R2 collector 原件：38 条固定 entry、15 个 pass、7 条查询，耗时 0.12988945899999998 秒，保留原 host 45 秒限额。结果为 16 read_verified、17 metadata_observed、4 个在已验证父目录下的 absence、1 个因父路径 `/etc` 为 symlink 而阻断。权威 exit 1 被完整保留；没有未知结果、重试或超时。八个自有查询/最终 ps 进程全部回收，FD、输出流已关闭。46,277 B stdout 已由三个原 SDK 页逐字拼回。[原始清点](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/inventory/mac-r2-readonly-actual/actual-stdout.public.json) · [root 终态审核](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/root-review/r10_current_inventory_mac_r2_readonly_root_terminal_review.json)

五个当前 agent 为 main、trnm、hepta-ui、hepta、hepta-backend。配置先前 SHA 匹配；所有已配置 prior SHA 的固定输入均匹配。六缓存中的四项存在，两项已在稳定父目录下证实不存在。主 agent DB 存在，WAL/SHM 不存在；后续捕获不能通过打开生产 SQLite 自动创建缺失 SHM。生产 gateway 与四个 relay 当前在运行；公开 argv 仅保留 argv[0]，其余参数只公开数量/hash，实际 wrapper 依赖尚未全解析。T5 UUID 为 FB804D1B-24CB-4D6E-AEA7-A9E180807758；三个备份根只做 metadata 观察，不代表当前备份内容和恢复已验证。

补证 job `1a1a8a36747-fc05-2f52` 仅进行了五次显式 metadata 观察和一次 readlink，0.00010899999999999799 秒完成，FD 已关闭。原九字段 identity 精确匹配，实际 `/etc` 文本目标为 `private/etc`。这只得到词法候选 `/private/etc`；没有打开该 target 或 crontab，没有声明 crontab 不存在，也没有重跑之前 37 条和 7 条查询。[别名观察原件](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/inventory/mac-etc-alias-actual/stdout.public.json)

Mac 五 agent 的第一版实现仍是未完成源码：guarded capture、外层服务管理器和完整 driver 尚未闭合，未运行实际消费者或 launchd。独立审查还发现逆操作中一次 SDK/raw/cache 写入之后若出现错误，现逻辑可能错误公开 outcomeUnknown=false；需要 attempted/completed 两标记使不完整逆操作保守记为未知，原一次 marker 和禁止重试仍保留。原稿与负面审查均保存，不能以这份源码声称 Mac 闭环已通过。[五 agent 源码计划](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/mac/five-agent-increment1-source/README.md) · [回滚分类缺陷](../../qa/evidence/20261104/r11-observer-build-current-client-preflight-r1/root-review/mac-five-agent-increment1-peer-blocker.public.json)

### 完整替代资格与后续顺序

既有 X230 正式 KV2 31/31、OpenBao 2.7.1 两侧各 69/69 的有限 13 模块对照、三机 128/128 与 Pocket 当前 AuthBus 结果继续保留。历史 59-surface ledger 的目标实际是 OpenBao 2.6.2，不能充当完整 2.7.1 分母；完整身份认证、引擎、管理 API、外部 provider、运维生命周期和故障面仍需逐项闭合。CI run41907498576 的 merge/head 两条 job 在 22:12:27 UTC 仍处于完整 locked Rust workspace 测试，前九步成功、未观察到失败；未取消、重跑或移动主 PR。

继续顺序是修正新诊断执行器并完成真实正常构建 44+7，定位并修复快照 503 后验证 CLI 迁移/恢复；补齐恢复后的三节点冷启；完成 Mac 五 agent 与 ROG/X230 当前依赖、实际服务重启/回滚以及当前加密备份恢复；再按逐台资格推进流量切换。所有客户端和备份路径确认迁移之前，旧 OpenBao、旧 HeptaBao 和恢复资产仍保留。

本检查点追加 29 个原始包、404 个原文件，共 5,471,833 B；所有原始文件保留完整 bytes 和 unsafe integer token，派生审核独立命名。先前索引 73 个顶层字段除 as_of_utc 外不改，旧失败和未知结论不覆盖。

---

## 先前检查点原文（各段时间边界保留）

## 当前检查点：Pocket 实际首轮完成；快照准入 503 已定位阶段，完整替代尚未获资格

更新于 2026-11-04T21:12:15Z。**Pocket R10 已完成实际产物传输、准备、18/18 预检和 66/66 主检查，两次当前消费者运行与两次回滚全部通过。三机 HA 128/128、X230 正式 KV2 31/31 和 OpenBao 2.7.1 两侧各 69/69 对照结果继续有效。全量替代资格仍为 false；逐台真实服务切流、全部客户端和备份迁移、旧版删除尚未完成。**

当前实际运行结果仍绑定 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`，正常默认 features。新增请求准入观察器独立发布在 `bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24`，已实际格式检查通过，尚未构建或运行产品。原 PR CI 仍绑定 `6d3040a2dbd06661a67f5c62df259ff446eb8515`，两条资格 job 正在完整 Rust workspace 测试阶段，已完成的前九步均成功。

| 用户要求的门槛 | 已有完整原始证据 | 仍须完成 |
|---|---|---|
| KV2 正式迁移、恢复 | X230 31/31；三机正式 KV2 额外 30 项；三份各 19 历史版本的导出见证完全一致；34 MiB 导入保留原五秒预算 | 全部实际生产数据、当前备份及客户端覆盖 |
| HA | 真实三机 128/128，SIGKILL、自然选主、ReadIndex、多数派丢失拒绝读写、冷启、ROG→空 Mac 密文恢复 | 请求的 Pocket→空 Mac 方向仍为 87/98；新自然选主准备与恢复后重启回归 |
| AuthBus 无 J3160 | Pocket 当前 native 0.144.3 消费者实际 AppRole/TLS/KV/Policy/续期/撤销，两轮 managed1/2 写入、SDK/raw-row/cache 回滚、SIGKILL 和冷启均通过 | 当前全部账号、实际安装 coordinator 入口与真实服务管理器；Mac、ROG 逐台闭环 |
| 逐台切换 | 可信凭证输入固定、旧输入与原账号顺序保护、一次回滚和退出证据 | 每台真实服务的凭证读写、重启、回滚和正式流量切换；生产密钥保管与解封安排 |
| 旧版清理 | 九份历史备份回执及完整原始读取链已核验 | 以当前客户端与恢复路径的实际迁移结果决定清理；本轮无服务、二进制或恢复资产删除 |

### Pocket 的实际通过范围

独立隔离的 Pocket job `1a1a85b63d4-fc05-2e6e` 完成，所有自有 server、Node、native 子进程均退出，未知结果和重试均为零。四个不同阶段记录为：

| 阶段 | 通过检查记录 | 唯一公开标签 | 完整路径源码校验 |
|---|---:|---:|---:|
| initial | 128 | 112 | 60 |
| cold-new-process | 128 | 112 | 60 |
| initial.rollback | 95 | 77 | 60 |
| cold-new-process.rollback | 95 | 77 | 60 |

公开标签使用 basename，因此不同源码文件可能同名。独立回读已将每轮 60 项对应到 51 个准备阶段完整路径、8 个安装插件副本与 1 个自有配置；四阶段的源路径排序与原始检查序列完全一致。回滚中同名 SDK 标签表示同一 agent 回滚前后分别取样。**这些数目是原始通过记录，不能改写为相同数量的独立用例。** 原始 14 文件全部不变，标签说明为追加的两文件。

实际进行了四次 native factory 创建和八次本地 RPC，十八个消费者 TLS 响应和二十四个外层已知 HTTP 结果。Policy 的未授权拒绝、token renew、revoke 和撤销后拒绝都有实际结果。保留 Pocket local5/native4、主 agent 与 tg agent 的原始身份、顺序和缓存；不声明最新 active managed generation、全部凭证修复、provider 可用性、真实服务管理器或生产切流。本轮未调用 J3160、provider、模型、refresh 或 quota。

### HA 方向失败的数字证据与下一轮边界

方向 R2 的九十份操作 metadata 原件与四十五个已知 HTTP 结果已全部回读。87/98 的原始失败不变：目标要求 Mac1，但实际选出 ROG2，故在目标解封前停止。停机后的有界只读观察器在 Mac 和 ROG 均完整结束，authority exit 0、日志完整持久，未运行产品请求、子进程或文件写入。

两台终态都是 committed vote `term2/node2`，committed 与 last LogId 均为 `term2/node2/index61`，保留 62 个连续 entry。Mac 122 个 journal event，ROG 123 个；CRC、当前 epoch 与完整 EOF 均通过。结果支持“Mac 在旧 fixture 终态没有更鲜日志、ROG 具有可恢复的 committed self-vote”的解释，不能证明历史启动唯一因果，也不提供 state-machine applied 或 ReadIndex 权限证明。

R4 最终对持有的 raft/log 目录 FD、根路径及相对文件名做了校验，但未将两个后代目录名重新绑定到父 FD；未观察到 rename。此范围限制与原始结果一同保留。新 fixture 的 reader 将补上逐层 named 绑定。下一轮只准备一次自然选主流程：先停 ROG2，让 Mac1/Pocket3 的真实多数派推进并观察实际 committed/applied 前沿，再验证停机日志的新鲜度。原来的 98 项、HTTP 15 秒、准入 8 秒及 controller 2400 秒边界保持；尚未执行新一轮。

### 快照 CLI：准入阶段已证明，内部失败原因仍未解决

旧 B01 只有一次实际 CLI save，退出码 2，没有 archive，状态仍为 FAIL_UNKNOWN，未重放。原始日志的安全投影与七份确切源码表明：该 503 从 `begin_native_snapshot_before → begin_request_before` 返回 Complete，archive export 和最终 archive writer 尚未进入。缺少内部阶段信息，因此不能将问题归因于序列化、传输 flag 或某一个 guard。

独立观察器提交只修改一个 runtime 文件中的 fresh-ingress read 函数，为原有步骤记录静态阶段、静态错误码和原始错误摘要，原业务调用、参数、ReadIndex、repair、拒绝、`?` 顺序与 deadline 保持。3911 个 source leaf 中另外 3910 个逐件不变，实际 rustfmt 1.98.0 退出 0，61578 字节格式输出与源文件一致。下一步仍须新的完整 checkout、正常构建、原 44 项和额外七项既有负向测试，再运行全新 Phase B fixture。公开 port map 的 string-key 修复仅在源码准备中，保留原 whole-equality 校验和历史失败。

### 九份备份回执属于一条历史恢复链

X230 的九个确切 public 文件、九份 file_info 和十三个固定版本读取回包已经独立重建字节流，全部 EOF、SHA256 与版本一致。它们证明 **2026-11-02 capture、2026-11-03 offhost transport/restore** 的一条链：23 个恢复文件、7 个非空数据库、6 个精确 auth store、5 个声明不存在的数据库族、1260 个明文 chunk。原始完整恢复 controller 为 289.174 秒，保留原 300 秒预算。

capture 的 host 标签为 `main`、UID 1000、Linux `/home/qian-qi` 路径；这些标签不证明当前 Mac 或当前 ROG 的物理归属。原策略下 security-state coherence qualified=true 与 raw/security metadata cohort stable=false 同时保留；不声明跨 agent 事务快照、当前凭证有效、当前 SDK 恢复或全量当前清单。本轮只读公开回执，未读取密钥、密文或 SQLite，也没有新恢复。九个注册/hold 引用是另一组分母，不能扩张成九份备份 payload 或九个强制恢复门槛。三机有限当前 collector 仍在源码准备。

### 证据与全量资格

本次提交保留 21 个包、307 个原始文件共 2,640,197 字节，逐 blob 字节数、SHA256、Git blob 和所有 packet Merkle 根已核对。原始 JSON 从未经 Number 重序列化，纳秒整数原文保留。主入口：[当前机器可读检查点](../../qa/evidence/20261104/r10-pocket-live-and-native-admission-checkpoint-r1/overview.public.json)、[本次完整清单](../../qa/evidence/20261104/r10-pocket-live-and-native-admission-checkpoint-r1/manifest.public.json)、[Pocket 原始主结果](../../qa/evidence/20261104/r10-pocket-live-and-native-admission-checkpoint-r1/pocket/live-with-labels/core.public.json)、[HA 数字观察结果](../../qa/evidence/20261104/r10-pocket-live-and-native-admission-checkpoint-r1/ha/numeric-r4-actual/assessment.public.json)。

完整替代还受到完整产品表面账本约束：59 个面仍为 2 个 runtime complete、52 个 partial、5 个 tooling，不能用上述专项通过代替 native auth、engine、admin、外部 provider 及全部兼容行为的资格。当前生产 initialization/unseal/load/cutover 均未发生，旧版清理未发生。后续以实际新结果追加证据，保留已有失败与未覆盖项。

---

## 历史检查点原文（截至上一提交 c18898b；上方为当前状态）

# HeptaBao：正常 V6 存储、三机 HA 与完整替代检查点

## 最新检查点：三机 128/128 通过；方向性 98 项未覆盖目标，完整替代仍未获资格

更新于 2026-11-04T20:41:46Z。**R10 三机 HA 的 128/128 已完成独立根审；X230 正式 KV2 31/31 与 OpenBao 2.7.1 两侧 69/69 对照结果继续有效。全量替代资格仍为 false，生产初始化、解封、加载、切流及旧版删除均未发生。** 本轮实际运行产物固定为 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` / tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`，正常默认 features，无 private diagnostic feature。

| 必须攻克的门槛 | 当前可核验进展 | 尚未闭合 |
|---|---|---|
| KV2 正式迁移、恢复 | X230 31/31；三机 HA 额外 30 项官方历史导入、快照、恢复和冷启均通过；3 组各 19 个直接存储见证一致 | 全部生产数据、全部备份路径和持续负载 |
| 三机 HA | Mac、ROG、Pocket4 **128/128**；真实 SIGKILL、选主、ReadIndex、失去多数派拒绝读写、三机冷启和 ROG→空 Mac 密文重建 | Pocket4→空 Mac 的本轮为87/98，实际选出ROG后在目标解封前拒绝；物理断电、磁盘耗尽与长期线性一致性仍未覆盖 |
| AuthBus 无 J3160 | Pocket4 R10 三个绑定源码、七个未改 helper、可信 profile1/2 来源、实际 SSH 路由与传输方案均已审 | 实际 R10 产物传输、prepare/preflight、真实 SDK live、冷启和回滚尚未全部通过 |
| 逐台切换 | 正在按 Mac、ROG、Pocket4、X230 单独整理实际客户端和备份清单，旧路由与 hold 保留 | 每台真实凭证读写、重启、回滚和正式接管；Pocket 不能代替其他机器 |
| 旧版清理 | 未删除旧 OpenBao、历史 HeptaBao 或原始失败证据 | 全部客户端、备份路径、回滚及接管门槛闭合后才可清理 |

### 三机 128 项：实际终态、恢复效果及原预算

job `1a1a81dde69-fc05-2dbc` 的权威终态为 succeeded / exit 0 / output complete / durable。原 98 项 direct LAN 加额外 30 项官方历史检查共 **128/128**；67 次变更都有明确响应，unknown=0、重放=0。根审独立恢复原检查集合，并核对八次 Mac foreground 生命周期、六条直接 mTLS 对等连接、三组原始存储见证和官方变更链。全部自有本地与远端进程已回收，没有保留隧道。[完整 summary](../../qa/evidence/20261104/r10-original128-r2-actual-core/summary.json)；[134 份逐操作原件清单](../../qa/evidence/20261104/r10-original128-r2-actual-operations/manifest.public.json)。

Mac 实际 leader 被 SIGKILL 后成功选出新 leader。单存活节点失去多数派时，读取不返回载荷、写入不返回成功确认；恢复多数派后，被拒绝的写入没有生效。三机全部停机再冷启后，已应用索引均为 59。实际密文恢复方向为 **ROG node2→空 Mac node1**：339 个对象、35,743,073 字节全部重新校验；隔离 443 个对象，其中 104 个为不再引用的对象。这些结果不冒称已证明 Pocket4 node3→Mac node1。

原普通 HTTP15 秒、admission8 秒、内部2400 秒保持不变；outer3000 秒明确为本次新增监督预算。134 份 intent/outcome 的原预算分布为 5秒×1、12秒×1、15秒×65，全部满足原预算。**34MiB 大导入实际 4519.807ms，距原 5000ms 只余 480.193ms；冷启解封为 10261.200ms，在原15秒内。** 导入余量偏小，这次通过不能当作持续负载余裕的证明。

导入后、恢复后、冷启后的三次 HA 原始历史导出各19个版本，body均为35,658,767字节，SHA256 `df3d8087d29f91ce201f9df252bd0dcda2fdccfd0e95537d0ab028f4fcff2086`。native HA 快照53,961,523字节，SHA256 `0203c8f312df97cca937a4c2c6315880a6c6c13d5c533593f2ce6f646362b90f`。持久化效果来自原测试的直接存储、ReadIndex及冷启检查，单凭HTTP已返回不推断 durable commit。

### Pocket4→Mac：原98项与自然选主

R2 prepare完整35,528字节，SHA256 `a583880730e5c3dfa24b8d31c714af44b11434f05bdd660a1f0e434a46c0387c`，已通过根审。10个构建文件、两份Cargo事件、五个QA文件逐对象等于已通过128项的准备原件；原12份比较围栏全部保留，增加实际R2成功的四份，合计16份。原98项集合完整保留。必须由Pocket4 node3提供密文、Mac node1实际自然当选空leader；方向不符时在目标解封前停下，不强制选主。

实际job `1a1a83fdca1-fc05-2e17` 当前为 **FAIL_DIRECTION_UNCOVERED**。唯一key `heptabao-r10-pocket-direct98-live-r2-7a40c9ce-prepared-a5838807`；原2400/15/8秒及新增outer3000秒均已绑定，本次权威终态为exit1 / complete / durable：87项已执行且全通过、11项缺失；实际source3→empty leader2，原守卫在目标解封前拒绝。45次变更都有明确响应、unknown=0；六次Mac foreground双端reaped/group empty、三台最终服务均已停止。原QA末尾应用数据清理及source/binary检查未执行；外层原构建/source/controller/16围栏均保持。原失败现场保留，不称为Pocket4→Mac恢复或性能失败。[准备原件](../../qa/evidence/20261104/r10-pocket-to-mac98-r2-prepare-core/prepared.public.json)；[启动意图和ACK](../../qa/evidence/20261104/r10-pocket-to-mac98-r2-live-dispatch/intent.public.json)。

### 四个CI失败：修正旧夹具，保留安全拒绝

run `41879510413` 的head、merge、aggregate均已失败。head与merge的server lib各为 **3708 passed / 4 failed / 8 ignored**，四条失败完全相同。产品已支持native SSH owner，而旧夹具继续把SSH当作“不支持的owner”，因而获得204/200，违反旧夹具的501/409预期。两份完整失败日志和aggregate日志均保留，失败未被改写。

新commit `6d3040a2dbd06661a67f5c62df259ff446eb8515`、tree `2ec2be733f5499cb632e529159a296f3c6f62cd1` 已经CAS推送到原CI源码分支，sole parent为R10。完整3911个leaf和358个目录Merkle核验确认 **只改四个测试文件，所有产品文件不变**。PKI/Transit foreign-owner夹具改为仍不支持的Kubernetes；正式存储activation和cold restore改为真实本地EC256私有CA加启用ACME的不支持profile。原501/409、完整私有状态、图、源身份、无目标发布及cold-seed GraphRejected断言全部保留，没有将拒绝预期改为成功。

根审和独立审阅均无阻塞。安装的Rust1.98工具链实际执行四次rustfmt，总计0.0724秒、全exit0且child已回收；四份最终源码已全量回读。格式差异仅四个排版hunk（包含可选尾逗号），canonical到最终稿共六个hunk。**格式化和源码复核不代表编译或测试通过，新完整CI `41907498576` 的head和merge已开始且格式检查均通过；workflow trust boundary `41907498806` 为SUCCESS。新完整CI终态仍待确认。** LAN上的R10源码与二进制保持原身份，旧运行证据不会改标成新commit。

### 官方CLI快照503：原失败与观察器问题分别保留

Phase B job `1a1a8177aec-fc05-2da5` 仍为 **FAIL / UNKNOWN**。只执行B01 leader save，CLI exit2、无归档；B02–B05、restore和冷启未执行。只读既有178字节stderr后，核对版本、EOF及SHA256 `bce4e0993df8aa57859efc05b509ad6ea36d8f2d0df9dd23d63ae3640e537df8`，安全投影命中固定产品错误 `native HA committed root is unavailable`。产品将committed-read内层错误映射为503但丢弃具体原因；当前不能断言发生于最初admission或快照最终验证。继续查看原服务器日志，不重放原未知操作。[安全诊断](../../qa/evidence/20261104/phaseb-r3-existing-failure-stderr-diagnostic-r1/original-stderr-safe-diagnosis.public.json)。

另有独立观察器问题：整数map key与JSON字符串key直接比较造成false input-fence alarm；lossless before/after输入已逐项核对相等。该问题不抹去CLI503及未知边界，也未将原失败改成成功。

### HTTP边界、AuthBus与剩余范围

严格HTTP的172份public操作原件已补齐并逐份根审：86个intent/outcome对，85个完整响应、一个明确连接前失败。完整响应包括81个定长、两个合法204无body、两个chunked；11个307均保留单一精确Location。仍有八项与官方状态不同，而且没有有效restore body。根审核验public边界元数据及固定观察器，未获取private原始HTTP报文；68个动态观察检查不是兼容性总分。

Pocket4 R10 AuthBus保留原实际SDK/native0.144.3工厂、main/tg两agent、local5/native4与已冻结核验的profile1/2来源。三源码仅17处绑定变化、七helper逐字不变；原HTTP10/consumer70/rollback35/launcher440秒不变，outer600明确为新增监督预算。真实provider新鲜度不由冻结来源推断。

产物传输仅固定R10 server（109,091,112字节、SHA256 `67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113`）及两份原始构建回执。既有SSH180/receiver180/cleanup10/Git15秒保持，outer360为新值；receiver原alarm在最终receipt发布前结束的限制仍如实保留。QA inert小作业已通过完整根审：11个文件原bytes/owner/mode/identity一致，仅三个Python语法编译，实际传输、prepare/preflight和live须分别凭权威回执闭合；本轮结果不能替代Mac、ROG或X230的客户端验收。

原始JSON、旧失败、未知和不安全范围的纳秒整数token均按原字节保留。远程只读MCP超时单独记载，不据此重启或重放业务。生产保管人、全部客户端及备份迁移、59个surface的完整资格仍未解决。**没有provider请求、J3160请求、生产切换或旧资产删除。**

---

以下为此前检查点原文，状态以各自时间戳为准。

## 当前 R10：X230 31/31 与双侧 69/69 通过；三机 HA 进行中，CLI 快照与 CI 仍阻塞

更新于 2026-11-04T20:01:46Z。**当前仍不具备全量替代 OpenBao 2.7.1 的资格，也未进行生产初始化、解封、加载、切流或旧版删除。** 本轮候选固定为 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`，tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`；使用正常默认功能的 Mac arm64 和 Linux x86_64 构建，前述两端 44/44 结果保持有效。

| 当前实际验证 | 已确认的结果 | 范围与证据 |
|---|---|---|
| X230：34MiB KV2 正式存储 | **31/31**；95 次变更均收到明确响应，零重放；143.885 秒 | 正式 native V6，实际 OpenBao 2.7.1 导出一次、导入一次，冷重启、快照保存/恢复及恢复后冷重启；3 组各 19 个直接存储见证与原始存储精度绑定。[完整原件](../../qa/evidence/20261104/r10-x230-full34-and-comparison69-actual-r1/full34/summary.public.json) |
| X230：OpenBao 2.7.1 对照 | 两侧各 **69/69**；13 个模块；每个规范化结果对象相等 | 67 项为数字 HTTP 状态，PKI 的 2 项是原测试合同的拒绝状态归一化，不能写成 69 个原始状态码全等。原驱动和模块未修改。[完整对照](../../qa/evidence/20261104/r10-x230-full34-and-comparison69-actual-r1/comparison69/summary.public.json) |
| Mac、ROG、Pocket4：本轮 128 项 HA | **R2 仍在运行，未授予终态资格** | job `1a1a81dde69-fc05-2dbc`；原内部 2400 秒、导入 5 秒、普通请求 15 秒、admission 8 秒均保持，外层 3000 秒明确为新控制器预算。Pocket→Mac 98 项尚未在 R10 运行。 |
| 严格 HTTP 观察 | 86 个操作全部有已知结果：85 个完整响应、1 个明确连接前失败；unknown=0 | 单主机三进程，68 个动态观察检查；仍有 **8 项官方状态差异**，未发送有效恢复体。172 份单操作文件补充归档待共享窗口结束。[核心原件](../../qa/evidence/20261104/r10-strictwire-actual-core-r1/result.public.json) |
| 官方 CLI 快照 Phase B | **FAIL / UNKNOWN** | 只执行 B01 leader save；CLI 退出 2，没有归档文件；node1 审计 request61/response62 为 503，但审计不能证明客户端响应帧完整。B02–B05、恢复及冷启未执行；81 个受控进程全部回收。[原始失败](../../qa/evidence/20261104/phaseb-r3-actual-failed-r1/result.public.json) |
| 完整 CI | 合并结果作业 **FAILURE**；head 作业观察时仍运行 | server lib 为 3708 passed / 4 failed / 8 ignored；四条失败需区分旧测试前提和真实安全回归。[完整日志](../../qa/evidence/20261104/r10-lan-x230-phaseb-checkpoint-r1/ci/126748711283-merge.log) |

### KV2 的新证据与限制

本轮 34MiB 指 35,651,584 字节有效载荷和 17 个保留的有效版本。源端 API 对大整数、长小数的舍入也被原样记录；精度验证使用 lossless 原始存储/protobuf 与目标的直接存储见证，不能把舍入后的 API 读回当成原始精度证明。导入后、冷重启后、快照恢复再冷重启后的 3 组见证，除各次发布的 root/generation 外，19 个版本的有效载荷摘要、删除、销毁、时间和版本信息完全相同。

X230 使用独立完整源码副本：3752 个提交、3911 个实际跟踪文件、完整 fsck，无共享对象依赖。传输完成后逐一核对二进制、构建收据、bundle 与来源收据；只读 MCP 观察超时被单独保留，不曾作为业务重放理由。测试保留原 HTTP 15 秒和单次迁移 360 秒预算。外层每个 1800 秒是明确记录的新控制器预算。当前这些结果关闭的是已列明的隔离测试范围，尚不能替代真实生产、全部备份路径或全体 OpenBao API 的验收。

### HA、快照与 CI 的失败保留

HA R1 在 16/128 时失败，尚未启动产品服务、没有变更或未知结果。实际诊断确认 Mac 固定 Python 路径的文件 SHA 与旧预期不同；R2 只改为实际验证的解释器 SHA、全新路径，并增加 R1 原件保护。原故障内部 stderr 未捕获，不能声称已证明解释器为何变化或完整重现了原故障。R1 原始失败和 R2 的完整四段差分都保留，R2 必须以最终 128 项、原时限、断主/选主/ReadIndex/持久化/重启和清理证据判定。

Phase B 原件仍包含 `input_fence_changed_after_run`。根审阅逐项比较完整原始 before/after 输入，保留全部不安全整数词面后其值完全相等；源码显示 fresh Python dict 的整数端口键与 parsed JSON 的字符串键被直接比较。这支持“观察器键类型错误”的源码推断，不能据此指称实际文件漂移，也不能把独立的 CLI unknown 改判成功或已知拒绝。原错误字段未重写，B01 未重试。

新 snapshot relay 文稿仍只是方案。正常 native V6/HA 的负向交付持久记录究竟走哪个真实 typed writer/admission，以及该记录改变共享 root 后怎样保留原授权、原源状态和 deadline 而不重复扣减，仍是两项实施前 OPEN。[完整约束](../../qa/evidence/20261104/r10-native-snapshot-relay-open-r3/OPEN_IMPLEMENTATION_REQUIREMENTS_R3.md)。不能通过放宽 frame、deadline、fsync 或退回 flat State 关闭这些门槛。

### 下一步和生产门槛

1. 收齐本轮三机 128 项的终态与受控进程清理；通过后才绑定实际通过摘要，执行 Pocket→Mac 98 项方向回归。
2. 读取既有失败的精确诊断，修复 CLI 快照阻塞与 CI 四条失败，保留原失败，使用新的明确身份和完整合同验证修复。
3. 将真实 AuthBus 消费者、可信凭证来源、AppRole/TLS/KV/Policy/续期/撤销、冷启动及 CAS 回滚合同绑定至当前 R10，再执行；旧 R8 通过结果保持历史身份。
4. 逐台真实凭证、重启和回滚完成，生产凭证托管与所有客户端/备份路径核实后，才可切流和清理。当前未满足这些条件。

本次新增证据包含 25 个原件包、294 个完整文件、58 个 Git Merkle 目录与 191 个 manifest 成员核对，并另存根审阅、完整 CI 日志和汇总。[本次索引](../../qa/evidence/20261104/r10-lan-x230-phaseb-checkpoint-r1/checkpoint.public.json)；[全文件清单](../../qa/evidence/20261104/r10-lan-x230-phaseb-checkpoint-r1/manifest.public.json)。以下保留此前检查点原文，日期较早的“当前”描述应按历史记录阅读。

---


## 当前 R10：Mac 与 ROG 正常 44 项均通过；Phase B 组件检查通过，实际快照待运行

更新于 2026-11-04 19:04 UTC。当前候选是 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`，tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`。**Mac 与 ROG 都已完成本轮正常默认功能的 44/44 回归，零失败、零忽略；两端各 14 个受控进程组全部回收。** 根审阅逐一核对了每端 20 份原始文件的完整 UTF-8 字节、SHA256、Git blob、固定测试名称、真实 stdout 终态以及运行服务的权威完成记录。每端原有构建、列表和测试时限保持不变。

| 实际运行 | 结果 | 原始结果 SHA256 | 证据 |
|---|---|---|---|
| Mac arm64，job `1a1a7d89fad-fc05-2cb1` | 44/44，0 failed，0 ignored | `28f47931ad644e610d45af00545b343a8d5867546ea8d00a44cae0a3de13c961` | [原件清单](../../qa/evidence/20261104/r10-mac-normal44-terminal-r1/manifest.public.json)、[根审阅](../../qa/evidence/20261104/r10-mac-normal44-terminal-r1/root-review.public.json) |
| ROG Linux，job `1a1a7c83142-fc05-2c88` | 44/44，0 failed，0 ignored | `409b8a02557cc5d2985d15f01ff28ff64a6fb43c4a8b1e0f50f03bb748fcbeee` | [原件清单](../../qa/evidence/20261104/r10-rog-normal44-terminal-r1/manifest.public.json)、[根审阅](../../qa/evidence/20261104/r10-rog-normal44-terminal-r1/root-review.public.json) |

此前 R9 ROG 的两个 native KV2 witness 失败用例在本轮真实运行通过，Mac 的 closed-peer TLS 回归也通过。旧 R9 42/44 失败和旧 R8 Mac 失败记录继续保留，资格仅授予本轮候选。Linux release server 完整哈希仍为 `67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113`，Mac 为 `bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98`；R10 是 test-helper 修正，Linux release 字节与 R9 相同，实际 R10 构建收据与测试身份均单独验证。

官方 OpenBao 2.7.1 CLI 的有效 native archive 验证使用新 **Phase B R3 draft 2** 身份。旧 R2 完整主控字节未恢复，因此没有继承旧 R2 源码或运行资格。新源码及原始参考控制器的完整 22 件材料已归档于 [源码清单](../../qa/evidence/20261104/phaseb-r3-source-draft2/manifest.public.json)。实际离线 job `1a1a7e773c5-fc05-2cdc` 已完成 7 份源码解析与编译、34 项证据组件和 32 项控制器组件检查，0.146 秒退出 0；运行后文件操作、网络调用和子进程均为零。[完整执行证据](../../qa/evidence/20261104/phaseb-r3-offline-actual-r1/manifest.public.json)和[根审阅](../../qa/evidence/20261104/phaseb-r3-offline-actual-r1/root-review.public.json)明确：四个模块的定义及纯内存方法确实被执行；“compiled_not_executed”单行记录只描述此前编译阶段，不表示这些模块从未执行。

这些组件检查没有运行产品、官方 CLI、目标 main、参考帮助方法或 host binding 构造器。有效快照保存、恢复、所有节点精确状态以及冷重启仍待真实 Phase B 运行。控制器保留 15 秒 CLI/HTTP、300 秒动作、原 readiness/election 时限；正常 seed/cold/final 停止采用一次共享 TERM5/KILL5 分配，参考控制器原有超时 SIGKILL/wait5 阶段另行保留，不声称所有停止阶段只共享一次预算。未知业务结果仍禁止新变更与重放。

当前完整 workspace CI head/merge 两项仍在第 10 步实际 workspace 测试，未获得完整 CI PASS。新候选的 X230 34MiB/69 项、真实三机 128/98 项、严格 wire 与官方 native snapshot CLI 均尚无本轮终态资格。后续条目是保留的历史检查点，当前状态以本节及[本轮范围记录](../../qa/evidence/20261104/r10-dual-normal44-phaseb-checkpoint-r1/scope.public.json)为准。59 个完整功能面、真实凭证与逐台回滚、备份迁移仍须继续闭合；**全量替代、生产切换、旧版清理均未获资格或执行。**


## R10 运行进度：ROG 正常构建中，Mac 离线 canonical 恢复完成

更新于 2026-11-04 18:26 UTC。ROG 的 R10 源准备已实际完成：独立干净 clone 为 canonical `49503322c7f446e5eb41e7744f1fdbd7f1192ecc` / tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`，唯一父提交 `1d12abc45a83d4b32e7185d01a876eb93110b1e2`；完整历史 3,752 个提交，strict fsck 通过，42 个受控命令全部回收。唯一已审 test helper 和五份控制输入的完整哈希、原 R9 源树均已复核。实际导出的单提交 Git bundle 为 1,522 字节，SHA256=`543ad493d0b3e224f9620b5418e7eda260a000ccc1d8c3c0153bc49a963dad36`。[完整源准备原件](../../qa/evidence/20261104/r10-rog-source-stage-r1/manifest.public.json)及[根审阅](../../qa/evidence/20261104/r10-rog-source-stage-r1/root-review.public.json)保留原始 JSON 字节。

正常 R10 release + libtest + 原六组 44 项的唯一 ROG 作业为 `1a1a7c83142-fc05-2c88`。根审阅者已独立读取实际 `preflight-admitted` stdout 和 running authority，旧 R8 产物与 R9 失败证据已通过启动检查，原 10,080 秒外层及内层 1,800/3,600/30/600 秒预算不变。**正在运行不代表构建或测试通过；当前没有该作业的终态准入。**

Mac 的 R9 离线恢复已完整通过。固定公共源码 bundle 在已核实的原 SSH 通道传输约 1.123 秒，实收 1,886,365 字节与原 SHA 一致；先核真实 T5 UUID，再 O_EXCL 创建、同 FD 全量回读和文件/目录 fsync；四个本机受控组和远端端点全部结束。随后唯一 resume 作业 `1a1a7c78a32-fc05-2c86` 实际 exit 0，完整持久输出，约 2.555 秒内发布。48 个受控命令全部回收，canonical `1d12` / `e1fa` 的 3,751 个完整提交和 strict fsck 通过；原本地 materialization `f0c6171` 以专用 ref 保留。旧 R8 源树及四份原 fetch 失败文件的字节和 inode 信息前后不变。只执行一次本地 file 协议 import，没有公网 Git 重试或 Mac Cargo。[完整原件](../../qa/evidence/20261104/r9-mac-canonical-resume-r2/manifest.public.json)、[根恢复审阅](../../qa/evidence/20261104/r9-mac-canonical-resume-r2/root-resume-review.public.json)和[根传输审阅](../../qa/evidence/20261104/r9-mac-canonical-resume-r2/root-relay-review.public.json)分别保留传输与 canonical 恢复的范围。

Mac 的 R10 四文件分发脚本已经完整源审，固定真实 T5 UUID 和原 30 秒 guard、原子 create-only、已有文件完全相同才可复用；此时尚未记录 Mac R10 源准备或构建成功。下一步使用 ROG 实际 1,522 字节增量 bundle 准备相同 canonical R10。

全替代仍有明确产品能力缺口：native snapshot standby 的实际 CLI 闭合、正式 native rekey/系统 owner、外部认证/MFA/密码策略、数据库/插件/外部 KMS、完整 namespace/Identity 与全资产迁移。当前正式 SSH owner 和已通过的 KV2 范围不被误列为缺失；旧 r670 失败也不冒充 R10 新失败。[逐项源码入口及限定](../../qa/evidence/20261104/r10-native-scope-gaps-r1/root-source-gaps.public.json)保留 exact R10 绑定。

本次还修复检查点汇总中两个历史纳秒整数被 JavaScript 序列化舍入的问题，恢复 `80bc5a9` 原发布文件的十进制值；独立运行原件一直保留原字节，运行结论没有改变。[精度修复记录](../../qa/evidence/20261104/r10-rog-source-stage-r1/checkpoint-integer-precision-repair.public.json)列出两个字段和原值。后续原件保持原字节，整数比较使用无精度损失的读取方式。

**生产切流、客户端与备份全迁移、旧 OpenBao/旧 HeptaBao 删除仍未执行。** 下列记录保留各自原时间与候选绑定。

## R10 源审归档（18:04）：检查助手修正已发布，实际编译与运行尚未判定

更新于 2026-11-04 18:04 UTC。当前 canonical 候选为 `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`，tree=`1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`，唯一父提交为 R9 `1d12abc45a83d4b32e7185d01a876eb93110b1e2`。本次仅修改一个 `cfg(test)` 状态检查助手：使用已有 checked native graph projection、完整元数据、KV1 root/key 以及 Zeroizing 的原生根编码见证；原有限令牌次数、耐久 generation、StateIdentity、pending delivery、原检查期限均保留。自 `finite_actor` 起的 12,674 字节、全部测试主体和 44 个测试名称没有改变。正式产品源码在 R9→R10 之间未改动。

ROG 的真实 rustfmt stdin 检查完整返回原 16,529 字节，exit 0，无 stderr。新的两机控制包由根审阅者完整校验 19 份 payload 的字节数、SHA256 与 Git blob，并完整审阅 stager/launcher；两份 combined runner 只变更标题、固定 tree、回执 schema 三行。独立 ROG Python AST 作业 `1a1a7b602b4-fc05-2c5c` 实际 exit 0，完整持久化 7,081 字节输出，9 个文件语法通过，32 个原函数的完整源码内容相同；没有执行被解析的脚本，也没有写文件。以上是源代码和控制包检查，**不是 Cargo 编译或 44 项测试通过**。[完整控制包及范围](../../qa/evidence/20261104/r10-normal44-controls-r1/README.md)与[根审阅](../../qa/evidence/20261104/r10-normal44-controls-r1/root-full-source-review.public.json)保留精确绑定。

ROG 的 R9 离线 canonical 导出已实际完成：作业 `1a1a7a5d73d-fc05-2c13` exit 0、输出完整持久化、300 秒原期限内发布；29 个 Git 受控命令均回收无残留。完整历史 3,751 个提交；相对真实 3,735 提交 anchor 的 16 个新增提交产生两个真实 bundle prerequisites。导出文件为 1,886,365 字节，SHA256=`49060b399899b9904aded82973589837062dace090fcb43102fa862a5ff7fb06`。[原导出回执](../../qa/evidence/20261104/r9-offline-canonical-export-r2/result.public.json)和[独立根审阅](../../qa/evidence/20261104/r9-offline-canonical-export-r2/root-whole-export-review.public.json)已保留；Mac 接收和 canonical 导入此时尚无通过结论。Mac 未进行 R9 编译，计划恢复 canonical R9 后直接准备 R10。

新 R10 CI `41879510413` 的 head 与 prospective merge 两项均已进入完整 locked Rust workspace 测试，尚无终态。旧 R9 CI `41869016900` 的两项实际终态为 cancelled，其汇总门禁因 cancelled matrix 失败；不能将该终态写成 Clippy 通过或某项代码断言失败。

后续正常构建保持原 Rust 1.98.0、release profile、默认 native-v6-storage/native-v6-ha、原 Linux/Mac 编译并发和期限、原 6 组 44 项及每组 600 秒上限。ROG 新 clone 必须校验 canonical R10 唯一父提交、完整 3,751→3,752 历史与 strict fsck；Mac 仅允许导入已实测绑定 SHA 的单提交 bundle。旧 R9 42/44 失败和 Mac 原 90 秒 fetch 失败均独立保留。

**当前没有 R10 正常构建、真实三机 LAN、官方 CLI Phase B 或 native snapshot relay 的通过证据。完整 59 面准入、正式生产切流、所有客户端与备份迁移和旧版删除仍开放。** 此段为新的进度记录，下列 R9 与更早证据均保留原候选和原时间范围。

## R9 归档终态：正式构建通过，精确回归 42/44，仍未准入

更新于 2026-11-04 17:32 UTC。当前候选源码为 `1d12abc45a83d4b32e7185d01a876eb93110b1e2`，tree=`e1faeaa3ed49d26fb01a7617a8879cb693a12907`。下文较早的正常三机 128/128、方向 98/98 和 R8 结果继续保留其原候选绑定，不能转记为 R9 通过。

ROG 的正常默认 release 构建成功（647.333 秒），正常 release libtest 构建成功（1,083.029 秒）。原六组 44 个精确测试均实际执行：**42 通过、2 失败、0 忽略**。任务 `1a1a7738839-fc05-2b7f` 的持久终态为 exit 1，未发生 supervisor 超时；14 个受控进程组均已回收且无残留，源树与保留的 server、seed、libtest 字节均未改变。

| 原测试组 | 通过 | 失败 | 忽略 |
|---|---:|---:|---:|
| SSH ownership | 25 | 0 | 0 |
| Native mount refusal | 1 | 0 | 0 |
| Native redirect transport | 5 | 0 | 0 |
| Parallel export actor / original scope | 2 | 0 | 0 |
| Ordinary HTTP framing | 5 | 0 | 0 |
| NoForward 2.7.1 | 4 | 2 | 0 |

两项失败位于新 NoForward normal HA 测试的准备阶段。`finite_actor` 调用 `unchanged(service)`，其中 `serde_json::to_vec(state)` 企图扁平序列化正式 native KV2 owner，被原有保护拒绝：`native KV2 owner requires separate authenticated records`。这两项尚未到达待验证的 NoForward 请求，因此不能把它们计为产品行为通过，也不能把准备失败直接等同于路由产品缺陷。修复方向是使用现有 checked native graph projection、完整状态元数据及真实根见证，保留两节点、有限令牌使用次数、实际 POST、审计和原始期限断言；修复此时尚未执行验证。没有以重跑或放宽预算覆盖本轮失败。

实际 Linux server：109,091,112 字节，SHA256=`67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113`；保留 libtest：188,176,568 字节，SHA256=`9b871dd8d12c063e6ea042d5bb4415d9a042da0e4d18d83fca3e184396879cf4`。[完整原件及范围](../../qa/evidence/20261104/r9-normal44-terminal-r1/README.md)、[独立根审阅](../../qa/evidence/20261104/r9-normal44-terminal-r1/root-review.public.json)和[原终态](../../qa/evidence/20261104/r9-normal44-terminal-r1/rog/result.public.json)保留真实失败与每组 stdout。

Mac R9 源准备的首次 Git 网络 fetch 在原 90 秒期限内失败；原错误和旧源码证据保留。之后的只读诊断确认缺少 canonical commit，对完整历史的离线续接仍在源级审阅，尚未启动 Mac R9 Cargo 构建。R9 的 Mac／ROG／Pocket4 真实 LAN 回归、官方 CLI Phase B 和 native snapshot relay 均没有新通过结论。云执行环境暂不可用，尚未冻结的 relay 草案也不能当作发布源码。

当前候选中，59 个产品面台账仍有 2 项 runtime_complete、52 项 runtime_partial、5 项 tooling_partial，whole_surface_admitted 全为 false；2.7.1 准入台账另有 11 个必需门槛、15 个安全差异与 11 个功能／正确性差异。台账中的历史失败不能替代当前运行结果，局部新通过也不能自动关闭这些完整准入范围。**全量替代、生产切流、所有客户端和备份迁移、旧版删除均仍未获完整证据。**

## 既有检查点与历史合同（保留原候选绑定）

本检查点记录 2026-11-04 已完成且可复核的工作。**正常构建的原始三机 128 项和 Pocket4 → Mac 独立方向 98 项已经通过；完整 OpenBao 2.7.1 替代、生产切流及旧版清理仍未获完整证据。** 下文明确区分已通过的合同、历史失败和仍开放的能力。

已完成以下 KV2／三机 HA 合同的物理候选为 `33cafa4c6e29f0bde1553e041550d21b4c725d9c`，tree=`cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`，GitHub 同 tree 发布 commit=`054d17cd50951efa46d78db3911ad1d277a0c584`。正常 Mac server SHA256=`d8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20`，Linux server=`7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`。两者使用原 release profile、默认 native-v6-storage/native-v6-ha，未启用私有诊断或 fixture 功能。X230 同 Linux 产物的正式 full34 已通过 31/31；原 13 模块官方 2.7.1 对照双方均为 69/69。这些合同不代表全部 OpenBao API。

### 正常三机原始 128 项

全新 r2 在 Mac、ROG、Pocket4 上完成 **128/128**，精确等于原 98 个 direct LAN case 与 30 个 official history case 的并集，没有重名、缺项或额外项充数。67 个变更 intent 均有完整 response，unknown=0，每个请求只派发一次。实际恢复角色为 ROG 节点 2 → 空缺且实际当选的 Mac 节点 1：seq47 冷解封 HTTP200 为 **10,083.937ms**；seq55 官方 34MiB 导入 HTTP204 为 **4,645.568ms**。原 5 秒导入、15 秒普通 HTTP、14 秒服务恢复、8 秒 admission 限制未放宽。

恢复后逐项核对 339 个叶对象，共 35,743,140 字节；443 个原对象隔离，104 个未引用对象继续隔离。原 19 版本状态、34MiB 存活历史、快照下载、快照后写入、恢复后的 publication 推进、各主机 ReadIndex、真实断主与重新选主、旧主冷启动追平和全节点冷启动均通过。控制器与外层观察器均正常退出，所有本轮 owned 服务、mesh 和三台负载观察器停止。

### Pocket4 → Mac 独立方向 98 项

全新方向合同完成 **98/98**，53 intents/53 responses/0 unknown。它在三个原始冷解封均完成后显式选择健康 Pocket4 节点 3 作为密文数据源，再要求空数据 voter 的真实选主结果为 Mac 节点 1；不伪造或强制选主。若实际方向不符，会在目标解封前退出并记为未覆盖。原方法仅有这两个已审阅的控制块变化，其余执行、请求、断言、清理与启动停止实现保持继承身份。

该方向的目标是原 Direct98 序列 **46**，HTTP200 为 **9,362.428ms**。逐项恢复 338 个叶对象、35,742,379 字节，442 个对象隔离，104 个未引用对象保留隔离。叶数与原 128 不同是两个 fixture 的数据集合不同；该方向没有重复 30 项 official history，不能标成另一轮 unchanged canonical128。完整原 98 集合、每条原请求期限（seed mount 12 秒，其余变更 15 秒）、二进制与源码、8 份旧证据围栏、所有 owned 清理均经根审阅独立核对。

### 历史失败保留及当前限制

`33cafa` 正常 r1 的 90/128、seq47 HTTP503 14,099.923ms 保留；`36076` 的 100/128 且 seq55 导入结果未知、后续 90/128，以及私有诊断运行的成功和失败也全部保留。未知变更没有重放。两次新正常通过证明具体新鲜运行满足合同，**不证明已找到此前偶发超时的唯一原因**。三机证明使用真实进程终止、持久化和重启；尚不代表物理断电、磁盘写满或长期线性一致性压力完成。

### AuthBus、服务安装与生产材料

Mac/ROG 原生 SDK 的管理顺序预览证据已发布到 QA commit `682c063994c18e1dafc476f6affa4d25e7ff716f`。采用 `[2,1]` 保留现存各 agent 的实际顺序，保留 `[1,2]` 会改变 ROG zbj 顺序的反例；原扫描失败及非凭证路由别名的逐项归因同时保留。现有真实凭证、原生插件和隔离回滚证明见后文；实际客户端流量仍未切换。

Mac 已在 `/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1` 创建只供后续部署使用的离线材料：精确正常二进制、新 CA 与 Mac TLS 证书、私有复制密钥、配置、未加载的 launchd plist 及绑定 T5 VolumeUUID 的启动检查程序。已核对证书用途、SAN、密钥匹配、权限、配置及 plist。该步骤没有启动服务、调用 API、初始化、创建 AppRole、激活存储、配置 HA 或切换流量。最初在 T5 顶层创建失败的 PermissionError 保留；只读检查确认现有用户拥有的工作目录可写，随后使用其子目录，未修改磁盘根权限。生产解封门槛与密钥托管尚未绑定，不能把测试的单份解封配置直接当生产策略。

X230 的独立系统级新一轮 `live-system-r5` 已通过 **547 项动态检查**。实际两个 root:root 0644 runtime unit 启动普通用户 qian（UID/GID 1000）的服务，五次实际进程核对覆盖 argv/exe/cgroup/PID/starttime、NoNewPrivs 和独立 user namespace；代码及配置在 mountinfo 与 fstatvfs 均只读，唯一 owner 状态可写。两 unit 的删除严格核对最初安装 inode，所有 owned 进程和注册项均已清理。

该轮在服务、源 fixture 生产者静止且两把原锁持有期间，配对捕获全部 9 个 owner 文件与 238,621 字节真实快照。在观察到后续变更后，执行一次真实恢复、SIGKILL/wait、冷解封，并由新安装绑定恢复原 `manifest_dispatched` journal；manifest CAS 没有重放。实际配置漂移导致 exit2，实际 CAS 已成功而本地回包验证失败后保持 unknown 并导致 exit3；两者均观察 6 秒（超过 RestartSec 5 秒）且无自动重启，后者经过明确只读历史对账才撤销和重启服务。使用合成 OAuth 数据，无 provider 调用；此轮没有安装版 SDK，不能代表 ROG manager 或生产切流。此前 user r1/r2/r3 及 system r4 的四次失败和各自清理均完整保留。系统级通过没有把用户级只读隔离失败改成通过，也没有改变全局 AppArmor/sysctl。

ROG 另外完成正常 33 构建的 **真实 SDK／协调器核心 314 项动态检查**，19.109 秒、exit0、owned 进程全部清理。使用当前安装的 OpenClaw SDK 2026.7.1-2 和七文件均未修改的 AuthBus 插件，10 个客户端进程中 8 个成功、2 个预期拒绝，50 个成功 HTTPS 观测均有独立完整 TLS 握手。真实 producer inbox、七字段授权、不可变凭证与 manifest CAS、follower 消费、竞争 CAS、提交后 exit73、冷启动历史恢复不重放、完整 SQLite 回滚、错误 CA 回滚均通过；21 个真实签发 token 撤销后再次冷启动仍拒绝，3 个 SecretID 销毁后原 follower 拒绝登录。续期使用真实 renew-self 且保持原 bearer，但只推进客户端本地 due 时钟，没有声称等待完整租期到期。

上述 314 项 SDK 证明执行的是 direct core API，未执行 installed entry；X230 的系统级证明是另一个 fixture。这两份旧结果仍分别保留，不能拼接成一次安装入口 SDK 执行。对应源、全量报告、失败历史及根复核已提交到 QA `b08cdaf17d6c83991d3ed991a686a0bacb371562`，tree=`77f953d68ced8db7fcd60442f202bd36cf2ddd22`。原 HTTP 10 秒、readiness 12 秒、worker 75 秒不变；SDK 结果显式不授予 OAuth 刷新所有权或 enforced scheduler。三个有限生产文件——OpenClaw 主配置及 native Codex auth/config——前后指纹一致，未泛化为全盘不变。

ROG 现已另有同一 fixture 内的 **installed-entry API／真实 SDK 330 项动态检查通过**，19.257 秒。五份源码精确匹配已审稿；原 installed Binding、GuardedBao、service/operation locks、operator inspect/version/head 与七字段 grant、实际 service_cycle、渲染和错误分类均执行。12 个协调器 action、10 个 SDK client、50 个完整 TLS 正向观测、21 token／3 SecretID 撤销、两次 SIGKILL 冷重启及真实备份／错误绑定回滚均经独立根复核。该轮没有注册或启动服务管理器，不能据此标作 ROG manager 通过；使用合成 OAuth 凭证，provider/J3160 调用为零，OAuth 刷新与 enforced scheduler 仍未授予资格。

这份运行在后续 create-only staging 前已经存在。后续 staging 在 mkdir／启动之前按 `fresh_control_required` 拒绝，旧文件未覆盖。限定窗口内只读对账定位到真实 durable job `1a1a67182ff-fc05-2559`，独立权威状态确认 exit0、output_complete/durable、无 timeout；当前有限 owned 进程集与三个原 PID 均为空。观察到的 durable metadata 不包含 launcher agent 身份，未作归因，未重跑 live。完整结果、确切源码、来源回执、独立复核和后续拒绝一并发布到 QA `15c5827dd7a8cfc06131d4901903ebf7e8090599`，tree=`42949d788d481b47a7cea80b93b36c00e1aec5ac`。

### 完整 CI 与替代能力分母

此前 CI 候选为 `0dc39624d1266a6fca98760757b9482bf6f98a7a`，tree=`959c65d6782b288c41730da869c86007c268547c`，prospective merge=`186570233517b2295de7384ef96a5815ba7db06f`。旧完整 run `41797943393` 在原 90 分钟总上限附近 cancelled，部分测试中原 KV2 挂载用例 FAILED；ROG 用未改原源码独立重现了 204 与旧预期 501 不同。源码证据表明 KV1 已被正式支持，所以修订仅把“应拒绝”的 KV version1 改为确实不支持的 version3，保留该用例全部 ACL/CAS/图不变断言。SSH 仍为独立拒绝项，未借此次修正开启支持。

工作流总 job 包络改为仓库已有完整矩阵采用的 360 分钟，全部 fixture/request 原期限、features、profile、断言及 gate 列表保持不变。完整 run `41814525698` 已在两个分支终态失败：各自的 server libtest 为 3672 passed、1 failed、8 ignored，后续资格门槛均未运行；失败是实际 AEAD 之后原调用者已到期的 403 与旧测试预期 503 不同。trust boundary run `41814525725` 已通过。CodeQL run `41814520252` 是单独扫描，不能代替完整资格。ROG 对修改后用例的独立正常构建已经通过：编译 18 分 49 秒，原精确用例 1/1、0.21 秒，3680 项过滤；source=`45d45a79349d8feaed35cb60335edc76ae81bd29`、tree=`7c66c145435dfa32afafc20dfb9e5c3a5f96cdaf`。它验证这一次挂载 fixture 修正，不能覆盖后续实际出现的另一项 CI 失败。

精确源码审计已发现正式 V6 的完整替代分母大于当前部署五项：某些 auth/engine/provider 的业务代码虽已存在，尚无正式 V6 存储 owner；SSH 挂载就是明确的运行路径拒绝。外部 KMS/plugin/postgres 等受 native profile 限制，未覆盖的根/子命名空间 system 操作亦需分别闭合。发布清单中的 OPEN/null 只是未授予完整资格，不能反过来当作所有功能都未实现，既有 full34/HA 等新证明继续有效。快照尤其要区分已存在的 HTTP frontend Redirect 与 service 内层拒绝直接 standby stream；其真实入口和官方行为正在核实，不能只凭一个内层 503 宣称整个快照路径缺失。

### 官方备用节点的真实 HTTP 基线

官方 OpenBao 2.7.1 独立三进程 loopback TLS fixture 已完成 49 项动态观测，记录 51 intents/51 outcomes：旧解析器报告 48 个 complete HTTP 回包与 3 个明确发生于连接前的 readiness 失败、unknown=0，全部 owned 进程清理。它没有保存原始响应头终止符；这些完成性字段属于原解析器报告，不能额外充当严格 HTTP framing 证明。实际 leader 为节点 1；默认配置 standby 2 在带 root token 的 snapshot GET 返回 200，未带 token／无效 token 返回 307；设置 disable_standby_reads 的 standby 3 均返回 307。leader 的无凭证 snapshot GET 返回 403。无效 snapshot／snapshot-force POST 在 leader 与默认 standby 为 500，在禁用 standby reads 的节点为 307。普通 256KiB KV 写在两 standby 均成功且 leader 精确读回；显式 No-Request-Forwarding 写返回 307，目标未落盘。

这轮两个 follower 仍是 non-voter，不能标作官方三 voter 故障验证；snapshot 只验证 archive shape，没有有效 restore 或内容完整性证明。每个请求仍是原 15 秒，不跟随 redirect。HeptaBao 已有前端 snapshot redirect，并非整条路径缺失；但默认 authorized standby 200 与现有选路是否兼容，需要另行实际 HeptaBao 请求及客户端行为证据。HeptaBao observer 保留原观测顺序，并收紧父 deadline、root 创建所有权、源码前后身份与进程登记／信号清理围栏。下列实际失败仍使 HTTP 对照不通过。

### 正常 33 snapshot observer 的真实失败与完成性更正

在 desktop 的全新 `normal33-standby-oracle-live-r2` 上，正常 33 构建完成 42/43 动态不变量后失败。记录 67 intents/67 outcomes；旧解析器报告 66 complete HTTP、1 个明确连接前失败（seq10）、unknown=0。第 67 个请求是节点 2 的无效 snapshot POST，解析状态 307，但 exact enrolled leader origin+target 谓词失败；只保存了 `Location` header name，未保存原始值或 CRLFCRLF 终止符。四个 owned 服务和 67 个 HTTP 子进程均已停止，原源码、二进制、控制器及五份旧证据均未变。

独立复核确认 Python `http.client` 可以接受头部终止前 EOF。因此原始 `response_complete=true` 与 `http_unknown=0` 字段只能按原解析器语义引用，**不能证明第 67 个响应严格完整，也不能断言是地址拼接错误**。完整旧失败原样保留；后继 observer r5 已在全新 live-r3 上单次执行并明确失败，详情如下。捕获 r4 的 39 项手工 spec 组件通过后，根审阅另发现父进程没有传递 `response_head_file` 的真实接口遗漏；该版本阻断于运行前，后继 r5 已在 desktop 真实父进程到 owned Python 子进程路径完成 61/61 无网络检查，包含 EOF、捕获文件写入失败、连接关闭及回收。未以缩小矩阵、改请求顺序或放宽期限换取通过。

该部分运行已观察到 leader snapshot GET 403/403/200，两个 standby GET 均为 307，leader 无效 snapshot／snapshot-force POST 为 400；与官方默认 standby 的 authorized GET 200、无效 restore 500 存在差别。case 矩阵未完成，roles_after 不存在，不能宣布完整兼容或从旧头部证据唯一归因。

后继严格运行 `normal33-standby-oracle-live-r3` 耗时 88.929 秒，durable job `1a1a68b95a0-fc05-26ba` exit1。59 intents／59 outcomes 中有 56 个完整响应、2 个明确连接前失败和 **1 个严格 unknown**；41 个已执行不变量均通过，失败发生在 HTTP 请求边界，不能把 41/41 标作该矩阵通过。独立复核重建 121 份嵌入公有 JSON 的字节与 SHA，并核对 57 个私有头部文件的 size/hash/0600 单链接身份。56 个完整响应另做体长度复核：54 个单一 Content-Length 与实际字节精确相等，2 个为合法无体的 204。

seq59 的节点 2 无效 snapshot POST 仍是原 22 字节测试输入，调用耗时 439.058ms，没有触及 15 秒期限。客户端只收到 43 字节，SHA256=`784faf9483052fa127c456e1fd7e1296a8ec358523780ac0a124d91d4d6f9aff`，严格等于源码首次固定写出的 `HTTP/1.1 307 Temporary Redirect` 加 `Location:` 起始片段。它没有地址或路径值，也没有结束 CRLF／CRLFCRLF；解析器虽接受 307，严格观察器立即标 unknown 并停止。该运行明确证明此响应被截断；零个旧 write-failure marker 不证明所有 write 成功，也不独证 TCP RST 的唯一因果。未知请求未重放，四个 owned 服务和 59 个请求子进程均已停止，正常 33 source/binary/controller 与七份旧证据围栏前后不变。后续独立修复将审查有界完整响应头组包写出；剩余 case 和 roles_after 尚未观察。

### SSH native owner 的正常构建和失败测试

SSH root owner 独立 r4 的 ROG source=`71e1cfff25a124d77ee1771c840c4c69b58c573e`，Mac source=`498a5c0297d7dee93c510bf12e0493a101ca1145`，GitHub source=`e44dcd87cd9249cf5459ab4d916161971f26222b`，三者 tree 均为 `20a7065b96e16b946c00e09841e0621d813457d6`。正常 release check 与 Linux libtest 构建通过；实际 20 项测试为 **18 通过、2 失败**，原日志和结果保留。一个测试在真实 audit I/O 失败后尚未调用正常 delivery completion 就断言 pending owner 已清除；修复将补实际 completion 调用，保留签名仅一次、无凭证泄露、冷恢复等全部断言。另一个揭示实际 HA forwarding 没有携带 SSH public-key reply 所需的原始 ingress，候选修复仍在审查。

Mac 同 tree 已在原 release/default profile 正常构建成功，耗时 256.753 秒，server SHA256=`b1238d851d507c26c67258e77106987e0c69e0d229893a2d2c814b339786dceb`；此处只证明构建，未证明 Mac SSH 运行。Mac worktree 依赖旧 common Git 目录，清理必须保护该依赖。首次 r2 的 Debug 测试断言编译错误也保留，未给秘密类型添加 Debug。后继修复不得把所有 `*/public_key` 升级为 1MiB 完整回复格式而让原 32MiB 普通 KV 降容；该宽泛方案已否决。所有旧正常 33／CI 0dc 的通过仍只属于各自确切 source/tree/binary。

完整替代、所有客户端及备份迁移、生产切流、旧版清理均仍为 false。后续修改将在独立候选上验证；本页的正常构建通过只属于上列精确 source/tree/binary。

| 最新完整报告 | SHA256 |
| --- | --- |
| 正常 r2 canonical128 summary | `8f7285ffad498ec0b6eeaca48e255790776a15ec62c218e195cf5e7ce0f2e8f1` |
| 正常 r2 canonical128 assessment | `66df7dbd422004f7f4569fb9e44a5835f929a5c7f5d19a08b484cc3ecf0cb318` |
| 正常 r2 canonical128 根复核 | `b3694b4910d6d6f90f5335df87bf130ac80481c7c9c66909939e3f32a9f92e29` |
| Pocket4 → Mac direct98 summary | `b02a111b487e33065117fc88596113c7e8a7695feb283331165381fafd3c167f` |
| Pocket4 → Mac direct98 assessment | `02f40102e2ec81021bc6ee1f51d7d72a14076ec57437e2babc66abb07f44a705` |
| Pocket4 → Mac direct98 根复核 | `9a320e34b8d2f1be660477b288aee3c02dbac1de0d102ad8751ef19a635e2c6d` |
| Mac 离线材料 prepared | `2a2223789632f111a2fa78bccbad5dac392e73f8441b7e95f21da270bddc83ff` |
| X230 用户级 r3 失败 | `e1a70454948703f3947d6431aded6a819a90de8b8938896c144e401df3ba242f` |

以下是带日期的历史检查点，保留当时状态和证据；当前结论以上节为准。

## 2026-11-04 10:10 UTC 增量核验

最新正常候选仍为 `33cafa4c`，正常三机 90/128 的失败没有被覆盖。为定位该失败，单独构建的私有阶段观察源码为 `e17180d81db8b62ce333b58961efb70021e1e259`，tree=`494be8525e801e7fbd72660b2eb36816f720d1df`。首次诊断运行在新端口的 Pocket4 readiness probe 失败，24/128、7 intents/7 responses，未到达冷恢复；其服务实际已输出 listener ready。停止后的有限规则核验发现新端口未在原 UFW 允许范围内，未修改防火墙。原失败、日志和清理回执均保留。

新的 r2 使用原允许的 46230/46231 端口以及全新数据目录，保持原 128 项、5 秒导入、15 秒 HTTP、8 秒 admission 和 14 秒 server 请求期限。它已完成 **128/128**，67 个变更 intent 均有明确 response，unknown=0；原 runner 和附加 collector 均 exit=0，所有 owned 服务、mesh、负载观察器停止。主机仍为 Mac、ROG、Pocket4，实际自然恢复方向为 ROG 节点 2 → 空缺 Mac 主节点 1。该轮未覆盖 Pocket4 节点 3 → Mac 的供给方向，不能授予正常构建资格。

根审阅已逐项核对完整 summary 的 128 个不同 case、全部预算、源码和三机二进制 pins，并独立验证精确冷恢复 scope inventory。唯一目标为 Mac node1 emission377：339 个缺失对象全部接收并 fsync，共 35,743,010 字节，逐项 SHA/大小核对通过；3509 条 trace、完整 BOUND、drop=0。其恢复阶段为 9.599666 秒，seq47 HTTP200 为 10,298.918ms；seq55 官方 34MiB 导入 HTTP204 为 4,587.567ms。观察记录含 200 次真实 ReadIndex、187 个实际持久化批次，1/2/3/4 对象批次数为 73/85/20/9。私有观察有开销，不能用这次较快结果解释此前失败的唯一原因；不同进程 emission 及不同主机的时钟不得直接相减，socket 并发累计值不得当作墙钟耗时。

Mac/ROG 的实际 SDK 顺序预览已完成：Mac 五个 agent 和 ROG 六个 agent 在 managed candidates `[2,1]`、activeProfile=null、非强制顺序下全部保留原 stored/effective 顺序。`[1,2]` 会把 ROG zbj 继承顺序从 `[4,2,1]` 改成 `[4,1,2]`，此反例保留，故正式计划采用 `[2,1]`。这只证明排序与状态保持，不代表执行了生产插件、换凭证或生产重启。两机配置中的旧来源尚未改变；当前 8200/8201 有限监听检查为空，所提生产端口尚未占用或保留。

正式 AuthBus coordinator 入口已准备并完成 45 项原核心合同及 28 项安装入口合同：真实私有文件/fsync/锁，KV 边界仍为合成。安装入口将服务 serve/recover 与显式 operator 初始化/授权/撤销分离，固定配置、代码、服务字节及原锁身份；通过独立 binding-pin.env 消除 unit 与 binding 的循环哈希。对已派发 CAS、不可接受的成功认证回复、完成记录落盘失败和不可读 pending，保留 unknown 及对应恢复要求，不自动重发。X230 的真实 normal V6/TLS、实际 supervisor 与完整 owner+KV 成对恢复仍待执行；这些合同通过不等于已安装生产服务。

Pocket4 两个当前原生消费者场景的 32 文件证据包已完整发布到 QA 分支 commit `c4adf3468c042f673228e3c0297dc592d94304ae`。原 packet SHA=`408ce5dc146d9d7fea257eda21cdd0b4b65055170ac6712b8dd135a9a2bccbe2`，32 个成员及全部条目哈希已独立核对；有限实际 secret literal 扫描为 37 个 distinct literal、0 命中。此发布不改变服务或客户端。

CI run `41797943393` 已终态 cancelled，不能继续写为 pending 或通过。两个 worker 的工作区编译分别成功耗时 66m41s、76m59s，随后执行了部分 Rust 测试，在原 90 分钟 job 上限附近被取消。head 日志已有一个原始 KV2 挂载 ACL/CAS 用例 FAILED；其余 libtest 结束摘要尚未输出，失败断言正在 ROG 用完全相同源码、原断言和 15 秒请求预算单独复现。编译采样最大单进程 RSS 约 12.72 GiB，cgroup counters 不可用，不由此声称 OOM。正在评审把包含编译与全部检查的 workflow 总包络对齐仓库既有 360 分钟完整矩阵；所有运行时请求/fixture 期限、profile、features、断言和 gate 列表均保持原值。该调整尚未发布，失败用例没有豁免。

| 新增精确回执 | SHA256 |
| --- | --- |
| e171 r2 原 128 项完整 summary | `f928c1d74bd1f8b4bad8530b6f2ad9d96ea8ff8020ac5f4384a136c833241d1d` |
| e171 r2 控制器与停止回执 | `a3aa88da3f1e810324bff4c45c6f9fea776e93ca9d38dbc47d5d1fc3c13b637b` |
| e171 r2 冷恢复完整 assessment | `b89064e4cfc256258739ef7f74fe47a67a471d05d8c6348a9231bab80c4d44d6` |
| e171 r2 精确 scope inventory | `b79e2f279828d6512d8685cd9aa5be0e6c60ef116d878b80123261a79b803315` |
| CI 41797943393 终态归纳 | `3ef19682a3a42a858a520b376896e8f63b06c44d7a1b7f4a693cf255e4bcc89f` |
| coordinator 45+28 合同回执 | `be7473e3cd0c4f3f3e3cb14fdcd2b3e6ef86b6da9821d8c06a01ff36a887d06c` |

以下各节保留此前阶段的源码身份、失败和证据范围；上表的新私有通过不会覆盖早期正常失败。生产切流、全部备份迁移和旧版清理仍未执行。

## 既有 36076 源码和二进制身份

| 项目 | 精确身份 |
| --- | --- |
| 物理构建源码 commit | `36076db5f5afe00db75eba9b607dee7802dae554` |
| 物理构建源码 tree | `ae71c4b243afd4099db66e7d9882b3f28c777a95` |
| GitHub 发布 commit | `a5c05856f23c395e590fd4e6eeec02bb669a2aa9` |
| GitHub 发布 tree | `ae71c4b243afd4099db66e7d9882b3f28c777a95` |
| Mac 正常 server SHA256 | `b924baba30b1fdc0e6f7e7f32ee0974fae7990b97544c0fbae877f85b420450d` |
| Linux 正常 server SHA256 | `3d9fdf79e26abf4c33fa57568ae7a4c88c79c5def569d92d571c639b855f3df8` |

源码发布与物理构建使用不同的 commit 祖先链，因此 commit ID 不同；已核对 Git tree 完全一致。Linux 二进制是在 desktop 原生构建，并经过哈希校验后送到 X230 执行验证。它不是在 X230 上重新编译的产物。

正常二进制启用 default、native-v6-ha、native-v6-storage；未启用私有诊断或 fixture feature。测试前后均检查源码和二进制身份。后续带私有诊断 feature 的构建只用于定位，不会替代正常二进制验收。

## 既有 36076 已通过的具体证据

| 主机或范围 | 结果 | 已证明的范围 |
| --- | --- | --- |
| Mac 命名空间退休 HTTP 对照 | 31/31 | 已使用挂载退休后的命名空间删除、重建及相关隔离行为 |
| Mac 正式 KV2 full34 | 31/31 | 17 个存活的 2MiB 版本、19 个历史版本状态、官方迁移、精确数据及存储核对、冷启、快照恢复 |
| Mac signed KV1 / cold / reader floor | 98/98 | 对应签名与恢复边界、真实旧 reader 的升级前正例与升级后拒绝、新 reader 对照 |
| X230 正式 KV2 full34 | 31/31 | 同一正常 Linux 候选的官方迁移、34MiB 历史、冷启及恢复 |
| X230 官方 2.7.1 对照 | 候选 69/69，官方 69/69 | 既定 13 个模块的 68 个声明用例，加 TOTP 挂载结果 |
| X230 真实凭证 AuthBus | 88/88 | 44 个父检查与 44 个实际 Node 子检查；两次服务冷启、真实凭证 KV 回滚、AppRole、TLS、Policy、续期、撤销、未知续期不重放 |
| Mac 实际安装版 AuthBus | 父检查 54/54 | 当前凭证身份、正式存储、实际插件与默认凭证选择器、Policy 拒绝、续期撤销、冷启与回滚 |
| Mac 安装版插件的两个阶段 | 各 51/51 | 初始进程与冷启动新进程 |
| Mac 安装版插件的两次回滚 | 各 40/40 | 使用实际 SDK 严格还原隔离逻辑状态 |
| Mac 两个可信来源的完整导入 | 父检查 45/45；插件各 55/55；回滚各 39/39 | 保留原账户身份、管理顺序和来源额度状态，实际 SDK 默认选择、SIGKILL 冷启、两轮全库 CAS 回滚 |
| Pocket4 实际安装版 AuthBus | 父检查 50/50；插件各 50/50；回滚各 39/39 | 本机插件与 SDK、既有 profile-1 的相同身份来源、TLS/AppRole、续期撤销、冷启及两轮全库 CAS 回滚；未调用 provider |
| ROG SDK 导入与独立原生身份保持 r3 | 父检查 60/60；初始和冷启各 94/94；两次回滚各 64/64 | 实际插件通过正式 V6 导入既有 profile-1；原生 user-scope 第四身份保持，实际 CLI 读取精确只读 auth/config，实际原生 factory initialize，隔离全库 CAS 回滚及进程退出 |

这些计数属于不同合同，不能相加后解释成全部 OpenBao API 通过。69 项对照不覆盖所有错误优先级、所有认证方法或所有 secrets engine。full34、HA、AuthBus 等其他合同分别补充其明确范围。

命名空间修复保留了 mount epochs 的抗复活含义；没有把带挂载墓碑的引擎错误认定为 pristine。它删除的是已退休且无活动资源的精确 namespace incarnation，并保留 incarnation 墓碑。它没有新增任意非空命名空间的级联删除能力。

## 36076 历史 HA 门槛与失败（保留原证据）

本轮是 Mac、ROG、Pocket4 三台真实物理机上的直连局域网 TLS 测试。正常构建、源 tree、三机二进制及运行器保持固定。

已通过的故障阶段包括：

- 核验原主进程身份后 SIGKILL，另一个节点实际选主。
- 新主保留精确历史并接受新写入；旧主冷启动后追平及 ReadIndex。
- 丢失多数派后拒绝写入确认和读取数据；多数恢复后核验拒绝的写入不存在。
- 全部 voter 停止、重新启动和解封，核对持久化 Raft 状态、历史与新写入。
- 两个节点共享密文缺失后的精确闭包恢复与全节点 ReadIndex。

原始合同要求 128 项，本轮通过 100 项。官方 34MiB 历史链的首次导入没有取得确定响应，后续该链的精确历史、再次故障转移、快照下载及恢复等 28 项没有取得完整证据。

seq55 导入的实际 owned caller 耗时为 5,011.837ms。调用器在原有 5 秒期限到达后发送 SIGKILL，并 wait 得到 -9。原超时分支丢弃了 kill 后的 stdout/stderr，因此无法区分没有响应字节、部分响应或完整但晚到的响应。不能从 HTTP 超时推断存储未提交，也不能把旧诊断的服务耗时当作本轮实测。该未知代已保留，未重放。

新一轮诊断保留原来的 5 秒导入、15 秒 HTTP 和 8 秒相关 admission 合同，仅增加耗时与长度/哈希观察。所有真实 fsync、目录屏障、ReadIndex 和原请求权限校验继续保留。

该私有诊断轮次已完成原始 128/128 项，67 个 mutation intents 均有明确 response，unknown=0；原始验收 runner exit=0，全部 owned 服务、mesh 和负载采样器已停止。seq55 在 4,633.859ms 完成，返回完整 HTTP 204，5 秒期限内余量 366.141ms。只有一个原始子进程和一次 communicate，没有 kill 或重试。实际快照下载、快照后写入、快照恢复、publication 前沿推进、三机精确历史、第二次故障切换与全冷重启均在该合同中通过。

外层诊断控制器 exit=1 的原因是附加日志采集器不接受两行合法的 reason_sha="-"，原源码明确用该 sentinel 表示无摘要。停止后的原日志已用精确增补格式的采集器只读补采，三份日志 SHA 与原采集完全一致，rejected=0；原失败记录保留，没有重放服务或变更。这些是诊断构建证据，不能代替正常二进制的最终 128 项验收。

本次诊断的 server request_end 为 4,233.670ms，caller 总时间为 4,633.859ms。嵌套阶段中，typed prepare 为 500.814ms，fsync quorum 为 1,435.937ms，整个 HA publication 为 2,236.382ms，local install 为 770.034ms。准备阶段实际提交 19 批、124 个对象，共 8,967,212 字节；19 批顺序调用合计 285.018ms。并行 frame 统计与外层阶段存在重叠，不能相加当作请求总耗时。全运行主机负载统计也不能在没有跨机时钟对齐的情况下解释此前正常构建超时的原因。

第二次正常运行使用全新 r2 控制、数据和节点目录，未复用旧未知结果或其数据；正式源码、二进制和原始运行器不变。该轮通过 90/128 项，47 个 mutation intents 均有明确响应，unknown=0。唯一健康来源为 Pocket4，两个已清空共享密文的节点选出 Mac 为主；Mac 冷解封在 14,029.604ms 收到完整 HTTP 503，仍在原 HTTP 15 秒期限内。原有服务日志明确记录 committed_changed_root_recover 在服务自己的原始期限到期后拒绝；state、barrier、root、activation 均未进入激活状态，recovery_required=false。它尚未到达官方大包导入，不能与首轮 5 秒超时合并归因。全部 owned 服务、mesh 和负载观察进程已停止，未重放这次解封。

已有三轮记录显示：先前正常首轮与私有诊断均由 ROG 向空缺 Mac 主提供恢复数据，该次解封分别为 HTTP 200 / 14,002.626ms 与 HTTP 200 / 13,534.457ms；本轮 Pocket4 向 Mac 提供恢复时为 HTTP 503 / 14,029.604ms。角色差异和紧余量是已观察事实；不能仅凭这些数值断言网络或主机负载是原因。

对已经停止的私有诊断原日志做只读分析，确认这次成功但较慢的冷恢复缺失 339 个对象、35,743,075 字节，恢复阶段共 12.749653 秒；消费者完成 193 个就绪批次和 206 次真实 ReadIndex。供给节点的 340 个请求分别经过真实 ReadIndex，其累计 17.774257 秒来自并发工作线程，不能当作单次墙钟时间。原请求权限、每批 fsync、持久化收据及并发窗口均未移除。新的窄修复仅针对经过严格 mTLS/ALPN 验证的 HBVP2 Legacy 响应，复用已有有界写入器合并响应头和响应体；目前已完成独立源码审查，组件和正式多机结果另行记录，不能提前判定已关闭 HA 门槛。

新响应修复的正常组件第一次实际执行合计 15 项，13 项通过、2 项失败。新增的三个真实 TLS 响应、原期限和大小限制测试均通过；原有 packed pipeline 正例返回 OutcomeUnknown，原冷恢复 blackhole 正例在原 14 秒预算内未完成。前一个 receiver 的一次实际 storage 为 134.481ms，存在原 100ms handoff 拒绝的可能，但现有日志未独立记录 enter_storage，尚不能唯一归因。后一个测试在真实 442 对象、35ms ReadIndex RPC 延迟下，14,024ms 返回失败，230 个已启动任务全部 join、active_frames=0；未放宽预算或减少对象。

随后同一 staged tree 的独立私有诊断在 setup 的原 15 秒期限已失败，尚未进入 14 秒冷恢复阶段，不能冒充重复的冷恢复证据。该轮完成 55/67 个 packed storage，实际 storage 合计 13.765 秒；主机磁盘有明显等待，但全程负载统计不能直接确定单次失败原因。原日志、artifact 和结果均保留。经审查的受控 fixture 调度将真实 TLS 到达与测试内 durable dispatch 分开，保留原 4 秒 frame deadline、全部实际存储收据和独立 100ms/20ms storage-lane 断言；它不证明生产 slow-fsync 下的吞吐门槛已解决。该阶段未授予正式替代资格。

后续 ROG 的正常组件验证已完成 15/15，source staged tree=ac1d3187f9a7c882b9dc0b709d73ce68ff6f2c94。临时目录明确位于真实 NVMe ext 文件系统，未用 /tmp 内存盘；feature 未启用 private diagnostic。原 cold blackhole 测试整个进程耗时 7.133 秒并通过其 14 秒断言，成功输出被默认 Rust capture 收起，因此没有独立的精确 repair 毫秒数。原 desktop 失败保持失败，不从换主机后的通过推断其唯一根因。

在该组件源码上合入已验证的 14 个 server 文件格式修复后，新的正常候选已冻结为 33cafa4c6e29f0bde1553e041550d21b4c725d9c，tree=cdc2376e7b39c1d8bbbeb10a813d58bfe923f336；GitHub 发布 054d17cd50951efa46d78db3911ad1d277a0c584 的 tree 完全一致。新的 Mac/ROG 正常 server 构建均已成功，分别为 624.072 秒和 476.579 秒，原三机回归终态为 90/128。异步 root-pull 请求仍保持原实现，未将另一项优化混入该冻结候选。

33cafa 原运行的停止日志确认：changed_root_recover 为 13,933,476µs，committed scope 为 13,948,275µs，入口 ReadIndex 为 14,782µs；服务请求总耗时 13,999,921µs 时 original deadline 剩余为零，密文和 barrier 未激活。Mac 在 08:04:37.825–08:04:38.098 UTC 有一次已报告的背景证据落盘：24 文件、353,180 字节、逐文件与目录 fsync。该 273ms 窗口的时间和 manifest 已纳入 assessment；跨主机时钟未校准，不能据时间差排除影响或把它认定为唯一原因。不得称该轮完全没有其他 I/O。新诊断将先在真实 TCP/mTLS 上观察请求端分帧；已核对客户端 TCP_NODELAY=true，因此不能凭两个 write 就声称 Nagle 是根因。

随后实际异步请求观察在真实 TCP/mTLS 上调用原生产方法一次，双方 TCP_NODELAY=true，原 2 秒绝对期限内完整返回；已解密的应用记录长度为 4、479 字节，首段至完整请求相隔 4µs，总 exchange 为 2.789ms。新增的单记录预期断言在完整响应后失败，作为基线保存；它只证明请求多分了一条记录，不能解释三机 14 秒超时。最初测试编译因遗漏 import 失败，也保留为测试前置失败。正在同一 33cafa 基线上准备带有限阶段计时的私有真实冷恢复诊断，请求实际写法、ReadIndex、fsync 和固定并发窗口不变。

## AuthBus 与逐台切换

已发现两个可验证的非 J3160 凭证来源：Mac 当前原生凭证对应既有 profile-2；ROG 上存在与既有 profile-1 相同身份的有效代。凭证有效与模型额度可用分开判断：profile-2 的真实业务响应为 usage_limit_reached；profile-1 捕获的来源状态含 subscription_limit / wham，blockedUntil=1793774885494 在当时尚属未来。后续必须重新执行真实 SDK 的时间相关排序，不能假定该时间仍在未来或强制选择 profile-2。迁移不会清除这些真实限制来制造成功。

profile-3 已进行一次受控原生续期，实际 provider 返回完整 HTTP 401，error.type=invalid_request_error、code=invalid_refresh_token。没有新代、未知结果或重试，原生产 stores 保持不变。Pocket4 与 desktop 找到的是同一已拒绝代，ROG 已确认路径没有目标账户的新代，ai395 的三个标准候选路径不存在。这些精确范围内尚未发现替代来源；需要准备同账户的原生重新登录，不能以其他账户冒充。

补充有限范围归因：Mac 已捕获的实际 main SDK 顺序中，profile-3 是第三个 fallback，配置没有非元数据的明确绑定；未观察生产会话覆盖，不能称其已全局停用。Pocket4 当前两个默认 agent 的真实 SDK/原生选择器均只选择本机凭证 ordinal5。tg 本地 profiles 数量为零，但 auth_profile_store 保有一条原始 primary 行，auth_profile_state 为零行；实际 SDK 继承 main 的全部五身份、order 与 usage。此前“空本地认证表”的文字不准确，完整两表哈希与旧捕获完全相同，原 selector 结论不变。profile-3 在这两个默认消费者中不是候选。其失效恢复应与 Bao 存储正确性分开记录；迁移必须保留原身份、失效代际和恢复材料，也不能把隔离测试排除该条目的顺序外推为生产行为。尚未启动重新登录。

版本锁定的 Codex 0.133.0 官方源码确认 CLI 凭证存储默认是 File，缺省读取其 CODEX_HOME/auth.json；MCP OAuth 的默认 Auto 是另一种存储配置。当前未发现有效配置覆盖证据，因此没有任意探测 Keychain。该结论不声称所有历史系统凭证条目不存在。重新登录准备必须保护当前原生账户，不注销或覆盖现用凭证。

同账户重新登录的 r2 私有入口已完成源码审查和准备验证，尚未启动 OAuth。入口固定实际原生 Codex 0.133.0 二进制和依赖；登录子进程只可写独立 home/tmp，不能读取旧凭证备份，也不能修改意图或尝试账本。两个完全合成的超时/中断进程组均已 SIGKILL、wait 且无遗留成员。新的登录结果必须匹配原 profile-3 账户和 JWT 身份，再独立封存；该准备结果本身不代表第三账户已恢复。

X230 88 项和 Mac 54 项验证使用真实 provider 凭证，但这些本轮核心检查不调用模型服务，也不派发 provider refresh。Mac 的既有一次 provider 读取成功有单独证据，与当前选中凭证做了精确绑定；不能把跨轮证据合并声称本轮新 provider 调用通过。

Mac 实际 gateway 最新检查已完成真实启动、两次冷启、完整隔离状态回滚及回滚后启动。早期轮次曾被隔离环境 DNS 阻断，均未派发 provider POST；修正实际 Undici 入口观察后，r8 向原模型服务派发了唯一一笔请求，取得 TLS 验证通过的完整 HTTP 429，网关也返回 429。原始 dispatcher 和 Response 保持不变，Authorization 与当前原生来源、实际选中凭证完全相同，并核对 JWT 账户身份；没有注入替代 header。请求账本已封存，没有第二次 POST 或未知结果。业务成功检查保持失败，429 的具体服务端原因另行记录。

现用 Mac、ROG、Pocket4 的 AuthBus 配置仍启用旧来源。每台都需要完成自己的实际消费者读写、冷启和回滚，再执行正式切换。当前默认模型路由、旧 relay 内部绑定、环境代理和历史恢复路径正在分别核对，不能用其中一个事实代替整条依赖链的证明。

ROG 的隔离安装版插件能够导入凭证，但原 SDK consumer 在 single_managed_default_candidate 处为 41/42，随后完整 CAS 回滚 39/39；生产服务及凭证未变。精确对照证明该隔离上下文中 codex 无凭证候选，而 openai 能选择同一既有凭证。实际模型同时声明 agentRuntime.id=codex，因此正在追踪生产 registry、runtime 和 native credential 路径，不能先把隔离 SDK 的缺口认定为生产入口缺陷，也不能直接新增无端点约束的全局认证别名。

后续安装注册和实际源码核查已确认：ROG 的原生 Codex 插件确实安装在 managed npm generation 中，`homeScope=user` 使插件跳过 SDK profile 的 `account/login/start` 导入，转而使用原生用户凭证。该原生账户与既有三个 SDK 账户均不同，是需要保留的第四个独立身份；其 access 到期时间尚在未来不等于 provider 可用。AuthBus 的 SDK upsert 明确设置 `syncExternalCli=false`，recycler 仅关闭或重建客户端，不写原生认证文件。不能强制改成 agent scope、增加 provider alias 或替换账户来制造通过。验证正在分别覆盖 HeptaBao 到 SDK 的实际导入，以及并行原生消费者在导入、重启和回滚中的来源保持。

Mac 的生产配置允许 Codex 自动运行时，而 r8 隔离配置只允许内置 openai 与 AuthBus 插件。原 r8 的一次真实 HTTP 429、凭证身份绑定和隔离回滚证据仍然成立，但不证明生产的 Codex 插件已经完成等价验证。新的只读审查通过 22/22 项，实际 managed 原生版本已锁定为 0.144.3，SHA256=718724d7221cf1298071ca92411cb74caa8422809154150cedca7b569a4518e3；它不同于独立登录准备的全局 Codex 0.133.0。当前配置缺省 homeScope=agent，实际 shared-client 构建器从 SDK openai 顺序选择并传递 chatgptAuthTokens。22 项只证明静态源码与配置，尚未查询生产进程 registry 或现有 session 的覆盖策略。

精确官方 0.144.3 源码确认 account/read(refreshToken=false) 使用缓存身份，外部 tokens 写入 Ephemeral 状态；但整个 app-server 启动会产生 models/cloud/plugin 后台网络路径，不能称为纯离线。Mac 正在用实际 installed registry、harness selector 和原生 factory 补充隔离消费验证，原业务 POST 和失败 refresh 未重放。

Mac 原生消费者的三次新隔离尝试均保留失败：r1 的观察器误拒绝 POSIX shell=undefined，尚未 spawn；r2 的嵌套 sandbox_apply 收到 EPERM，尚未原生 RPC；r3 改为经 9/9 无凭证预检查的单层 kernel sandbox，实际 spawn 成功，但 sandbox 内只读 /bin/ps 观察器收到 EPERM。r3 父检查 37/38，实际 RPC 列表为空，Node 超过原 120 秒预算后按原逻辑终止，outcomeUnknown=true 保留；单次全库 CAS 回滚 61/61，owned 进程和 Bao 服务均已退出，生产状态未改。r3 的 81 条已通过子检查不构成整轮通过。此失败促使后续版本由原 Python 父进程在沙箱外只读检查自己 owned 的进程关系；新增权限仅允许向子进程发信号以完成清理，未扩大文件或网络范围。

Mac 后续 r4 已真实完成初始和冷启原生消费，但 QA 中两个循环重用了阶段变量，覆盖初始回滚计划。原回执的 56/56 不构成双阶段回滚通过；r4 保留为不完整，随后对从未尝试的初始回滚只执行了一次严格 CAS 清理，62/62，原回执未改。修复局部变量并增加阶段名称、计划数量、尝试集合和实际四阶段断言后，全新 r5 父检查 60/60、初始及冷启消费各 95/95、两次完整逻辑存储 CAS 回滚各 62/62，四个阶段已独立核对，unknown=0，所有 owned 进程组及服务停止。实际安装的 loader 和默认 selector 选择 Codex 0.144.3；真实 initialize、精确 chatgptAuthTokens 登录和 account/read(false) 响应完整。两阶段均保留源额度状态及控制文件字节，生产五个 stores、native 输入及 relay PID 不变。外网被内核拒绝，后台网络尝试未计数；该证据绑定 `36076`，隔离候选顺序为 1、2，不能外推为生产当前 1、2、3 的完整顺序迁移，也不证明模型可用或生产网关切流。

Pocket4 双 agent 的独立真实 selector 回归为 30/30：实际 installed registry、model runtime、harness auth provider 和默认 native builder 均保留，未注入 profile、store 或顺序覆盖，两个候选都为当前 ordinal5。该 selector 轮次未启动原生 factory。后续 full-current-baseline r1 在运行前因“零 profiles 等于零 raw rows”的错误前提失败，未启动 Bao 或原生进程；该失败保留。修正为精确原始两表形状和哈希后，全新 full-r2 绑定正常 `33cafa`，父检查 49/49，初始和冷启的双 agent 消费各 111/111，两次 SDK-local/effective/raw CAS 回滚各 80/80。四个真实原生 factory 使用本机当前 ordinal5，八个显式 RPC 均收到真实响应，四次 account/login/start 的响应类型为 chatgptAuthTokens；没有强制账户或 store、没有 provider 请求，owned 进程均停止。全量当前状态导入是幂等的，两 agent 的 logicalProfilesChanged 与 rawAuthRowsChanged 均为 false；另一个全新 missing-r2 隔离场景已通过父检查 49/49、两阶段消费各 110/110、两次严格回滚各 80/80：只在 owned 副本中预先移除了当前 ordinal5，真实插件从 HeptaBao 补回相同凭证字节，main 的逻辑与 raw 行均发生实际插入；tg 的有效继承结果改变，原 primary raw 行保持不动。其他四个身份、order 与 usage 均保留。每轮回滚精确恢复各自的起始基线，missing 场景回到其缺失条目的隔离基线，不能描述为生产还原。两 scope 的全部四阶段和源哈希均已独立核对，unknown=0，生产 units、hold markers 和真实输入均未改变；尚不授予生产 gateway 重启或切流资格。

ROG 的 r3 已独立核对完整回执：两个实际 factory 只显式调用 initialize，六次 CLI 状态检查均只读打开精确 auth/config 各一次，其他 auth 文件打开数为零。真实插件初始和冷启动各 94/94，两次严格逻辑回滚各 64/64，父检查 60/60；源 usage 状态、生产 auth/config、PID 与启动身份均未变，全部 owned 进程组已退出。此前 r1 的 WAL 预检查失败、r2 的 syscall 观察器漏记经典 open、原 generic SDK 41/42 失败均保留。r3 没有显式 account/read、account/login/start 或模型请求；原生后台尝试未计数，内核无外网。该结果不授予 provider 可用、生产网关重启或正式切流资格。

ROG 使用的 Codex 0.159.2 已通过精确官方 tag/commit 核对：CLI 默认 File，但有效 managed requirements 可覆盖该值；原生 `account/read(refreshToken=false)` 仍会触发 workspace discovery，初始化也会启动该路径，遇到 401 时可能进入原生恢复流程。因此该 RPC 不能被当作纯离线凭证读取。测试保持内核无外网，原生文件读取使用同版本 `login status` 的实际路径，并明确区分文件可读取、原生进程生命周期和真实业务可用性。

## 清理资格

当前不具备删除旧 OpenBao、旧 HeptaBao 或备份恢复依赖的资格。X230 的一个活动 OpenBao 2.7.1 容器已确认属于旧 oracle 命名、网络隔离、无宿主端口、无挂载卷的资产；这些元数据没有证明容器层没有数据，也没有授予删除资格。

清理需等待所有实际客户端、启动配置和备份恢复路径完成迁移。历史查询目录与日志引用单独分类，避免把文件存在误认作活动消费者；也避免在消费者关系未确认时提前删除。

四机的有限注册清单现已闭合到可规划范围：实际 launchd/systemd/cron 注册、精确客户端配置、已装休眠入口及已知恢复材料。该范围内未发现已确认的 Bao/AuthBus 定时备份或恢复注册；无注册的假想任意手工路径不会自动新增门槛。Pocket4 两个暂停入口的负向 ConditionPathExists、实际 marker、来源摘要和禁止自动解除字段均已读取核对，仍保留。X230 旧 oracle 已通过命令元数据确认显式 server -dev，但未读取其容器数据，也不由此推定可删除。

## 仓库发布与 CI

草稿 PR [#152](https://github.com/TrillionniumFoundation/HeptaBao/pull/152) 的初始 integration head 为 016b9c3f6e79b2b540a32f784b96fd13a9695855，tree=d5dc6167579afe1c6f99dc06d3306a6c0b45e00d。它以 a5c05856 和现有 main 7b4a59bd 为父提交，仅保留 main 有意清空的 README，runtime 文件与冻结 36076 完全一致；不能声称整个 tree 与物理构建相同。

实际 workflow run 41789789589 的 head 与 prospective-merge 两项均在 cargo +1.98.0 fmt --all -- --check 失败。源码身份、merge parents、Python 依赖及精确 Rust toolchain 步骤通过，后续 runtime、workspace 和 provider 测试全部尚未执行。独立 workflow trust-boundary run 41789789604 成功不代表完整资格 CI 通过。已在独立 worktree 仅用 cargo +1.98.0 fmt 修复定位到的 14 个 server 文件，并通过原 fmt --check：Mac commit=731833c9010d020ef22c078b9dd013a362aedfeb、tree=8ad5fbe0d2f10bba0f1224d4a23a923f557a0374。对应 GitHub integration head=924c16afbc0c7ceebc727fcac1bdd7e64e4bec8b、tree=892503fe6c26dd965cb54dfd43816220fdf879d1，仍只额外保留 main 空 README；已更新 PR 触发新一轮 CI，终态尚待核验。冻结源码和旧证据保持原样。

AuthBus 可复核辅助源码先发布 a78bdadc（tree=76ad1d16），再追加范围修正与只读 audit 到 97f67bb5（tree=530cdab18a5caa1d92928ed6f901e9136b939ade）。后者与 Mac 实际提交 ccee5c8d 的 tree 一致，原始 401/429/SDK 失败未改写。发布辅助源码不是生产插件部署或切流。

第二次 CI run 41791159057 的两项矩阵均通过格式检查，但旧 validator 仍要求 main 有意清空的 README 承载工程说明，故在仓库一致性阶段失败。已把同样的 plan、精确包数、全部构建命令、状态格式、兼容语料与执行真实性检查放到既有 docs/CURRENT_DOCUMENTATION.md，并增加缺失命令、错误包数和过期声明的拒绝回归；没有关闭 runtime 检查。最新草稿 head=fdc802e2e933a65f298ff449ce00f1c0a454b682、tree=06852fd0349436edca875920026979d0a17c20bd，其全 Rust 文件与物理 33cafa 候选一致，额外差异限于空主页、文档和相应检查/测试。该新轮 CI 终态仍待核验，前两轮失败保留。

该提交的 run 41792816829 两次 attempt 均通过格式、全部仓库/Python 验证，但两个 worker 都在 Rust 编译阶段收到 shutdown signal，以 143 退出。日志未显示 Rust 编译错误或 Rust 用例开始，具体上游关闭原因尚未证明；两次均保持失败。第二次在同一不可变提交和 workflow 上执行，没有修改断言或预算。

当前 PR head 已追加为 1780833661058efff2e31cd2ce2733d485075ac3，tree=3835532737b5a2369ea46947442b3c03a77d0271，仅变更 CI workflow：Cargo 编译并发固定为 1，编译阶段记录有限内存、磁盘和进程资源计数；采样器在任何 Rust 用例开始前停止并 wait。原完整测试命令、matrix、所有其他步骤、features/profile 和 90 分钟 job 预算保持不变，产品 Rust 文件仍与物理 33cafa 一致。该 run 41797943393 现已终态 cancelled；两项编译成功，部分 Rust 测试已执行，head 有一个 FAILED，详见本文件最新增量。记录资源计数不代表已证明内存或磁盘耗尽。

## 主要回执 SHA256

| 回执 | SHA256 |
| --- | --- |
| Mac namespace 31 | `740a5ecb69440850011e038551daa3f3cd1c03fd00806ad2c9c028936c6b70e1` |
| Mac full34 | `25040e083eb24684e2042fde8f87ae2b76d3310d64c0be47187f01783b487398` |
| Mac signed / cold / floor 98 | `37c0982cb9ce174ba2f9cba41252446b0210c6d8734cc4ceea0494bd9cc0058b` |
| X230 full34 | `cd70e6f486e4d61f99adbc293c3c11b6bc53a9e3b85eca9f38753ab5f3152ac7` |
| X230 69 项对照 | `f68a9f50bb9cc72a39d4adbd903abe5fdad266b62cb9d819dc6596dbfb1f8fdf` |
| X230 AuthBus 88 assessment | `4336a6e7dd4d6e31c83fd6d6cb339e4b9887a048f8345a4e8f9f7d003de0fc5f` |
| Mac AuthBus core 54 | `3ac84a78cb6f6fb145508adbb6918cf7de40478ec92854eeb4427ec5c04242a7` |
| Mac 实际 gateway r8 / HTTP 429 | `f93f529a2e4b30e18e729856d141b8c0ae6d4b29988180c50504bf53f04726de` |
| profile-3 原生单次续期 / HTTP 401 | `3926b7f90c408c6bc0381a2cf98dc906c250cf2d31891a9e69dd4222e1a7d81d` |
| profile-3 401 独立分类 | `4b2f6683d202694efd2f0e0f72f33a7c180ddac4e040c2a002b9b667afe233bf` |
| provider 429 独立分类 | `f8bd706ced854db71e1029bfb0aaa16382eb8aa445c57ed531a4bce170db4323` |
| 三机 normal360 原 128 项 summary | `6c0c51c2e155db952dfb154b5d5418e2a66beb21b3548f63d1b25f4787deab8b` |
| 三机 normal360 r2 / 冷解封失败 summary | `c200f77ee6807772c4e7db38285b4165ef99b393c9083d43e8edb0f007c982c0` |
| 5 秒导入失败边界 | `352d797c58371547ccfd125d4ceed7ca54baf5f756ebf81a2dd81224951e5a90` |
| private360 单次导入 / HTTP 204 边界 | `f2a2a360936a98383343c4b1a2df210a04a3e931462ea4a7f945e27d145ad4f8` |
| private360 原 128 项完整 summary | `43f467004962c5cf7ca0bb8d80d800d5f10cf60d289d5bd06859018d1ea55456` |
| private360 停止日志补采 manifest | `4e3c4dc3f25d7921f88e8905c53cc605aa9799cb437a45e352e8f7f1dc475d76` |
| private360 完整导入阶段分析 | `a954706ffd066c8cff101e5a0ccdfd10e06001de3fc379bdc6edf253b5a607fb` |
| Mac 两个可信来源完整导入 | `7a6ee0da71910aa58a8d95b517b4c2516a6f3fbf3ad4fac4e1fc5b55b07a7fcb` |
| Pocket4 本机实际插件与 SDK assessment | `840efef707e7744ef1f7e294f97b4d3bf900529ae0764130ea63ec8b9a41d185` |
| 四机当前客户端与备份依赖矩阵 | `aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0` |
| 四机有限注册与切换范围 recap | `f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64` |
| profile-3 原生登录 r2 准备 | `1377d995d1feab5d77d5bdcd87c22f8226d009d4ee5c4270eef109c0978eb0f1` |
| profile-3 r2 sandbox / owned group 合成检查 | `c9234e438c52ede6395123d0aa17ecaf77f1e3ecee8dcf4731542ee8318eee91` |
| 正常组件第一组 result | `3bb3d5919df6356b2c7ac36b6fe96043de0966b0ac3ba52b968b29922f353971` |
| 独立两个冷恢复组件 result | `7fab41145b6ac9cab606e845f1c1491dcca1c76a0f9b0ff08d17f8b909de09e7` |
| 既有私有冷恢复阶段分析 r2 | `e870c44631d99e14b60033c93012264d7aec0311effd36b43af271f3c0b9562d` |
| Mac 实际 runtime 静态审查 22 | `37617ffc49187da02e24d0b2a5c9380a1e2fa5430ab01af7a9975b444562e9e8` |
| Mac managed 原生 binary pin | `fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e` |
| Mac managed 官方 0.144.3 源码合同 | `f9de7db17bf33d0195ccad087b333bf8a83957b35417be0ca4712fda33775adc` |
| ROG native-preservation r3 core | `4c905377b40663d972839117579fa3e0a317528ac6e6b9fddfd0765cd18c7472` |
| ROG 正常 HA 组件 15/15 | `a2a84c4869aeb552262fc0d8479d8eeaeb0fdfa2f5a17b78c89a4e2de965f030` |
| 新 33cafa Mac 正常构建 | `b53967aac8d06547473f68f907047fd34a89f4ab6295cb9765b24f2202853f33` |
| 新 33cafa ROG Linux 正常构建 | `7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42` |
| 新 33cafa X230 full34 31/31 | `5864b822e4b48833de5ef05ab8f3e402447122f0fbc74ab4ef76c029bcd6a051` |
| 新 33cafa X230 双方 69/69 | `8b9224e43aad89caa7118c24746a3800d1c1ce932a7786051c62c11a71565a6b` |
| 新 33cafa 原 128 项 prepare-only | `bbc0ea744caed7c19e6099c1ab912351ca600dc771f3d8fe530836c1b7f4b5af` |
| Mac native r3 原始失败与清理 | `0168c4a3a0703f2240145117366a42dbc31f7cd1ecdc5647282c53b369f5b4e6` |
| Mac profile3 有限当前绑定归因 | `6a059b7f4b69b5cb37808b2e447eea6a89dda4a003d2eb5c4816510a0d0aba4e` |
| Pocket4 双 agent 当前原生 selector 30/30 | `79e232c4282796ffb07c174fbc32c5e4a4cb5f87167ec42851fd042cc8a8f3ea` |
| CI 41792816829 attempt 1 关闭边界 | `48e0d207f3a2939994204d1836015818d1f60a525fc641928b8717a94f382ce5` |
| 新 33cafa 三机原 128 项完整 assessment | `30f3f88667cfb876833d4c84347c40ca9c20fc91c08e4f1d812cdf41b11cda4f` |
| 新 33cafa 三机原始失败 summary | `41af5de59863ec2d430674d0b6272b040276d2777dda383a25a2e195cdab9f44` |
| CI 41792816829 attempt 2 关闭边界 | `fc149d259198ed285dbdab51c3fd72848b2be3157f3666535ac4baf439f65770` |

原始失败回执均保留，包括构建环境选择错误、选错旧版 oracle observer、SDK 回滚检查点与持久化状态不一致，以及网关首次业务派发前的隔离环境限制。修复后的通过结果没有覆盖原始失败记录。


| 新增回执 | SHA256 |
| --- | --- |
| Mac native r4 不完整原回执 | `2c79b976d1cb3bdc18735a2e5c6d313515fb9b41be804154bfbbd21df2884086` |
| Mac r4 未尝试初始回滚的独立清理 | `8ebbdc7b15818d2dc4e213eccddf0486b112bb123b5a3c1e080c040e72c10024` |
| Mac native r5 完整四阶段 | `6caa9ebfc2a3bf3ae637676a8055022817ec0efa85b09c6ffc304ac854ca6236` |
| Pocket tg 原始表形状纠正 | `158fb3da106d0b81abb110a002938aa2df86a1a76cc85d927e8dd6306b249adb` |
| Pocket 当前凭证双 agent full-r2 | `9006c6d0eae73de89dd62ed381877c873cabd1fff94f790ded7c3e2e2241c7dd` |
| 实际异步 root-pull 两记录基线 | `b90c9660e69ed85ae84017cc856b94abb0dc648920162dc0a950f41a73be8325` |
| Pocket 缺失当前 ordinal5 的实际恢复 | `133e1060d327bd14cae5b0673d3c5649c92d99c5d306f946114bcd480c691b41` |
| Pocket 双场景独立 assessment | `9f7a9ee41ea0bcfd1246380c438161989163086810ce190a8ce7f1b99461315b` |

### 后续精确修订、共同候选和当前预检（本次更新）

完整 CI 的 AEAD 失败已经按 exact 0dc 与 prospective merge 源码逐字核对。原 root-policy token 的 TTL 为 6 秒，实际 payload AEAD 后暂停为 7 秒，原传输期限为 15 秒。Auth 在 root-policy shortcut 之前检查原 token 的存活；导出失败路径又明确优先保留当前 original-owner 的授权拒绝，因此这一情形的既定响应是 **403 permission denied**。独立的原 2 秒请求 scope／3 秒 AEAD pause 用例继续精确要求 503。没有通过扩大期限、接受多个状态码或修改产品代码解决失败。

一个已经存在的独立 ROG 修订 source=`9c54d92a18ef59022a803cb89566ca8007b8b97c`、tree=`30731312c123edcc2de2ecce02347337ba49d587` 只改变这项测试的预期，并增加 errors 精确内容、无 data/auth/unwrapped/consistency 的断言，保留真实 pause、无文件、pending/binding 清理和 fresh-root 导出。其正常默认配置 build 为 1328.343 秒，两个原精确用例为 10.114 秒、2/2，通过并清理；完整 result/intent/prepare/权威终态及独立源码对比保留。该任务的启动者未由现有证据确定，不归因为本次根代理发起；没有重跑它，也不计入新的 31 项。

PR #152 已有并发提交 `f9139c3b37b6373df3e4b4c61ebdd4f847afac4d`（parent 0dc，tree=`ebd395e4515e903e11db34347bd042c013bc780c`），根复核确认它恰为同一测试修订，未改其它文件。新的完整 run=`41837754898`、prospective merge=`4917ae1dc021b948c92a9e9cc4b2e2af171a713b` 正在运行；head job=`126600985114`、merge job=`126600986208` 仍为 complete locked workspace 步骤，未声称编译或整套门槛已通过。trust-boundary run=`41837754906` 已通过。这一 CI 分支仍对应正常 33 产品代码，不是下述共同 r7 的全量 CI。

共同 r7 同时固定原 SSH root owner、明确的 root-SSH 原始回复转发类型、普通 KV 大 JSON 保持 Q9/S7、挂载拒绝 fixture 和单次完整 HTTP 307 响应头。24 个文件的 SHA/Git blob 与完整树已经核定：ROG source=`dc1c02dbd4803f4301097a8268d121e5d7f27464`，Mac source=`9c08c538a0a9dad6a20f1672c108008592c03aa8`，GitHub commit=`d76783b5fe9eb58f54c18a43075d1f4e374fd3d6`，三者 tree 均为 `97d4e782ffa1f2e5d4e116747c34d8c9fb5390d8`。GitHub 分支为 `codex/heptabao-native-ssh-http-20261104-r7`，没有合并或生产切换。

Mac 正常 server/seed 构建已经 exit0、output complete/durable，304.484 秒，server=`e4d06288fdc516d4b5750cf00883a2de9cef40a2ab1c8c442e0ce555366d9350`（91774416 字节）；原默认 native-v6-storage/native-v6-ha、release 配置、源码身份和 owned-group 清理均通过。ROG 也报告正常构建已完成，随后进入正常 libtest。两机各自的 **25 SSH + 1 挂载 + 5 HTTP = 31 个固定用例仍须取得实际终态**，不得以正常构建或旧 18/20 替代。Mac 的大 stdin 投递超时和后来分块传输、全 SHA 提交、create-only staging 分别保留；控制连接超时不被算成产品运行失败或通过。后续严格 wire fixture 将绑定新二进制另起现场，旧 43 字节截断证据保持原样。

严格 HTTP observer 的后续修订补上 Content-Length 实际字节数核对，以及原 stdlib 读取中的 chunk size、chunk data CRLF 和最终 trailer CRLF 被动观察。固定长度短体和四个实际 stdlib 误接受的分块反例均保留；新的独立 chunk 组件为 20/20，自测为 81/81，未增加网络读取或请求预算。它们证明观察器组件，尚不证明新 r7 产品 wire 已通过。

Pocket 的新首轮方案只管理此前已验证的 1/2 号凭证代际，保留原 5 号默认选择、独立 native 4 号、全部六类缓存原内容/缺失状态、两个排除项及 order/usage。r1 没有启动运行；完整源码审查发现 HTTP 变更异常的 unknown 分类和 Node 非超时异常清理缺口后，r2 用新 QA/准备/运行目录修正，真实短子进程组件 25/25。

**Pocket r2 只读预检失败，未启动 HeptaBao、SDK/native 消费者或生产服务。** 18 个已经执行的检查全部通过，实际失败为 `registry_read_failure_not_known_missing_shm_case`：原 registry read-only 查询返回 SQLITE_CANTOPEN(14)，当前 main 为 111644672 字节且 WAL/SHM 都不存在，不符合先前只准许的“非空 WAL、缺 SHM”分支。原输入规则正确拒绝，既有失败没有重跑。两份 auth 表、配置、六类缓存、native4、原 hold 与两个 inactive/dead/MainPID0 单元前后未变。后续只能对这一实际观察到的主文件形状另写有限且稳定的复制/查询规则；它不能被描述为首轮消费、回滚或生产切换通过。

已开始对固定官方 OpenBao 2.7.1 CLI 的快照跳转行为做精确源码分析，并准备独立双 TLS 端点与后续真实集群矩阵。源码预测仍需真实 CLI 证明；HTTP 200/307 与无效恢复 500/400 的差别继续单列，未用客户端通常会跟随跳转作为兼容性结论。所有恢复观察仅允许固定无效输入，不能重放未知的有效恢复。

本次仍未初始化或加载生产服务，未释放 Pocket holds，未切流，未删除旧服务、二进制、数据库、备份或 common-Git 依赖。`full_openbao_compatibility_qualified=false`，`all_clients_and_backups_migrated=false`。


### R7 两平台正常测试终态、旧检查点耐久化和 Pocket r3 预检（追加）

本节接续 validation `8100e8de50eabe150b3a9b567acfc4f078072449`，保留上节冻结时的 pending 记录和所有原始失败。**共同 R7 仍未通过跨平台门槛：ROG 的 31 项全部通过，Mac 为 29 通过、2 失败。** 两机测试都是同一产品树 `97d4e782ffa1f2e5d4e116747c34d8c9fb5390d8` 的正常默认构建，不能把一台机器的结果填补另一台的失败。

| 平台 | SSH 原 20 + 新 5 | 原挂载精确用例 | HTTP 原 2 + 新 3 | 总终态 |
| --- | --- | --- | --- | --- |
| ROG Linux | 25/25，43.942 秒 | 1/1，0.281 秒 | 5/5，0.129 秒 | 31/31，0 ignored |
| Mac arm64 | 25/25，69.061 秒 | 1/1，1.715 秒 | 3/5，2.112 秒 | 29/31，2 failed，0 ignored |

ROG source=`dc1c02dbd4803f4301097a8268d121e5d7f27464`，正常 server SHA256=`666370dba0a1e2df4cb2b3177f54b1e190bc2a281aa64fd8501c4625f30e74ed`。正常 server/seed 构建 635.706 秒，正常 libtest 构建 1076.908 秒；权威 job `1a1a6baeb4f-fc05-287f` exit0、完整且耐久。所有 8 组本次拥有的 build/list/test 进程已收回，源码、保留的测试二进制和发布产物前后相同。三组 stdout 的逐项名称、计数、0 ignored 与固定 31 项清单一致。完整 result、两份构建回执、三组 stdout/stderr/阶段回执及权威状态均按原字节收入本节证据。

Mac source=`9c08c538a0a9dad6a20f1672c108008592c03aa8`，正常 server SHA256=`e4d06288fdc516d4b5750cf00883a2de9cef40a2ab1c8c442e0ce555366d9350`。权威 job `1a1a6ceb1c0-fc05-28d3` 明确失败，输出完整且耐久；7 组本次拥有的进程均已停止，源码和测试二进制保持冻结。两个失败为 `native_http_redirect_tcp_tls_first_record_is_complete_with_unread_upload` 和 `native_http_redirect_tcp_tls_flush_retains_original_deadline_failure`，原 stderr 均记录 `actual native HTTP header parse`。本节封存其真实失败，不改写旧结果，也不把后继夹具修订或源码审查计为该次通过；后继候选需另有自己的源码身份和运行终态。原 R4 18/20、未知启动归属的 R5 22 项和独立 actor 2 项继续各自保留，不计入这里的 31 项。

上述对照由根独立复核，原 review SHA256=`3c356588189df0f12d042f7b6934c9e6e75008bdf637d71a38df49d85709bd9f`。R7 产品分支仍为 `codex/heptabao-native-ssh-http-20261104-r7`、GitHub commit=`d76783b5fe9eb58f54c18a43075d1f4e374fd3d6`；它与 CI 的正常 33 分支 `f9139c3b37b6373df3e4b4c61ebdd4f847afac4d` 不同。本次没有重新查询或改变 CI 状态，也没有提交产品改动、合并 PR 或替换生产二进制。SSH root owner 的有限测试不能替代 child namespace、全部 provider/API 或既定全量 release 分母。

原 13:00 冻结的 **86 文件检查点已在 Mac T5 成功耐久化**：archive 为 658311 字节、SHA256=`2435c0eca2cba81203e9f1d429542bfb5e518d92170ce89c3eb36cce95da3bc5`，解包总计 2046997 字节。先分块传输至新文件并校验完整 SHA，再以固定 FD/身份/权限检查读取，在新根 create-only 写入、逐文件回读校验和 fsync 全目录。两次分块工具超时按同 upload ID、offset 和相同字节对账，没有重新生成证据包。job `1a1a6e0799a-fc05-2937` 已 exit0、完整耐久；原 receipt SHA256=`891f68c06cae1e8424d64ca4d2064bab015f19b582cd42c224a7c01cc66d00d6`。

这个检查点的内容明确仍是 **validation `605b73dc1d9859703827f9f16ecc37eda67d7875` 与 QA `15c5827dd7a8cfc06131d4901903ebf7e8090599`**，不含本次 R7 两平台终态，不能因保存较晚而扩大其版本范围。新落盘根为 `/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-blocker-closure-r1/root-reviewed-checkpoint-r7`；原包、manifest、传输和权威回执均保留，未加载服务或改生产配置。

Pocket r3 对 r2 真实 `SQLITE_CANTOPEN(14)`／主文件存在且两 sidecar 缺失的形状，仅增加受限读取分支：exact code14、非空且不超过 128 MiB、原 FD 与完整身份/内容哈希贯穿复制和查询、两 sidecar 始终缺失，仍仅查询原精确 13 列和原注册行。原 WAL 分支、内核只读、原 10/70/35/440 秒预算、完整消费者/CAS/凭证及生产 fences 不变。冻结 QA SHA256=`c8a6820b8f8f12a8b4fb4078d4a0833b2fe01c782d4793cbdd487896a0db3790`，基底继续为正常 33，未冒称 R7 产品消费测试。

云端验证的限制与实际主机结果分列：namespace 创建遭 EPERM；权限型 SQLite 组件实际返回 `SQLITE_READONLY_DIRECTORY(1544)` 而非 14，组件原失败保留，没有为此放宽条件。10/10 仅是实际 admission 表达式的 AST 边界检查，不是文件复制 I/O 或消费者资格。r3 的静态 review/准备说明按当时原文保留，之后的 stage、prepare 和以下预检另有独立回执。

**Pocket fresh r3 预检仍为 FAIL。** job `1a1a6e52cb3-fc05-295d` 在 3.138 秒后 exit1、无 timeout、无 unknown；已完成的 18 项检查均通过，原主文件稳定复制后的 exact-row 查询因 `current_registry_schema_changed` 拒绝。完整 core SHA256=`b240a1d7baa19d28cca1111be3c9bbeac3884efa21ecf9c95121b6e40203c98e`，outer/core/intent/权威状态/输出均原样保存。尚未执行任何首周期 phase、HeptaBao 服务、installed SDK/native 消费者或 provider 请求，全部 owned 子进程停止。原两份 auth 表、配置、六类缓存、独立 native4、输入与 held 单元状态保持不变；没有释放 hold、切流或清理旧资产。r2 的 code14 失败与 r3 的 schema 拒绝不是同一次运行，也未被拼成一次通过。

本次新增原件位于 `qa/evidence/20261104/r7-terminal-r1/`。`full_openbao_compatibility_qualified=false`、`combined_r7.runtime_qualified=false`、`pocket_first_cycle_preflight_r3.first_cycle_runtime_qualified=false`；全部客户端/备份迁移、正式生产切换和旧版清理仍未获运行证据。该次 publication 只准备可审阅材料，GitHub commit/ref/PR 更新由根另行执行。


### R8 正常构建、X230 原始回归与实际消费者终态（追加）

本节接续 validation `173603791bf19bb5a7148caf2173ab19b1ac2463`，保留此前所有 pending、失败和 unknown 原件。**R8 仍未获得跨平台或全量替代资格：ROG 为 33/33，Mac 为 32/33；X230 的正式存储原 31 项与两侧原 69 项均通过，Pocket 的 R8 隔离真实消费者也通过，但实际生产切流、网关恢复与旧版清理尚未执行。** 这些结果分别绑定各自版本、机器和运行范围。

#### 同树正常构建的 33 项终态

R8 产品树为 `d5a0f91a4d47f7c8d5f34170ea167d10dc036e04`。ROG physical commit=`384c957612186d64c5a530044af0ae62c568cc3d`，Mac physical commit=`2d9a2efd4cfc3a9ee60a450eee58866828a3f5ad`；二者 tree 相同。原 25 项 SSH、原 1 项 mount、原 5 项 HTTP redirect 与独立 2 项 actor/deadline 共 33 个完整名称不变，正常默认 feature/profile、原各组期限均保留。

| 平台 | SSH 25 | 原 mount 1 | HTTP redirect 5 | actor/deadline 2 | 完整终态 |
| --- | --- | --- | --- | --- | --- |
| ROG Linux | 25/25，43.893 秒 | 1/1，0.280 秒 | 5/5，0.129 秒 | 2/2，10.152 秒 | 33/33，0 ignored |
| Mac arm64 | 25/25，69.129 秒 | 1/1，1.702 秒 | 4/5，2.195 秒 | 2/2，11.055 秒 | 32/33，1 failed，0 ignored |

ROG 正常 server/seed 构建 660.734 秒，server SHA256=`666370dba0a1e2df4cb2b3177f54b1e190bc2a281aa64fd8501c4625f30e74ed`。R7→R8 只改测试，因此该 server 字节与 R7 相同并不异常；源码身份与 R8 测试终态仍独立记录。ROG job `1a1a701ddd9-fc05-29dc` exit0，Mac job `1a1a707739c-fc05-29ef` exit1，输出均完整、耐久、无 timeout；ROG 10 组、Mac 9 组本次拥有的进程均收回，源码与测试二进制前后相同。

Mac 唯一失败为 `native_http_redirect_tcp_tls_first_record_is_complete_with_unread_upload`，原 stderr 为 `Os { code: 22, kind: InvalidInput, message: "Invalid argument" }`。原 R7 的两项 `actual native HTTP header parse` 失败继续保留；不能把后继修订或 R8 的 32 项通过倒填为 R7 通过，也不能把 Linux 33/33 替代 Mac 失败。根独立跨平台审阅为 `ac8a42f62643772ed34a595cb26b5e2d304c7387fcde54023cfee850003be2c8`，两个平台的完整 result、status、四组 stdout/stderr、正常构建回执及固定清单均收入本节原件。

#### X230：同一 R8 正常产物的 full34 与 69 项对照

X230 新根为 `/home/qian/heptabao-blocker-closure-r8-384c9576-20261104-r1`。从已验证的 desktop incoming，经现有严格 SSH 身份/known-hosts 路径 create-only 传送 server、两份原构建回执和两条 source bundle；新独立 checkout 的 HEAD/tree、所有文件完整 SHA、fsync 与前后 source pins 均验证。旧正常 33 根与原证据保持不变。

原 full34 在 142.913 秒完成 **31/31**，真实载荷为 **35,651,584 字节（34 MiB）**。通过内容包括：固定官方 2.7.1 来源与 TLS 身份；保留、软删除和已销毁版本的历史；单次导出/导入；正式 native V6 存储的完整历史与冷重启；真实快照下载、后续修改、单次恢复及恢复后冷启动；undelete 数据精确、destroyed 数据保持不存在；data/metadata CAS 拒绝无副作用和成功计数精确。源与目标各自 owned，原 HTTP 15 秒、迁移 360 秒预算未变，最终所有 owned 服务停止。完整 summary 为 90,877 字节，SHA256=`ee24ee6018562ec938ef5fd4ad7158293bb94ee421916d416c4b92c9587f8b30`。

在 full34 明确终态和清理后，原 69 项对照独立执行一次，38.036 秒完成：**HeptaBao 69/69、OpenBao 2.7.1 69/69，0 failed、0 not_run、差异集合为空**。完整 summary 为 104,035 字节，SHA256=`523d2bb14e287fc83246d7c5b537e1e8639b7a56d0139cd7cd55af41f32df903`。两轮 source/binary 前后均为 clean 384c/d5a0/server666370；两个权威 job 均 exit0、完整且耐久，两份大 summary 以固定文件 version 分块取回后校验完整字节和 SHA，未重新运行测试。

69 项范围仍仅为 approle、core、edge_tls、identity、kv、operations、pki、system、token、totp、transit、userpass、wrapping 这 13 个模块。原 wrapper 明确传入该集合；底层 acceptance CLI 自身的默认 12 模块与之不同，不能混淆。两个结果的完整规范化对象一致，其中 67 项使用数值 HTTP 状态，`pki.lease_expire_lookup` 和 `pki.revoked_lease_absent` 分别使用原定义的 `rejected_after_ttl`、`rejected_400_or_404`（允许 400/404），不能写成 69 个原始数值状态完全相等。原脚本没有 SSH 测试；full34 的唯一 501 出现在 `sys/health` 就绪等待允许的状态集合中，并非旧 SSH mount 拒绝断言。固定官方 executable SHA256=`535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea` 与归档成员一致。这里是 X230 单机 loopback 的 owned 合成资格，不能外推成完整 API、生产消费者或 LAN HA 资格。

#### Pocket：保留原 flags、身份、order 与六类缓存的真实首周期

Pocket R4 原失败仍封存：core 44/45；initial consumer 的 65 项前置检查通过后，原 raw CAS helper 因目录不满足 `/current-native-` 契约而拒绝，尚未进行该 consumer 的数据库写入、SDK 导入或 native RPC。outer 仍明确 `outcomeUnknown=true`，不能因为事后定位到封套路径而改写原结果或声称该次回滚通过。之后 R5 只修正 owned 目录绑定，在新根执行。

R5 绑定正常 33，23.040 秒通过 core **66/66**、initial/cold 各 **128/128**、两次完整回滚各 **95/95**。该结果与后继 R8 分开。R6 用同一受审逻辑、原 10/70/35/440 秒预算和仅 artifact/source 绑定变更，在 R8 上实际执行一次，20.988 秒得到同样的 **66/66、128×2、95×2**。两轮都由真实 installed SDK `2026.7.1-2`、Codex native `0.144.3` 的实际 factory 消费：4 个 native factory、8 个真实 initialize/login RPC，实际 `chatgptAuthTokens` 返回；两 agent 默认选择均保持本机 ordinal5。

共同 manifest 只包含原已管理的同身份 1/2，真实 TLS 读取和凭证代际更新有明确证据；main raw auth 行实际改变，tg 保留原本地 raw 行并通过 SDK 继承 effective store。全部五个身份、原 order/usage、本地 ordinal5 与独立 user-native4 保留。原 `publishNew=true`、两个 agent 的中央 order 排除及 shadow 语义没有被关闭或改写：每周期产生 3 个真实 inbox 事件，原 coordinator core 无 grant 时分别 defer 3/累计6，manifest 不扩散。这里测试的是 exact core API，不冒称 installed coordinator service-manager 已在 Pocket 运行。

实际 SIGKILL、wait、冷启动 sealed→unseal、新消费者读取均通过；每阶段回滚各自只尝试一次，完整 SDK local/effective store、raw 两表行与时间戳、六类缓存的字节/mode/缺失状态全部恢复。多文件回滚不被描述为跨文件原子事务。内核禁止 provider 外网；后台尝试数没有测量，不能说为零。原生产 auth/config/cache/registry/native4、两 held 单元与 hold markers 前后不变，没有解除 hold、启动生产网关或切流。

R6 的 artifact relay 和 18/18 只读 preflight 有各自原回执，仍仅证明对应准备范围。随后真实 live job 为 `1a1a74813e5-fc05-2ad3`，core SHA256=`1f42b95791dba63e1dd6cb12bbd643b8d073403948df72f8fe2f282e75806423`，outer SHA256=`1a5d795252411f0eefdef9b77b517676024958ff755eca5c87086550e483cc60`，明确 exit0/unknown=false、owned 全停。首次控制通道 ACK 超时的 193 字节原件和同一请求/同一 idempotency key 的耐久 ACK 原件都保留；没有以新 key 请求第二次业务运行，也不从 `reused=false` 推断首次内部 dispatch 的归属。

此项只证明冻结的已验证 1/2 代际经 R8 存储驱动 owned Pocket 消费者、重启及回滚。它不证明当前最新 provider 代际、账户额度、所有账户、生产 gateway 重启、offhost 恢复集、正式持久服务或后继 R9。QA 文件中保留的原正常 33 provenance 与实际 runtime result 的 R8 source/artifact 绑定分别保存，实际 R8 资格取后者及其独立审阅。

#### 官方 CLI：十项完整观察揭示实际客户端影响

固定 OpenBao 2.7.1 CLI 的 Phase A 使用 owned synthetic TLS responders，**没有启动 OpenBao 或 HeptaBao 服务，没有任何有效 restore 归档**。早期 run1/run2 均在子进程身份 guard 处明确失败，业务 case 0/10，unknown=false；其失败原件不变。第二轮捕获到真实 `/proc/cmdline` 在进程启动中的短暂空值，后继源 R4 在同一原期限内等待可见后再次执行完整身份验证，未放宽 argv/exe/PGID 判据。

第三次独立运行完成 10 intents/10 outcomes、unknown0、全部 owned 清理；这是 **completed observation，不是 10/10 兼容通过**。固定 CLI 的实际行为包括：直接 200 可保存 171 字节精确合成 archive-shape；307→200 的 save 确有第二请求但 CLI 报 incomplete snapshot；直接 restore 收到 400/500 时 exit2；307→400 的 restore 第二次 upload 为 0 字节且 CLI exit0；禁 redirect 的 restore 对307也 exit0。坏 CA、HTTPS→HTTP downgrade 与第二次 redirect 上限另有完整观察。原始输入均无效，不能因 exit0 宣称成功恢复；171 字节只验证形状控制，不证明合法归档互操作。

这些结果使无条件 standby redirect 对既有 CLI 的影响成为实证，仍需解决默认 standby 行为与有效归档互操作。完整 root review SHA256=`3790cc868b531404374455d1fc03a080c0670746ed554157fe18ed12960c843c`；原两失败、第三次完整 result、source R4 与准备/终态均在本节。

#### R8 strict wire：单物理机三进程，保留 sequence73 unknown

此次 strict wire 在 **1 台物理机、3 个 loopback 节点进程** 上运行，不能称为真实 LAN 三机验证。完整 73 个 intent/outcome 对中，70 个严格完整 HTTP、2 个连接前明确失败、1 个 unknown；53 项已执行动态不变量为真，但这些不是完整矩阵分母。所有 4 个 server 组与 73 个 caller 组均已收回，原8份 fences、源码和产物不变。

四个 standby snapshot POST 已获得严格完整 307 与精确 enrolled Location；两次普通 256KiB standby 写及 leader 精确读也完整。随后 sequence73 `ordinary_write_explicit_no_forward` 在 request 已发送后，response-header 阶段仅获 9 字节，`BadStatusLine`，未形成 `CRLFCRLF`、无 Location；caller 没有 timeout，进程已收回。此请求按 unknown 封存且未重放；没有证据把它称为实际 HTTP501 或 TCP reset。整轮 **FAIL / full_matrix_qualified=false**。完整 257,188 字节 assessment 的 SHA256=`9d0028eef9cf5729accc4b4fb2504c3cb87aef122da616d37ea4dd30c97f5782`，root review 为 `234529df9bfae1e89eca56b68102c5289dfa86ba0bcce9b92cf3307b2103ebb9`。

#### Mac EINVAL 与 CI 后继修订的证据边界

Mac 单一失败的原生 syscall 观察定位到 `setsockopt(SO_RCVTIMEO)`，使用合法约 4.99 秒 timeout 仍返回 EINVAL22。独立无凭证、无 TLS、无产品执行的 kernel micro 在同一连接上实证：连接期间设置 timeout 成功，peer close 后设置接收 timeout 返回22，但 readiness 后直接读仍可完整取得108字节。全部 owned sockets/worker 清理。该诊断支持让测试 client 在原绝对期限内读取已缓冲数据，**不直接证明产品 TLS 正确，也不把原 Mac 32/33 改为通过**。九份原始代码/输出/回执和 root review `0eb22c43eed4413c8a1b396714f44d833927fd60b21c6d499f2cc145d6477d7e` 一并收入。

独立 CI run `41837754898` 的源仍为 `f9139c3b37b6373df3e4b4c61ebdd4f847afac4d`，不是 R8。head 与 merge 的完整 Rust workspace 测试步骤成功，随后 strict Clippy 均失败，后续 release gates 跳过，完整 verdict 失败。三个精确诊断为 parallel KV2 export 8/7 参数，以及 HA KV1 projection、native KV1 sudo 两处可合并条件。后继四文件最小差分已经独立 source review：唯一调用点的冗余 original-deadline callback 移到 callee 内原样 lazy 建立，early/worker/final 实际检查次数与位置、before_delivery/stop 顺序不变；两处 let-chain 保留原短路顺序。没有 lint allow、`-D warnings` 调整、期限或断言变化。

该 Clippy 修订只属 **下一候选的源码准备**，尚未在此 checkpoint 获得新编译或 Clippy PASS。R8 的两个原文件已按精确片段处理，避免用 CI 全文件覆盖 SSH 改动。新增 R9 HTTP/NoForward 和 Mac fixture 修订留待另一个同树正常构建/运行包，不混入本节既有 R8 结果。

本节继续保持 `full_openbao_compatibility_qualified=false`、`combined_r8.runtime_qualified=false`、`production_cutover=false`、`all_clients_and_backups_migrated=false`、`old_assets_deleted=false`。原 86 文件 Mac 检查点仍是先前冻结的 605/15c 范围，未因本次追加自动包含这些新结果。新增原件集中在 `qa/evidence/20261104/r8-terminal-r1/`；本次 preparer 不更新 GitHub ref/PR，也不读写根 continuation state。


## R10 dual normal releases and Mac source admission — 2026-11-04 18:47 UTC

The current source is canonical commit `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, tree `1d4211f91e1b34a2ed087a3bbef2e2884bac88e9`. Mac imported the exact 1,522-byte one-commit bundle into an independent checkout after the separately evidenced R9 history recovery. Its 3,752-commit history, sole parent, strict full fsck, clean tree, T5 volume UUID, and all 42 reaped source commands passed. The prior R9 source and failure receipts remain intact.

| Current R10 gate | Actual observation | Scope |
|---|---|---|
| Mac normal release | Passed in 259.684 seconds; arm64 server 93,038,816 bytes, SHA256 `bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98` | Original normal default features and release profile; no fixture feature |
| ROG normal release | Passed in 651.520 seconds; x86_64 server 109,091,112 bytes, SHA256 `67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113` | Exact current-source build receipts; matching R9 binary bytes do not transfer R9 test outcomes |
| Mac normal44 | Combined job `1a1a7d89fad-fc05-2cb1` running | Source/retained-artifact preflight admitted; original 1800/1800/30/600-second internal limits and two Cargo jobs |
| ROG normal44 | Combined job `1a1a7c83142-fc05-2c88` running | No current 44-test terminal qualification yet |
| Physical Mac/ROG/Pocket4 HA | Four full source candidates reviewed; syntax-only check passed | Original 128 and 98 workflows, actual election, unchanged budgets; actual artifact pins and new runs pending |
| X230 full34 and comparison69 | Exact published R8 wrappers recovered and narrow R10 binding changes reviewed | Original 31 checks, 13 modules and 69 cases per side preserved; source/artifact staging and current runs pending |

Raw source, preflight, start, release and running-state originals are archived under `qa/evidence/20261104/r10-mac-source-and-build-start-r1/` and the two `r10-*-normal-release-r1` prefixes. They retain original JSON bytes, including integer tokens. New controls and exact diffs are archived under `qa/evidence/20261104/r10-physical-ha-source-draft-r1/` and `qa/evidence/20261104/r10-x230-source-draft-r1/`. Root reviews distinguish source preparation, release compilation, and actual runtime qualification.

The prior two X230 outer supervisor values were not recovered. R10 explicitly selects a new 1,800-second overall supervisor guard for each fresh wrapper run; the original inner HTTP, migration, acceptance and cleanup code remains unchanged. This does not attest equality of old overall job caps or an end-to-end timing comparison.

The current source still requires normal44 terminal success, new X230 validation, current physical HA evidence, actual native-archive CLI save/restore and cold recovery, and all outstanding product-surface, credential, client, backup and rollback gates. Production cutover and old-installation removal remain unperformed. Full OpenBao 2.7.1 replacement is not qualified by these release builds.
