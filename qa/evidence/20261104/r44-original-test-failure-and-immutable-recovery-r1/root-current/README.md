# R44 — 原始 JWT 测试失败、Mac 注册变化与快照分页恢复

证据截止：2026-11-06 15:08:00 UTC。前一检查点：`5733a11714677d542fa9a8dbed260364c68f14cf`。

**全量替代 OpenBao 2.7.1：未证明。生产切换：未进行。所有当前客户端与备份路径迁移：未完成。旧版删除：未进行。任务继续。**

本检查点保存 37 个已整件读取的证据包，共 773 个文件、13399936 字节；逐成员 Git blob、字节数、SHA-256 和树的 Merkle 校验见 [INDEX.public.json](INDEX.public.json)。索引检查只证明归档完整性。源码机械检查、构建成功、运行断言与生产迁移分别记录。

## 本轮已经确认的结果

### 1. ROG 正式构建成功，回归在第二个 JWT 测试失败

原任务 `rog/1a1b10cad9b-fc05-7560` 的完整终态、全部输出和 49,775 字节报告均已取回。源提交为 `025b05a340de841b8161c1120344e86eae30eb97`，源树为 `1d8160c9385f8053b9a683cc1834da0f912e2d37`。它没有在编译阶段失败：

| 阶段 | 实际结果 | 原预算 |
|---|---|---|
| 默认功能正式 release，server 与 seed | exit 0，632.549 秒 | 1,800 秒 |
| ordinary-no-default check | exit 0 | 下列三项共享 3,600 秒 |
| file-libtest build | exit 0 | 同一共享截止时间 |
| default-libtest build | exit 0 | 同一共享截止时间 |
| 三项共享编译合计 | 2,161.133 秒，未重置截止时间 | 3,600 秒 |
| 第一个原生 JWT 身份、续期、冷重启测试进程 | exit 0 | 原 file17 组预算 |
| 第二个拒绝 remote / batch / 坏签名测试进程 | exit 101，0.0773 秒 | 随后停止 |

只实际进入第一组、运行两个测试进程；149 个唯一测试、166 个 profile 实例是计划数量，不能记为通过。原报告的异常为 `AssertionError`，消息为空，具体断言仍须读取原第二测试的固定 stdout/stderr。两日志元数据读取已获精确范围并进行中，没有重建或重跑原任务。

报告记录的 8 个直接子进程都已回收，剩余组成员为空；旧保留资产前后相同。但最终 `source_unchanged`、`binaries_unchanged`、`release_artifacts_unchanged` 字段未写入，不能补成已经观测，Cargo target 仍未取得复用资格。

完整原终态链：31 calls、10 observers、10 pages，原检查 403 项与 root 168 项。报告 BODY 链：7 calls、1 observer、5 pages，原检查 87 项与 root 35 项。

证据：[原报告](../PKI025b-report-BODY-actual-full51/report.original.json)、[完整报告链](../PKI025b-report-BODY-actual-full51/CALL-INDEX.public.json)、[root 资格](../C-report-root-A-source-root-C-logINFO-GO/C-report-full-root35.public.json)。

### 2. Mac 已定位 parser 字面值问题；后一次观察发现注册已缺失

第一次原注册只读诊断的两次 `launchctl print` 都显示 running、PID 32527、runs 1。唯一被严格数字解析拒绝的字段是 `last exit code = (never exited)`。源码修补仅让该字段的这个字面值映射为 None；PID/runs 的数字约束及最终成功必须等于 0 的条件保留。此修补只有源码资格，尚未执行 Python 回归或业务验证。

随后固定 PID 身份诊断 `mac/1a1b148990b-fc05-7784` 的第一次精确 print 返回 113，注册缺失；现有控制流在 PID 采样前拒绝，因此没有 PID 元数据、没有第二次 print、没有后续就绪文件观察。原 6,920 字节输出与所有观察链已完整取回，17 个应用 FD、1 个直接 helper 都已关闭/回收。

**这一条缺注册观察不能证明 PID 已退出，也不能证明谁移除了注册或历史 managed scope 已关闭。** 历史 UNKNOWN 保留，没有发送信号、bootout、读取旧私密 capsule 或重试业务。

下一版只读源码已将注册分类与固定 PID 分类分开，仍保持两次 print、原七个固定路径、45/35/60 秒边界和原资源清理。ESRCH、混合采样、身份变化都保留 UNKNOWN；缺注册不会跳过剩余固定观察。root 15 项与新的纯源码 62 项通过，截止时未发运行 GO。

证据：[第一次完整诊断](../Auth-registration-diagnostic-full86/actual--stdout.original.txt)、[后一次完整失败](../Auth-PID-identity-original-full70/actual--stdout.original.txt)、[后继源码范围](../Auth-independent-label-PID-SOURCE21/CONTRACT.public.json)。

### 3. 快照第二次分页缺口已恢复，原失败记录保留

格式化文件 `service_snapshot_forward_wire.rs` 的原 binary_read 已结束且 future inactive，但取第一页时发生 MCP -32603 传输超时。这个传输错误不构成产品功能失败证据。

恢复使用同一不可变结果：只新增一次 offset 0 结果取回，再按实际 next_offset=16384 续原 `p2`。没有新增 binary_read、status、重置页计数或改写原 failed p0。22,426 字节原 payload 重建后，16,474 字节文件的完整哈希与固定版本一致。之前 INFO10 的失败与独立恢复、file7 的 Git 读取失败也保留。

截止本检查点，root 已确认的边界为 **17/23 个文件、1,200,639 字节、47 个 closed observers**；剩余 6 文件、145,998 字节依原固定表继续。前 12 文件的 1,066 个原始 blob 输入、12,434 项前缀检查已由 root 精确复现。最终 23 文件及 49 overlay 资格尚未完成，新增 snapshot 源码尚未因此取得产品运行资格。

证据：[恢复原件与边界](../Snapshot-file16-recovery-actual19/BOUNDARY.public.json)、[root 21 项资格](../Snapshot-file16-recovery-root21/root-qualification.public.json)。

### 4. X230 官方 ACL23 fixture 已完成源码准备，尚未执行

入口使用既有官方 OpenBao 2.7.1 Linux archive 与 binary，实际运行时仍须验证当前文件、整件哈希及 TLS 下的真实 2.7.1 服务。新的外层请求拟为 390 秒，原 owner 的绝对 360 秒截止时间保持不变。入口修正了两处具体源码问题：每次写入限制为 65,536 字节；额外 health 请求分别记录实际 attempted/completed。

这条 fixture 仅观测官方 23 个 ACL 场景；候选 HTTP12 与候选 ACL 对比均尚未运行。JWT draft2 中“无 default policy 的 actor 与自动补 default”源码矛盾继续保留，不能通过给测试 actor 增权或放宽全局校验掩盖。

证据：[入口 R2](../official271-ACL23-entry-R2-SOURCE13/)、[journal](../official271-ACL23-journal-SOURCE9/)、[root 32 项源码资格](../official271-ACL23-R2-root/)。

## 用户五道门槛的当前状态

| 门槛 | 已有有效证据 | 尚需完成 |
|---|---|---|
| KV2 正式迁移/恢复 | 历史 `4e808d0` 上 Mac 31/31、X230 31/31，34MiB、19版本、迁移/快照恢复/冷重启语义 | 最终整合二进制上重做，覆盖 leader/standby CLI 原失败路径，并核对当前备份路径 |
| Mac/ROG/Pocket4 HA | 历史同版真实 LAN 98+12，SIGKILL 断主、选主、quorum 503、ReadIndex、原密钥冷重启 | 最终候选同字节多机回归；历史结果不包含物理掉电 |
| 无 J3160 的 AuthBus | 原失败、parser 字面值及注册变化均有完整原件；本轮没有使用 J3160 | 建立当前可信凭证来源和全新可追踪 scope，完成 AppRole/TLS/KV/Policy/续期/撤销/重启/回滚 |
| 逐台切换 | 尚无新生产切换 | 当前每台 consumer 清单、真实凭证 R/W、重启、回滚，再逐台切流 |
| 清理旧版 | 未删除旧服务、二进制或资产 | 所有客户端及备份路径迁移完成后才清理；保留必要证据与恢复资产，仅留下最新合格服务 |

旧版 normal61、formal34MiB、LAN98+12 与 comparison69 均只属于其原提交和原范围。comparison69 中两条旧 PKI 状态曾经过归一化；新的严格 400 断言仍待实际完成。源码路由数量不能代替 OIDC、Kubernetes、MFA、远端 JWKS、真实 DB/RabbitMQ/Kubernetes secrets、ACME/EAB、seal/rekey/recovery、KMS/HSM 等未完成的替代证据。

## 接下来直接推进

1. 读取原失败测试日志，定位并修复具体断言的原因。
2. 收齐格式化 23 文件，绑定保留两个精确分页异常的最终检查器，固定整合 commit/tree。
3. 完成 Mac 独立注册/PID/公开文件诊断，以当前证据建立新验证 scope；历史 UNKNOWN 仍原样保留。
4. 执行 X230 官方 ACL23，完成 JWT 局部兼容修复与严格 HTTP12。
5. 对同一最终二进制跑整合 237 unique / 254 profile、Mac/X230 formal34MiB 和三机 LAN 回归。
6. 完成逐客户端与备份迁移，再执行用户要求的逐台切换和有条件清理。

机器可读状态：[STATE.public.json](STATE.public.json)。本提交是继续工作的证据检查点，所有失败和未完成门槛均保持显式。
