# HeptaBao 全量替代 OpenBao 2.7.1：续接状态

记录日期：2026-11-05 UTC。本文记录已完成的代码、真实观察和仍未取得的资格。

## 判定

**全量替代资格仍为 false。当前合并候选没有取得新的 Mac/Linux 正常编译、19 项 Rust 回归或三机 HA 通过证据；不能据此进行正式切流或旧版删除。**

源码候选已经持久化：`f80d2d54800ba7e932d91572c084f930af3e5714`，tree `667ae96b264c5e7f4b9290933612125d883b9e69`，branch `work/20261105-snapshot-combined-61ff-r1`。父提交分别是 outer restore `4f0a732bd934321e5abfc3025a22345a1c42c5ae` 与 HTTP 204 `0e3237fe287553c49e14109ddfbdf33b674e8a64`。

相对 `21a521`，合并候选改变 13 个文件；相对 ROG 现有 `70714605c39014bea93545f7f6aa4217d2a23544`，完整差异为 **33 个文件：22 个 Rust、6 个 Python、5 个已有证据文件**。root 从完整 Git 叶条目重算树对象，复现了基线、两个修复分支和合并树；33 份传输输入合计 1,607,590 字节，也逐个重算 Git blob 和字节数通过。

## 本次落地的修复

### 公开恢复的归档结束行为

公共 `snapshot` 与 `snapshot-force` 上传在读到第一个完整、经过原有内容校验的 tar 归档后结束外层解析，以对应固定 OpenBao 2.7.1 oracle 已观察到的 footer truncation 与串接 gzip 行为。内部默认 importer 和 repair 保持严格 gzip/file EOF。

完整请求体 staging、大小/期限、四个必须条目、tar 终止块、内容 hash、sealed checksums、内部 AEAD 和实际安装门槛保留。新增四项 Service 回归候选覆盖首归档选择、冷重启、必需内容损坏、无效首归档加有效第二归档，以及外层解析成功后的 seal 认证拒绝。**这些 Rust 回归尚未运行。**

### 公共 HTTP 恢复成功返回 204

只有服务端类型化的 `Observation::Upload`、精确公共 POST/PUT 路径、无下载文件，以及完整 finalizer、audit、HA delivery 和 quota metadata 完成后的成功 200，才转换成公共 HTTP 204 并清除 body。内部 Service 元数据语义保留。

PendingRestore inspect/cancel 保留 200 JSON；repair、下载、307、权限/期限/审计失败和未知发布状态保留原响应。真实 HTTPS 回归候选包含 POST/PUT × 两个公共路径、实际 marker 回退、完整历史及 cold reopen。

独立复核发现并修复了 204 的观察盲区：按状态推断 body 长度为零并不能证明线上没有尾字节。FormalApiListener 改为观察 TLS EOF；三个 Python reader 在 `HTTPResponse.read()` 的状态捷径之前从原来的 `response.fp` 读取 EOF。各次 HA restore 也改成上传前验证实际 before epoch，随后要求实际 after epoch 恰好增加一次；capacity 观察没有被称为事务性的 publication receipt。

## 已实际执行与未执行

| 验证 | 实际结果 | 资格边界 |
|---|---|---|
| 新 Python guard | 3 passed、0 failures、0 errors、0 skipped；完整 module 和 30 份固定依赖 | 仅 guard 与标准库字节解析器；无真实 TCP/TLS、Rust 或 HA 执行 |
| Python 输入对应合并树 | 30/30 依赖 blob 与 `f80d2d5` 合并树一致 | 可以关联这三个 Python guard；不转授 Rust 资格 |
| 新 Mac r5 attempt | job `1a1a90d2733-fc05-30d1`，权威 failed/exit 1，预检见外部产品进程后拒绝 | 未应用补丁、未编译、0 项测试执行；不是测试失败 |
| ROG 只读预检 | job `1a1a93e525e-fc05-3335`，launch unknown；同键对账 reused=true、retried_launch=false | 无权威终态、退出码或预检结果；没有提交候选构建 |
| 合并候选 Rust 回归 | 19 项已确定，0 项执行 | 原 14 项、outer 4 项、遗漏的完整 HTTPS 正例 1 项；待现场执行 |
| X230 已留存正式 34MiB 链 | `7071` 正常二进制，31/31 checks，408 个已知子进程均有收尾记录 | 证明该旧源码、正式 native-v6-file profile 的迁移/持久化/恢复链；不自动转给合并候选 |

三个 Python guard 的 stdout 为 0 字节，stderr 为 750 字节，SHA256 `ab72c9b5a8ef2b42f4a707a4330cc214fc9055f0c3488713f48aae2b7ef62628`。其原始外部执行器 SDK 对象未单独保留；会话工具记录观察到 exit 0，日志与 runner 结果已保存，缺失声明已归档。没有重构 original 回执，也没有为填补缺口重新执行测试。

## 两个现场执行阻塞

### ROG 原预检任务状态未知

固定只读请求 commit：`748768eeec9803244364ff61431dd6ece30339ee`。request SHA256：`6f5d05d3535abd90909472dbcbaab457a177b50479d762d4bf145a08588cdfeb`。

唯一幂等键为 `ha-linux-readonly-preflight-61ff-20261105-r1-217c4d2e840a-4a9cf4612c3c`。初次提交返回 `Remote launch outcome unavailable`。三次原任务状态查询均返回原远端 job directory 不存在的错误，没有取得权威状态；同键 API 对账明确返回相同 job、`retried_launch:false`、`status_authoritative:false`。最后一次状态查询时间为 2026-11-05 01:34:49 UTC。

目录不存在或已经过了声明的 90 秒监督时长，都不足以制造终态证明。当前缺失实际 UID/工具链/工作树/锁/资源/进程归属预检结果，构建未获准入。须先对账原任务；后续输入保留禁用执行与空缺字段，没有另造预检 key 绕过未知状态。

### Mac 已知 r10 外层控制器未确认结束

已知 run：`e70cd7fda3c928604cd82e8c1a157502`。只读复查限于已知 T5 r10 目录的一层过滤清单和四份小文件。

末次已观察子进程 PID 12531 的 terminal 继续显示 stopped、leader_reaped、owned_live_group_empty 为 true，但 `ok:false`、`terminal_within_original_stop_deadline:null`，资格明确为 `cleanup-observed-only; stop budget requires live controller delivery`。未取得外层 job、外层 terminal 或取消协调记录。

因此 `outer_controller_job_identified=false`、`outer_controller_terminal_confirmed=false`、`mac_validation_window_released=false`。这不是宣称外层仍运行；也不能因子进程缺席就释放窗口。此次 FS 回包没有提供四份文件的 size/SHA/version，原 SDK 对象未存档，复查摘要明确记录这些限制，没有借用旧 hash 伪装新观察。

## 五道门槛的当前结论

| 门槛 | 证据与剩余工作 |
|---|---|
| KV2 正式存储 | X230 `7071` 的 34MiB 正式存储链通过：17 个保留 live versions、35,651,584 字节，并覆盖 deleted/destroyed 元数据、一次导出/导入、物理 witness、三次 SIGKILL/cold reopen、snapshot restore、CAS。合并候选仍须正常链接后重验，不能沿用旧通过结果。 |
| 真实三机 HA | Mac/ROG/Pocket4 同一候选的真实断主、选主、ReadIndex、持久化与重启尚未形成完整证据。Linux loopback 组件即使通过，也不能代替 Darwin 或三台物理机回归。普通 KV 的 immutable clock transport 仍未接通。 |
| AuthBus | 已验证过一个不依赖 J3160 的可信凭证来源；原 local-RPC 反例仍显示两个已初始化渠道共享同一可写目录，`singleWriterGatePassed=false`。421 个检查包含反例与回滚收尾，不代表修复成功；新候选上的真实生命周期和当前凭证鲜活性未复验。 |
| 逐台切换 | 已建立六台主机的 144 个候选路径、21 个已配置 agent 条目登记。它们不是已迁移服务数或有效备份数。以本合并候选计，尚无主机完成全部真实凭证读写、重启、回滚和正式流量证据。 |
| 旧版清理 | retirement 仍全部为 false。客户端与备份路径尚未逐项闭环，当前 OpenBao、回滚材料及仍需使用的 2.7.1 oracle 保留。 |

前序 KV immutable transport 与 AuthBus fixed writer 的继续开发调用曾被自动审查以 “possible cybersecurity risk” 中止，未返回更细代码原因。本轮没有通过换入口重提这些被阻止的动作；新快照修复没有解除这两个门槛。

## OpenBao 2.7.1 的全量分母

已将官方 v2.7.1 固定为 `a5db72cef75c24b920ade02065b18dd8eb666bac` 并重新审计。仓库旧 59-surface、472-fixture corpus 的目标是 2.6.2，不能当成 2.7.1 全量验收。

当前正式 V6 admission 仍对 JWT/Kubernetes/OIDC 等认证状态、动态 database/外部 owner、非默认 Raft 管理和部分 namespace/control-group custody 施加限制。其他模式的能力不能自动转授给正式 V6 profile。还需完成 2.7.1 专属安全/续期回归和实际部署的插件、客户端及备份范围确认。

## 精确续接顺序

1. 先解决原 ROG job 的权威对账，并取得 Mac r10 外层完成或取消协调证据；记录真实运行窗口。
2. 对固定合并源码取得当前工具链、干净工作树、独立源码/target/cache 归属、锁与资源证据，保持原 normal profile 和 phase guard。
3. 执行 strict 检查、正常 libtest 编译、19 个唯一命名组件；有真实通过与已知收尾后才进入正常 server/seed 链接。任何字节修改均形成新的源码身份。
4. 将新 Linux 正常二进制交 X230，在新私有输出目录按既有单次导出/导入和原 business deadline 重验正式 34MiB 链。
5. 在 Mac、ROG、Pocket4 上完成同一源码对应二进制的真实 HA 闭环；另行攻克普通 KV transport 和 AuthBus 单写者门槛。
6. 每台完成真实凭证、TLS、AppRole、KV、policy 拒绝、续期/撤销、重启与回滚后才切流。客户端和可恢复备份逐项迁移后，才执行条件成立的旧版清理。

以上顺序没有减少用户要求的范围，也没有把未执行项目写成通过。

## 后续控制包与证据导航

Linux 控制包已固定在 `b337f1013ef78c7842356539d986eadda04425dc`；driver 为 47,078 字节，SHA256 `1b7612f40601bdc60d4be40b812746d1e7f78cd1542804d9d67ed1d1365070f9`。root 独立确认原 OwnedRunner 类保持逐字、三份 custody helper 仅将 UID 501 适配成 1000、33 份压缩源码与固定树一致，19 个测试实际函数位置和顺序一致；已完成的只有离线语法与静态检查。`bootstrap`、`process_request`、原任务关闭证明和当前成功预检都仍为 null。

- [合并源码与完整差异](combined-source/combined-source-publication.public.json)
- [33 份输入的 root 独立核验](combined-source/combined-source-input-root-review.public.json)
- [19 项清单和禁用控制器](../ha-linux-combined-candidate-61ff-r1/README-controller-r2.md)
- [控制器的 root 独立复核](linux-preflight/root-linux-offline-controller-review.public.json)
- [ROG 原任务状态未知的完整记录](linux-preflight/root-unknown-launch-review.public.json)
- [Mac r10 限域复查及证据限制](mac-r10-followup-20261105/review.public.json)
- [Python guard 实际结果](../native-snapshot-http204-61ff-r1/python-guards-result.public.json)
- [Python 执行器原件缺失声明](../native-snapshot-http204-61ff-r1/python-guards-executor-receipt-missing.public.json)
- [六机候选迁移登记](fleet/fleet-candidate-migration-register.public.json)
- [固定 OpenBao 2.7.1 范围审计](acceptance-scope/openbao271-readonly-audit.md)
