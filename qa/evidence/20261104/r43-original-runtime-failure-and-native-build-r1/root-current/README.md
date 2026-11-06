# HeptaBao R43：Mac 原运行失败证据闭合，ROG 正常构建已启动

截至 **2026-11-06 13:46:22 UTC**。任务继续。**完整替代 OpenBao 2.7.1、生产切流、所有当前客户端和备份路径迁移、旧版清理均未通过。** 本检查点固定当前事实与原始记录；源码检查、传输恢复、进程观察和产品回归分别记账。

## Mac AuthBus：已取得完整失败事实，仍需修复

原任务 `mac/1a1b0e85206-fc05-73e1` 以退出码 1 结束，未超时；136,193 字节 stdout 和空 stderr 均完整、持久化。失败为 `ManagerRefused / typed_launchctl_integer`，发生于 launchd 状态解析。运行耗时约 1.499 秒，业务阶段完成数为 **0**，控制 HTTP 尚未构造，因此 AppRole、TLS、KV、Policy、续期、撤销及冷重启没有得到本次成功资格。

原 81 次调用、10 个观察、60 页不可变返回内容已全部保存；作者证据检查重演 1,252 项，根独立复核 265 项。它们证明原失败记录和观察链完整，不是 1,517 个产品测试。当前 before capture 已完成，私有 capsule 正文未导出。11 个直接辅助进程和已返回的文件描述符均已收束。

**launchd 托管注册项与进程仍为 UNKNOWN。** 原 bootstrap 返回 0，但 manager 没有取得 wrapper/真实 server 的 exec 身份；失败清理再次被同一个整数解析检查拒绝。原解析器已明确允许 `78: EX_CONFIG`，现存公共报告没有保留触发错误的具体字段和值，所以不能据错误码猜测修复。下一步只针对这个原注册对象做有限只读投影，随后依据实际结果处理收束与修复。[完整原始记录](../Auth-original-runtime-full453/) · [根资格与未决边界](../Auth-original-runtime-root265/ROOT.qualification.public.json)

## ROG：四个实际构建输入已闭合，149/166 回归尚待终态

四个控制文件的实际元数据与正文均已核对。BODY0 原丢失 ACK 的恢复返回 `reused=true`，原 UNKNOWN 历史保留；其余三个正文通过各自原操作完整取得，没有把失联调用重放成新的业务成功。原四 INFO 的传输链也已独立复核，缺少单独归档的 native 文本只从完整原 SDK 精确提取，不发起新 Native 读取。[BODY0 原恢复](../PKI025b-BODY0-reconcile-full47/) · [其余三个正文](../PKI025b-remaining3-actual-full101/) · [原 INFO 传输](../PKI025b-original-INFO4-full-transport/)

实际绑定请求已且仅已启动 `rog/1a1b10cad9b-fc05-7560`，`reused=false`，候选为 `025b05a340de841b8161c1120344e86eae30eb97`。该候选修复之前 33b 构建的两个参数缺失编译错误；**尚不能声称本候选已编译成功**。计划分母是 **149 项独立测试、166 个配置实例**。截至已完整复核的第三次原观察，进程仍为 systemd active/running；实际 release、测试列表与测试结果均为 null。

原 12,000 秒外层预算、1,800 秒 release、3,600 秒共享编译及各 600 秒测试族预算保持。新的观察次数上限单独明示，不冒称继承自旧 GO。C 持有唯一 Cargo target 窗口，预检 flock 不是终身锁；没有其他 Cargo 构建获准并发。[唯一原始 ACK](../PKI025b-original-BUILD-ACK6/) · [原运行中的完整观察](../PKI025b-original-BUILD-running65/) · [根运行态复核](../BUILD-running56-and-file11-lane24/ROOT.original-BUILD-running56.public.json)

## 快照修复：已读回 12/23 个变化正文，合并候选尚未冻结

先前第 11 个文件的 INFO page0 交付中断已通过原不可变页恢复，原错误保留。现在包括 519,619 字节 `service.rs` 在内的 **12 个正文、1,132,623 字节** 已完整取得；共有 37 个已闭合观察、194 条原调用记录。最新文件的 8 个范围全部闭合，根对这一停止边界和 9 个原终态作了独立复核。这里没有将全部 194 条记录提前宣称为最终全链资格。

B 当前在 INFO12 之前停止，释放通道给 Mac 原实例诊断。剩余 **11 个固定文件、214,014 字节**，每个只需原表规定的 INFO 和单个正文范围，现均未提交。[最新停止边界](../Snapshot-file11-closed-release24/) · [完整 service.rs](../Snapshot-file11-whole-service/formatted-output.rs) · [余下原表](../Snapshot-remaining11-original-table/)

合并方案保留 025b 的 5 个更新叶子和严格 PKI 400 期望，覆盖快照分支的 49 个叶子，其中 23 个为格式化实际输出，26 个按既有冻结全件复用。精确回归清单为 **237 项独立用例、254 个配置实例、18 组**，目前只是源码清单。runner/launcher 与复用现有 stager 的接口已经核查；新 commit/tree/request 仍未绑定。launcher 仍受原 40,000 字节上限约束，最终字面量绑定后须重新计量。[精确清单](../Integrated237-inventory-SOURCE24/) · [runner/launcher 源码](../Integrated237-runner-launcher-SOURCE26/) · [stager 接口](../Integrated237-fresh-stage-interface11/)

## 官方 2.7.1 比对与已发现的 JWT 草案矛盾

已核对官方 v2.7.1 发布资料，并找到 X230 既有官方 Linux 二进制及压缩包的历史实际路径与哈希。后续隔离 fixture 必须重新核验完整包、唯一常规 bao 成员和二进制，再以明确 `version="2.7.1"`、Linux Owner 与验证 TLS 启动；当前没有新官方 HTTP23/HTTP12 结果，也没有为此重新下载或执行旧 full34 wrapper。[官方发布来源](../official271-primary-release-source5/) · [X230 原实际来源](../X230-existing-official271-root-reference/) · [仅源码计划](../X230-official271-oracle-only-plan6/)

JWT ACL 草案 2 存在明确源码矛盾：测试 actor 没有 default policy，却要求空 token_policies 的角色写入返回 204；当前处理器会加入 default，再被既有授权子集检查拒绝。该结论是源码推导，尚未当作已观察到的 Rust 或官方 HTTP 状态。下一步按原 23 个 case 观察官方行为；不能通过给 actor 补 default 或全局放松策略校验来掩盖差异。[具体源码证据](../JWT-ACL-draft2-source-contradiction/)

## 五道最终门槛

| 门槛 | 已保留的实际证据 | 仍需完成 |
|---|---|---|
| 正式 KV2 | 4e808 基线 Mac 31/31、X230 31/31 的正式 34MiB 迁移/恢复 | 最终合并二进制复跑，CLI leader/standby 修复验证与所有备份路径迁移 |
| HA | 4e808 基线 Mac/ROG/Pocket4 真实断主、选主、ReadIndex、持久化和冷重启 98+12 | 最终候选在三台实际机器复跑；原 SIGKILL 结果不声称物理断电 |
| AuthBus | 当前输入捕获与完整启动失败记录 | 原实例收束、最小修复、无 J3160 的真实凭证完整链及冷重启/逆向回滚 |
| 逐台切换 | 当前仍未形成全量切换资格 | 每个当前消费者先真实读写、重启和回滚，再逐台正式切流 |
| 旧版清理 | 没有删除旧服务或恢复资产 | 所有客户端及备份路径迁移确认之后，才清理旧版并保留最新合格服务 |

既有 normal61、full34、LAN 和 X230 69 项历史资格均保留原范围，不能转移给尚未构建的新候选；X230 原 69 项中仍明确区分 67 个精确状态和两个旧 PKI 归一化案例。其余端点、后端集成与灾难恢复缺口继续保留，目录或路由数量不是完整兼容证据。

## 归档边界

本轮挂载 **38 个完整证据树，1,053 个文件，10,333,229 字节**，另加本目录根记录。根索引按完整成员重算所有 Merkle 身份，78 项通过。产品源码不在本检查点修改，前一 R42 提交及其 UNKNOWN/失败历史不改写。纯检查器错误有独立保存，纠正它们不会改动原 Native 结果。[机器可读状态](STATE.public.json) · [完整成员索引](WHOLE-PACKET-INDEX.public.json)
