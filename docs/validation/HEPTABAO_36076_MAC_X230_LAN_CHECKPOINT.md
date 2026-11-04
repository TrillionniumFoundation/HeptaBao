# HeptaBao 36076：Mac、X230 与三机验证检查点

## 当前结论

本检查点记录 2026-11-04 已完成的可复核工作，**不授予全量替代、生产切流或旧版删除资格**。

同一份正常构建源码已完成 Mac 和 X230 的 34MiB 正式 KV2 迁移恢复验证。命名空间退休问题和 TLS 请求分帧问题已有修复及对应测试。三机 HA 正常构建的原始 128 项测试通过 100 项，停在官方历史导入；这一轮导入超过原有 5 秒调用期限后结果未知，未重放。随后相同源码的私有诊断构建完成了全新隔离运行的 128/128 项，但不能替代正常构建的最终验收。

实际安装版 AuthBus 插件已完成真实凭证导入、默认模型凭证选择、重启、续期、撤销及隔离状态回滚。Mac 实际网关已通过启动和完整状态回滚；一次真实默认模型请求返回完整 HTTP 429，业务成功尚未取得。现用 Mac、ROG、Pocket4 的 AuthBus 配置仍指向旧来源，逐台迁移尚未完成。

## 源码和二进制身份

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

## 已通过的具体证据

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

这些计数属于不同合同，不能相加后解释成全部 OpenBao API 通过。69 项对照不覆盖所有错误优先级、所有认证方法或所有 secrets engine。full34、HA、AuthBus 等其他合同分别补充其明确范围。

命名空间修复保留了 mount epochs 的抗复活含义；没有把带挂载墓碑的引擎错误认定为 pristine。它删除的是已退休且无活动资源的精确 namespace incarnation，并保留 incarnation 墓碑。它没有新增任意非空命名空间的级联删除能力。

## HA 尚未通过的门槛

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

## AuthBus 与逐台切换

已发现两个可验证的非 J3160 凭证来源：Mac 当前原生凭证对应既有 profile-2；ROG 上存在与既有 profile-1 相同身份的有效代。凭证有效与模型额度可用分开判断：profile-2 的真实业务响应为 usage_limit_reached；ROG 的 profile-1 当前也记录了 future subscription_limit / wham 状态。迁移不会清除这些真实限制来制造成功。

profile-3 已进行一次受控原生续期，实际 provider 返回完整 HTTP 401，error.type=invalid_request_error、code=invalid_refresh_token。没有新代、未知结果或重试，原生产 stores 保持不变。Pocket4 与 desktop 找到的是同一已拒绝代，ROG 已确认路径没有目标账户的新代，ai395 的三个标准候选路径不存在。这些精确范围内尚未发现替代来源；需要准备同账户的原生重新登录，不能以其他账户冒充。

版本锁定的 Codex 0.133.0 官方源码确认 CLI 凭证存储默认是 File，缺省读取其 CODEX_HOME/auth.json；MCP OAuth 的默认 Auto 是另一种存储配置。当前未发现有效配置覆盖证据，因此没有任意探测 Keychain。该结论不声称所有历史系统凭证条目不存在。重新登录准备必须保护当前原生账户，不注销或覆盖现用凭证。

X230 88 项和 Mac 54 项验证使用真实 provider 凭证，但这些本轮核心检查不调用模型服务，也不派发 provider refresh。Mac 的既有一次 provider 读取成功有单独证据，与当前选中凭证做了精确绑定；不能把跨轮证据合并声称本轮新 provider 调用通过。

Mac 实际 gateway 最新检查已完成真实启动、两次冷启、完整隔离状态回滚及回滚后启动。早期轮次曾被隔离环境 DNS 阻断，均未派发 provider POST；修正实际 Undici 入口观察后，r8 向原模型服务派发了唯一一笔请求，取得 TLS 验证通过的完整 HTTP 429，网关也返回 429。原始 dispatcher 和 Response 保持不变，Authorization 与当前原生来源、实际选中凭证完全相同，并核对 JWT 账户身份；没有注入替代 header。请求账本已封存，没有第二次 POST 或未知结果。业务成功检查保持失败，429 的具体服务端原因另行记录。

现用 Mac、ROG、Pocket4 的 AuthBus 配置仍启用旧来源。每台都需要完成自己的实际消费者读写、冷启和回滚，再执行正式切换。当前默认模型路由、旧 relay 内部绑定、环境代理和历史恢复路径正在分别核对，不能用其中一个事实代替整条依赖链的证明。

## 清理资格

当前不具备删除旧 OpenBao、旧 HeptaBao 或备份恢复依赖的资格。X230 的一个活动 OpenBao 2.7.1 容器已确认属于旧 oracle 命名、网络隔离、无宿主端口、无挂载卷的资产；这些元数据没有证明容器层没有数据，也没有授予删除资格。

清理需等待所有实际客户端、启动配置和备份恢复路径完成迁移。历史查询目录与日志引用单独分类，避免把文件存在误认作活动消费者；也避免在消费者关系未确认时提前删除。

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
| 5 秒导入失败边界 | `352d797c58371547ccfd125d4ceed7ca54baf5f756ebf81a2dd81224951e5a90` |
| private360 单次导入 / HTTP 204 边界 | `f2a2a360936a98383343c4b1a2df210a04a3e931462ea4a7f945e27d145ad4f8` |
| private360 原 128 项完整 summary | `43f467004962c5cf7ca0bb8d80d800d5f10cf60d289d5bd06859018d1ea55456` |
| private360 停止日志补采 manifest | `4e3c4dc3f25d7921f88e8905c53cc605aa9799cb437a45e352e8f7f1dc475d76` |
| private360 完整导入阶段分析 | `a954706ffd066c8cff101e5a0ccdfd10e06001de3fc379bdc6edf253b5a607fb` |
| Mac 两个可信来源完整导入 | `7a6ee0da71910aa58a8d95b517b4c2516a6f3fbf3ad4fac4e1fc5b55b07a7fcb` |
| Pocket4 本机实际插件与 SDK assessment | `840efef707e7744ef1f7e294f97b4d3bf900529ae0764130ea63ec8b9a41d185` |
| 四机当前客户端与备份依赖矩阵 | `aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0` |

原始失败回执均保留，包括构建环境选择错误、选错旧版 oracle observer、SDK 回滚检查点与持久化状态不一致，以及网关首次业务派发前的隔离环境限制。修复后的通过结果没有覆盖原始失败记录。

