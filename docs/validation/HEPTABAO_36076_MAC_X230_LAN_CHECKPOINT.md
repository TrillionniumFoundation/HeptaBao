# HeptaBao：36076 验证与 33cafa HA 候选检查点

## 当前结论

本检查点记录 2026-11-04 已完成的可复核工作，**不授予全量替代、生产切流或旧版删除资格**。

最新正常候选为 `33cafa4c`，Mac 和 ROG 均已按原 release profile 完成构建，没有启用 private diagnostic。Mac server SHA256=`d8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20`；Linux server SHA256=`7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`。该 Linux 产物在 X230 上的原 full34 已通过 31/31（147.112 秒），原官方 2.7.1 对照双方均为 69/69（44.541 秒）；源码和二进制前后相同，owned 服务全部停止。原断言、15 秒 HTTP、360 秒迁移预算和 13 模块对照入口均未改动。

新候选的三机原 128 项已经终态失败，90 项通过、38 项未执行。该轮自然角色为 ROG 节点 2 向空缺 Mac 节点 1 恢复；seq47 单次冷解封在 14,099.923ms 返回完整 HTTP 503，服务内部原 14 秒恢复期限已耗尽。47 个 mutation intents 均有确定 response，unknown=0，owned 服务、mesh 和观察器全部停止。原 5 秒导入、15 秒 HTTP 和 8 秒 admission 限制均未改；响应端修复不足以关闭冷恢复门槛，旧 Pocket4 节点 3 向 Mac 节点 1 的失败方向也未覆盖。下文 `36076` 的旧证据分别保留其身份，不能自动改标为新候选。

既有 `36076` 正常构建源码已完成 Mac 和 X230 的 34MiB 正式 KV2 迁移恢复验证。命名空间退休问题和 TLS 请求分帧问题已有修复及对应测试。三机 HA 正常构建首轮原始 128 项测试通过 100 项，停在官方历史导入；这一轮导入超过原有 5 秒调用期限后结果未知，未重放。随后相同源码的私有诊断构建完成了全新隔离运行的 128/128 项。再后的一次全新正常构建运行通过 90 项，在密文缺失恢复中的节点 1 冷解封收到明确 503；诊断通过不能代替正常构建验收，两次正常失败均保留。

实际安装版 AuthBus 插件已完成真实凭证导入、SDK 凭证选择、重启、续期、撤销及隔离状态回滚。Mac 隔离网关已通过启动和完整状态回滚；一次沿内置 HTTP 路径的真实默认模型请求返回完整 HTTP 429。后续核查发现生产还安装并启用了 Codex 原生插件，r8 的插件允许集合未覆盖它，因此该轮不能代表完整生产运行时。现用 Mac、ROG、Pocket4 的 AuthBus 配置仍指向旧来源，逐台迁移尚未完成。

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

当前 PR head 已追加为 1780833661058efff2e31cd2ce2733d485075ac3，tree=3835532737b5a2369ea46947442b3c03a77d0271，仅变更 CI workflow：Cargo 编译并发固定为 1，编译阶段记录有限内存、磁盘和进程资源计数；采样器在任何 Rust 用例开始前停止并 wait。原完整测试命令、matrix、所有其他步骤、features/profile 和 90 分钟 job 预算保持不变，产品 Rust 文件仍与物理 33cafa 一致。新的 run 41797943393 尚待终态；记录资源计数不代表已证明内存或磁盘耗尽。

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
