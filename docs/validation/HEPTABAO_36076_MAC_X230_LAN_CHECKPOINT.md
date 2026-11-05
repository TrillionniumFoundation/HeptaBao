# HeptaBao：正式存储、三机 HA、AuthBus 与完整替代检查点

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
