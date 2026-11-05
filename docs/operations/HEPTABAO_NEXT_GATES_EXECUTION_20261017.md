# HeptaBao 下一阶段执行记录（2026-10-17—18）

## 当前结论

已完成同源 R8j 的 Mac arm64 / Linux x86_64 原生构建、Mac 30 项 native 集成回归，以及 R8m 在真实 Mac 上的 3 项当前闭包修复回归和 1 项 34 MiB 双对象包回归。Mac / ROG / Pocket4 的 native 物理验收已经实际启动两次；第二次在第五笔历史写入返回 503，尚未进入断主、重选主和全冷重启阶段。

**五项生产门槛尚未全部关闭。生产流量尚未切换，旧 OpenBao 尚未删除。** 本文中的每个结果保留自己的源码、二进制和测试范围，不把不同版本、组件或客户端的通过数相加为生产资格。

远程执行通道已经恢复。原 Mac R8g 任务 `1a14a0b3e5d-1b6abb-13e` 的原任务状态和完整输出已取回：任务退出 1，Cargo 退出 101，原两处 RootError 编译错误，测试未运行，源树未变。该失败原样保留，没有重跑或改写为后续版本的通过。

独立 AuthBus 的四机真实 Google key canary 已各完成 141 项。新的 SDK owned-source R2 完成 293 个通过事件、292 个不同 case 标签；原驱动退出 0，外层控制器因同一个合法双客户端场景重复 case 标签而退出 1，严格对账文件保留这一差异。四机迁移 metadata 回执有效，但仍存在清单边界和未迁移对象；当前四机 AuthBus 配置仍指向 J3160。

## 五项门槛

| 门槛 | 已完成且有证据的工作 | 尚需完成 |
| --- | --- | --- |
| KV2 正式存储 | 有界迁移、根/cursor 原子发布、跨 barrier 重封装；R8m 实际 Mac 当前闭包修复 3 项和 34 MiB 双对象包 1 项通过 | 正式 Service/HTTP 恢复准入、导出结束时的原权源与终结时钟绑定、历史/灾备 epoch 转换；完整 HTTP 34 MiB 写链及三机资格 |
| Mac / ROG / Pocket4 HA | V5 62/62；R8j 同源两种原生 ABI、Mac 30 项通过；native 物理第二次 35 项实际观察、34 通过 | 第五笔历史写入的交付拒绝；保持原 15 秒请求、8 秒 ReadIndex，完成新版本全部 89 项真实三机验收 |
| 独立 AuthBus | 四机各 141 项真实 Google canary；合成中央发布器 314 项；实际 owned-source R2 的 AppRole/TLS/KV/Policy、SQLite 恢复、续期及撤销持久化 | 全部真实源和消费者映射、provider 活性/刷新归属、真实 A→B 轮换、生产 coordinator 与 scheduler 接替资格 |
| 逐台切换 | 19 个 SecretRef、38 条 backup/runtime、12 条 binding 已形成逐条清单；四机批准范围扫描原件及缺口均已保存 | Mac 枚举截断、main 两个缺失 agent、10 个未在投影中找到 consumer 的 SecretRef；每台实际迁移/重启/回滚与全部备份恢复合格后切流 |
| 旧版清理 | 保留现状及已观察到的旧服务入口，清理条件继续生效 | 只有所有客户端和备份路径完成迁移后，才停止并删除旧服务、二进制及可再生成资产 |

## 已取得的验收结果

完整原始回执和摘要校验位于 [证据索引](../../qa/openbao-acceptance/evidence/next-gates-20261017/index.json)。保留失败回执，后续通过不会覆盖它们。

| 验收 | 结果 | 实际覆盖范围 |
| --- | --- | --- |
| R6 三物理机 HA | 62 / 62 通过 | Mac、ROG、Pocket4 的正常 V5 Service：真实 leader SIGKILL、重新选主、ReadIndex、失去 quorum 后拒绝、追赶、三机全冷重启及持久化写入 |
| R7 Python AuthBus | 111 / 111 通过 | 合成 AppRole、Policy、KV、CAS、错误 CA、续期、证书叶绑定、重启、配置回滚、撤销持久化 |
| Mac R8c native Service | 24 项 Auth、2 项迁移恢复、6 项对象测试通过 | 原 Actor/SID/cert/issued token 在 fsync 与强制审计前后保留；迁移/恢复与跨 barrier 的真实对象重封装 |
| Mac R8f 34 MiB TLS | 1 项通过 | 两个实际 pinned TLS 接收端的完整闭包多数派及唯一根 CAS；第三个密文接收端离线；14,092 ms 完成，原 15,000 ms 未延长 |
| 批量 TLS 与缺块读取组件 | HA 4 项通过；Raft 125 项通过、1 项原有忽略 | 三叶有界批量、真实黑洞连接与健康来源并存、错误证书和过期原截止零目标写入、冷缺块新主恢复 |
| main 原插件与 SDK、真实 Google key | 141 / 141 通过 | 官方元数据端点、实际 SDK SQLite、每次新 TLS 叶核验、续期、冷重启、备份恢复、错误 CA 回滚、四个 bearer 与 SID 的撤销及冷持久化 |
| main 当前插件模式 | 248 / 248 通过 | `publishNew=true`、`manageOrder=true`、shadow 调度的原生产者/消费者行为；中央提交由测试写入器完成，不代表中央服务已经接替 |
| Mac 原插件与 SDK、真实 Google key | 141 / 141 通过 | 该物理机实际插件、SDK、凭证、TLS、重启、SQLite 备份、回滚和撤销 |
| ROG 原插件与 SDK、真实 Google key | 141 / 141 通过 | 该物理机实际插件、SDK、凭证、TLS、重启、SQLite 备份、回滚和撤销 |
| Pocket4 R1 | 103 项通过，第 104 项失败 | `plugin.actual_inbox_list` 预期 200、实得 404；后续撤销步骤未运行，整轮未合格 |
| R8g 本地编译 | 失败，3 处错误已保留并修复 | 生产路径引用了 test-only schema 常量，两处测试缺少 RootError 转换 |
| R8h 本地编译 | 通过 | Rust 1.98、locked/offline，库、服务二进制与测试目标；编译通过不等于运行通过 |
| R8g 原远程任务对账 | 失败，已取回原件 | Cargo 101、两处 RootError 转换错误；原 2,534 文件源树一致，未将后续结果覆盖原失败 |
| Pocket4 R2 真实 Google canary | 141 / 141 通过 | 原 0.3.3 插件、实际 SDK、准确 Google 资源范围；仍保持 shadow、enforce=false；原 R1 失败保留 |
| R8j Mac native matrix | 30 / 30，7 组通过 | 并发容量、完整 Service、精确时钟、安装、Auth、对象 TLS、迁移；来源与物理验收二进制分别绑定 |
| R8j 两种原生 ABI | 两个构建通过 | Mac arm64 与 Linux x86_64；完整源码和独立二进制摘要已保存，构建不等于物理验收通过 |
| R8j native physical 01 | 18 项已观察且通过，随后失败 | V5 seed 历史读取将版本放入 GET body，被真实 HTTP 边界忽略；未进入故障阶段；owned 服务和 mesh 已停 |
| R8j native physical 02 | 35 项已观察、34 通过、1 失败 | 修正历史版本 URL query 后通过激活与 seed；第五笔 2 MiB 历史写入 HTTP 503；未完成 34 MiB 或 HA 故障回归 |
| R8k Mac 34 MiB archive | 1 项通过，21.23 秒 | 原请求预算内执行的真实双对象包/hostile 输入回归；整项测试时间不等于单请求时限 |
| R8m Mac 当前闭包修复 | 3 / 3 通过，22.78 秒 | donor 全缺、独立 cold owner、真实 ReadIndex 超过 8 秒后保持原 15 秒截止、checkpoint 漂移及历史根拒绝 |
| R8m Mac 34 MiB archive | 1 / 1 通过，21.20 秒 | 真实双对象包往返和 hostile 输入；完整 2,588 文件源树运行前后相同，原 R8k 基础目录亦未变 |
| R8n shared-01 Mac 对象同步 | 13 / 13 通过，0.95 秒 | 11 个新增和 2 个既有 checked I/O 测试；真实同 fd/目录同步、坏叶/替换/原截止拒绝；2,590 文件前后完整校验；没有执行本候选的完整 HTTP 或物理 HA |
| 合成中央 AuthBus R1 | 314 个检查通过 | 原生产者/消费者、manifest CAS、真实 HTTPS/SDK、进程中断与冷重启；没有真实 provider 凭证或 OAuth 刷新 |
| 实际 owned-source AuthBus R2 | 驱动成功；293 事件 / 292 不同标签 | 实际来源 A、原 SDK、中央提交/消费者、私有 journal、服务冷重启、SQLite A 恢复、15 个 bearer 及 3 个 SID 的撤销持久化；原外层 false 单独严格对账 |
| migration-gap v3 四机扫描 | 4 / 4 回执有效 | 批准范围内 metadata/配置投影，未打开凭证载荷、未连接 J3160；有限枚举和历史 reused 观察明确标识，迁移/备份/切流/清理资格均 false |

批量组件最终一次的 34 MiB 多数派加根 CAS 为 **3,830 ms**，冷缺块新主拉取为 **2,705 ms**。这些计时来自组件场景，不是物理三机或生产流量的延迟指标。

三物理机 V5 结果使用完整的、经已有 SSH host key 核验的 loopback mesh 承载端到端 pinned mTLS。main 是通道控制端，不是 voter。该结果证明进程故障恢复；不证明直接 LAN 分区或物理断电行为。

## 本轮实现的关键行为

### Native V6 存储与共识发布

迁移以原 V5 根、完整 publication LogId、本地 Durable owner、barrier、seal 和原请求截止为来源。对象写入按有界 locator 批次推进，最终以条件事务选择根和 cursor；未知 fsync 或根发布结果会进入恢复状态。

HA 发布保留同一个随机 operation，只提交一次 intent，只收集实际 TLS 完整闭包 fsync 票，只尝试一次根 CAS。CAS 一旦开始，之后的超时、失去原 Actor、fresh-read 失败或本地安装失败都不能被报告为“肯定未提交”，也不能自动创建新 operation 重试。

原 Actor、本地源和原截止在准备、暂存、复制及 CAS 前后持续检查。实际 ReadIndex 和 fsync 回执都不替代业务授权。intent 暂存使旧 generation 见证失效后，代码取得真实新读并比较原根、enrollment 和完整 provenance。

### 本地安装与读取

实际已提交根的共享密文经过验证后，按各节点自己的 barrier 重封装。Raft 根 generation 与本地 Durable publication generation 分别记录。最终事务同时更新实际根、active cursor、保留源和 HA cursor。

冷恢复只允许修复实际当前闭包中、已有合法 metadata 所登记的缺失对象；已存在但损坏的文件不会被覆盖。旧 HA 根缺少过时数据时，可以在原 unseal 截止内安装实际最新闭包，无须把缺失的旧 payload 重新当作权源。

对外回复持有原请求的 opaque native read proof。强制审计后复核同一个 proof、原 Actor、目标对象、issued token、时钟和实际安装状态；不能通过重新捕获一个新 proof 掩盖审计期间的状态变化。

### HA 并发容量

最小普通工作池中的业务转发可以占满 native 接收和 ReadIndex 所需容量。显式 `start_native_v6_candidate` 在开始接收连接前，为 native 与 ReadIndex 各增加两个独立配额及相应工作线程，保留原业务转发容量和两个共识工作线程。

普通 `HaProcess::start` 保留原行为。普通启动后再迟启用 native 被拒绝，避免把新功能放进容量不足的旧池。新测试以真实 TLS 业务请求占满两个健康节点的业务处理器，并要求在第三节点停止时，ReadIndex、两个实际 fsync 票、一次 CAS 和 follower 读取仍在原 15 秒内完成。

## Pocket4 R1 的失败与 R2

Pocket4 使用原 0.3.3 插件，Mac 与 ROG 使用 0.3.1。0.3.3 只上报调度策略中明确覆盖的资源；R1 使用的空 `providers` 策略没有产生 inbox 事件，因此 LIST 返回 404。

R2 只为隔离 Google 测试 profile 增加准确的 host/agent 范围，保持 shadow、`enforce=false`，保留原 key、来源证明、插件、SDK 和八个冻结的 R9 依赖。它仍要求原始 LIST 200、四轮各一个上报及完整 141 项验收。没有把 404 改成可接受结果。

控制器：[authbus_pocket4_credential_canary_r2.py](../../qa/openbao-acceptance/authbus_pocket4_credential_canary_r2.py)。R2 已在独立目录实际完成全部 141 项；[原始回执](../../qa/openbao-acceptance/evidence/next-gates-20261017/pocket4-canary-public-r2.json) SHA-256 为 `f471c6f93b0e3008cbf8962137100db7e672e26b2022f07fd5b434f1538378fa`。这证明该隔离来源和客户端链路，不代表所有旧凭证已迁移。

## 中央 AuthBus 与凭证来源

原插件没有 inbox LIST、不可变 profile 写入或 manifest CAS 发布器。`leader=true` 的业务分支筛选并刷新 OAuth，然后把 `leader-refresh` 事件写入自己的 inbox。因此原插件 leader 测试不能代表中央发布器接替。

独立中央候选需要原生产者 → 按 host 核验的 inbox → 不可变 profile → manifest CAS → 原消费者的完整闭环。每次凭证替换绑定明确的当前/下一凭证摘要和来源身份；私有 fsync journal 保存未决操作，未知 manifest 回复只能由准确的当前版本或对应 KV2 历史证明，不能盲目重发。

现有 Google key 的来源完全独立于 J3160。它证明该 key 的所属来源和实际可用性，不代表旧 OAuth profile 已迁移或具备刷新资格。SDK 来源工具只通过原 SDK 的只读 persisted-owner API 读取明确列出的库，导出前后复核；private candidate 保留在来源主机。

另一个独立的 SDK enforced-deny 实验发现：SQLite 拒绝撤销写入后，当前和冷 resolver 仍可选择旧 grant。该实验整体验证失败，证据已保留。现有客户端使用 shadow、enforce=false；不把该实验的局部通过写成 enforced 模式已经合格。

### 实际 owned-source R2 的结果和严格对账

[实际驱动回执](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-owned-source-actual-r2-public-receipt.json) 的 293 个事件全部通过，其中 `actual_manifest_cas_race.captured_actual_token` 在两个真实 AppRole 客户端上各产生一次，因此不同标签为 292。原驱动退出 0；[原外层回执](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-owned-source-r2-controller-public-receipt.json) 因要求标签唯一而 false/退出 1。两份原件不变；[严格对账](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-owned-source-r2-reconciliation-r1.json) 检验摘要、唯一重复位置、15 组 bearer live/cold 撤销、3 组 SID destroy/cold login 400、原来源多次复核以及最终 A 一致性。

实际执行没有联系 J3160、没有 provider 调用或 OAuth refresh，也没有真实 A→B 轮换。续期使用同一 bearer 的实际续期调用；本地 due 时间缩短仅用于触发实验。服务与 journal 的冷恢复、110,592 字节闭合 SQLite A 备份回滚均属于这一单节点隔离 fixture。成功退出包含原 Popen child 的 finally 清退，但没有独立 kernel birth/owner retirement 回执，不能据此声明全机零残留、所有 bootstrap 权源撤销或生产迁移完成。

### 逐台迁移清单

[正式迁移清单](../migration/authbus-owned-source-migration-20261018.md) 与 [完整 JSON](../migration/authbus-owned-source-migration-20261018.json) 逐条列出 19 个 SecretRef、38 条 backup/runtime、12 条 binding、main 两个缺失 agent、Mac 四个启动项和八个依赖。没有由文件存在推导可删除，也没有猜测目标 KV mount/key。

四机当前 AuthBus 配置仍为 `https://100.66.117.33:8200`。19 个 SecretRef 文件均存在并符合 owner/0600/配置路径，但载荷未打开；Mac 四条、Pocket4 六条在批准配置投影内没有 consumer pointer。Mac maintenance 命中一处每目录条目上限，68 个 depth-2 目录未递归；main 两个 agent 目录和各自五个文件共 12 次 FileNotFound。21 个 client scope 和旧 client-store metadata 保留原 2026-10-17 reused 日期。以上缺口保留 pending；扫描成功并不把任何迁移资格改成 true。

## Native 物理验收第二次失败

[physical 02 回执](../../qa/openbao-acceptance/evidence/next-gates-20261017/r8j-native-physical89-02-summary.json) 绑定 R8j 两种实际二进制和独立 query 修正 QA。前三台 voter 为 Mac / ROG / Pocket4；同一分支另外保留的 Mac / ROG / X230 回执是不同实验，不能相互替代。

前四笔 2 MiB 历史写入分别 HTTP 200，用时 4,602、7,157、8,709、10,975 ms。第五笔在 14,018 ms 返回 HTTP 503；只确认前四笔额外 8 MiB 已得到成功回复。原 HTTP 15 秒、ReadIndex 8 秒、17×2 MiB 和 89 项要求均未降低；没有自动重试第五笔，也没有进入 leader SIGKILL 阶段。三台 owned 服务和本次 mesh 已停止，目录和证据保留。

[只读诊断](../../qa/openbao-acceptance/evidence/next-gates-20261017/r8j-native-physical89-02-diagnostics-r2.public.json) 确认 Mac 审计先记录计划响应 200，随后 seq 69 记录 `ordinary-kv-delivery-veto` 503。该 veto 可能来自原截止、private owner、强制同步、recovery、sealed 或最终 Actor 复核；五条没有请求关联的 r72-sync 日志不能确定第五笔具体失败子阶段。计划响应的审计时间不是响应发送时间，计划 200 也不能证明根 CAS 成功。实际业务结果不能按“肯定未提交”处理。

下一候选保留所有原权源与时限，仅减少已有精确对象的临时写盘与重复加密。新增 veto 诊断应以成功落盘的 veto audit sequence 关联闭集失败原因，不能输出路径、token 或凭证指纹，不能在成功响应最后 Actor 检查之后新增日志 I/O。

## Native HA 备份仍是门槛

本地 `HBV6PK01` 使用节点 barrier；Raft 选择的共享 ciphertext closure 使用 replication key 和原始随机 nonce。相同明文重新加密不能生成旧共享叶引用。因此本地对象包及其摘要不能代替原共享闭包备份。

完整 HA 归档需要同时绑定两个对象包、实际根、完整 intent/publication LogId、enrollment、epoch 和本地 seal。只修复实际当前根的缺块，与在线恢复历史状态、无原 quorum 的灾备恢复是不同模式。

R8m 的内部 `HaProcess::repair_native_v6_current_closure_from_archive` 已完成真实 Mac 3 项回归，34 MiB 双对象包回归亦通过。它先取得真实当前 ReadIndex，保留原 owner callback；仅允许对原 closure 缺失叶写入精确共享密文，实际 file/dir fsync 和 full closure open；过期 ReadIndex 只能通过新的真实读及同一 selection 条件续取见证，不能重置原请求截止。归档只提供数据，不提供新授权或 quorum 票；已有坏叶拒绝且不覆盖。

**内部 helper 尚未开放 Service/HTTP 恢复入口。** 正式 warm 准入需要先在真实当前根中验证原 Actor/Auth，并保持 barrier/seal/本地 generation 及原请求条件；不能用恢复后的 Auth 反向授权本次恢复。完全 cold/sealed 场景仍需要显式恢复 owner。导出终结审计与 token clock 可能发布新的根，当前 SnapshotTransferPlan 也没有完整原 native 权源 custody；这些问题未由内部 helper 解决。

历史恢复需要真实已提交的 epoch transition、实际 TLS 多数 fsync 和一次原子根/epoch CAS。当前同 epoch 的检查仍然生效；尚未开放 native HA 历史快照恢复。

具体实现与验收边界见 [Native V6 HA 备份下一门槛](../storage/HEPTABAO_NATIVE_V6_HA_BACKUP_NEXT_GATE.md) 和 [当前闭包修复候选](../storage/HEPTABAO_NATIVE_V6_HA_ARCHIVE_REPAIR_CANDIDATE_20261017.md)。

## 源码及恢复执行顺序

| 版本 | 实际受检源码 / tree | 准确范围 |
| --- | --- | --- |
| R8j | 原 `4f0bacd59be21d204783d69b500d2a19ef6af55a`；tree `9514b66b8cda559938e135d6c7c5b9606296fd4a`；恢复检查点 `675d842e3f086b84512e398368d9ffd38071c636` | Mac 30 项、两种原生构建、Mac/ROG/Pocket4 physical 01/02；物理 QA query 修复另有独立摘要 |
| R8m | `090da802ce1d26c890f7c4100623f05bf488002f`；tree `f8413d46654dde2425260d044f0000ad3a2fda87` | 实际 Mac 3+1；2,588 文件前后完整校验；GitHub 同树检查点 `2193185dc1a89d54513c2d9009fd17a968549d6b` |
| R8n shared-01 | `a6b8990d40bac15b1d9a066dc2303658d73372cb`；tree `9277b345ca1f9c1117b03332958b51b7c25ed772` | 实际 Mac 13 项 checked I/O；GitHub 同树检查点 `70ee76774ecdb5ce24a2620f5813c4c596c3fe78`；其余尚在实现的优化不属于该受检树 |

分支中的 `94640adbb200d97b52ef69a465f262e8976b5fc5` 保留并发的历史 URL query 实测与其他硬件证据，再合入 R8m 五文件；它的 tree 与受检 R8m tree 不同，不能把合并提交整体说成原 R8m 已运行源码。

继续执行：

1. 在新源码目录验证共享密文和本地 barrier 重复写盘优化；普通交付诊断保留原所有检查及调用次序。
2. 对最终冻结候选完成原预算内的完整 HTTP 34 MiB 链、Mac arm64 / Linux x86_64 原生构建，再在全新 owned roots 执行全部 [89 项 native 三机验收](HEPTABAO_NATIVE_V6_PHYSICAL_HA_GATE.md)。
3. 接通正式 KV2 迁移/恢复准入；历史恢复需真实 epoch transition、完整密文多数 fsync、单次 epoch/root CAS 和冷安装资格。
4. 按逐条清单闭合所有真实凭证来源、消费者与备份；完成每台的实际读写、重启和回滚。provider 活性、刷新和真实轮换保持独立资格。
5. 每台资格满足后正式切流；只有全部客户端及备份完成迁移，才按清单删除旧服务、二进制和可再生成资产。

不能以编译通过、合成凭证、归档文件存在、未执行脚本或组件多数票代替以上真实门槛。
