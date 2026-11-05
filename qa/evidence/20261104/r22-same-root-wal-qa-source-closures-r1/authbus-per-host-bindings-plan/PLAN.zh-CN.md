# 逐台真实客户端、生产绑定与备份迁移计划 · R1

状态：SOURCE ONLY。本文整合已经保存的公开原件，未读取任何新主机状态，未提交 inert、current capture、服务操作、生产切换或清理请求。原始失败、UNKNOWN、已发布证据和既有 hold 均保留。

## 1. 立即推进的顺序

先把已完成根审的 Mac current-WAL caller 最小绑定到新 1c665 Mac 正常产物，完成这一个真实五-agent 自有环境验证；随后完成 ROG 六-agent、Pocket4 两-agent 与 X230 实际安装范围的逐台闭合。生产目标集群、服务切换和适用的备份登记各有独立证据，不用旧测试集群填生产字段。

| 主机 | 已有客户端分母 | 最新可用事实 | 下一项具体工作 | 当前不能转移的资格 |
|---|---|---|---|---|
| Mac | main、trnm、hepta-ui、hepta、hepta-backend，共 5 | 当前配置固定 SHA ca2dd7d…；AuthBus enabled=true、generation=200；registry WAL 当前观察为 5,969,912 B | 新 1c665 Mac normal61 实际产物到齐后，按既有最小模板替换产品/ROOT 常量，源审→单次 inert→完整回读→单次 current fixture | 公共 SQLite/native probe PASS 不能代替五-agent current；QA launchd 不能代替生产 KeepAlive |
| ROG | main、azi2、azi3、azi4、azi5、zbj-llm-runtime，共 6 | 最新配置 SHA 6e365990…，AuthBus disabled、generation=203、orderExcludedAgents=[main]；gateway inactive | 从该配置与实际 Linux runtime/registry 源准备六-agent 有限 capture/native/rollback；再绑定新 Linux normal61 | 旧 active/enabled 摘要和 41/42 SDK 结果不能覆盖最新状态，也不能替代当前六个真实 native 消费者 |
| Pocket4 | main、tg8687951891，共 2；“4”是主机名的一部分 | 旧 R10/495033 自有环境初始/冷启/逆向均已真实通过；生产 gateway 与 restart helper 仍 held | 保留原 prepare/preflight 与 10/70/35/440/600 预算，最小绑定新 Linux 1c665 产物、新根和当前原始来源 | 两-agent PASS 不外推为四-agent、全账号、新产品或真实 systemd 生产恢复 |
| X230 | 当前应用客户端分母仍待精确来源确认 | 已知 disabled proxy、运行中的 2.7.1 dev oracle、历史恢复材料；旧报告记标准应用路径缺席 | 先按精确 public receipt 恢复原标准路径 readset，再决定是否需要一次有限当前确认 | Docker 无端口/无挂载不能推出无数据、无消费者或可删除；存储/HTTP QA 不能替代应用客户端 |

证据：[Mac finite38](references/mac_finite_inventory.public.json)、[ROG finite46](references/rog_finite_inventory.public.json)、[X230 finite18](references/x230_finite_inventory.public.json)、[Pocket R10 原始 core](references/pocket_r10_actual_core.public.json)。完整路径、字段位置和 SHA 见 CURRENT-HOSTS.public.json；文件 identity9 和纳秒字段仅引用原始 JSON token，不用 JavaScript 数字重序列化。

## 2. Mac：让新产物一到就能最小接入

### 已完成的源码与公共前置

current-WAL 完整源码包为 ab729106132c035c353979285aa70a302318b3c2，112 件、6,720,222 B、16 个 Merkle tree。根审 4b4c7a065ce953d2ff4b0471d47e87c2c0a4e59b 已闭合入口 9 hunk、outer 14 hunk、inert 12 hunk 和完整绑定。原 df026 两份请求只是保存的源码基线，仍未获执行许可。[根审原件](references/current_wal_root_review.public.json)

公共 WAL 十案例的实际 proof 已由根逐项核完，root review a9ec2253fa07df8853114ab3bcb803a994ec5daa。它绑定实际 Python 3.14.3 / SQLite 3.53.4、source_id、unix-posix/readonly_shm 路径、十独立 reader 的原始结果和闭包；W03 的 CANTOPEN 14、W10 已返回行先计入 1 MiB / 8 MiB 账本也保留。该 proof 只授公共机制资格。[公共实际根审](references/public_wal_root_review.public.json)

### 新 1c665 的最小 binding

目标固定 commit 1c66541993662f92cf717154e33717abedb2ea74，tree 94ced21a63ff9aaca4538c0d4796efea2150e632，正常测试分母 61。需要实际 Mac source / normal / native / combined61 / authority / server file_info 及根资格回执；路径、bytes、SHA 以这些原件为准。当前全部未来值保留 null。

最小变化范围已在 future-product-binding-template.public.json 固定：四个含产品身份的文件（inputs、outer、launchd manager、server wrapper），七个仅 ROOT 变化的文件，以及 candidate、源码 pins、carrier payload、两个请求 key 的级联。新 proposed ROOT 为 /Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-1c665-current-registry-wal-r1；这只是待审命名，尚未观察其 absence，也没有创建。

原五-agent database()/immutable_query()、registry-only WAL 库、公共 proof 原字节、原 current config 与 closed code set、全部业务/cleanup 期限和严格 before/after capsule 比较保持。不能把更换产品常量写成新产品消费者通过。

### 实际运行必须证明的内容

由 T5 UUID、held parent/name/dev 和 current source 的原全身份守卫开始，再在原 sandbox 下运行 current capture。只有带完整 returned-connection / cursor / public-code FD / held FD 闭包的已知结果才可进入 materializer 和 manager。连接先于同 inode held FD 关闭；连接关闭未知不能先把 held FD 关闭后声称完整闭合。

initial 与 cold 使用各自独立状态和 checkpoint；各自 inverse 不共用快照、不覆盖 phase 字典。四 phase × 五 agent 的真实结果分别保存，每个 native worker 仍有独立真实 parent lineage、nonce 和一次性观察器。五个 worker 共享一个 phase120 绝对期限，不给每个 agent 新 120 秒。

选择器按当前配置和 SDK 的实际结果运行。保留 main 的真实 profile3、trnm 的空 primary raw / 继承 effective、原 publishNew/manageOrder/顺序/usage 与六个 cache。inverse 只对真实持久 local/raw 两表做 CAS；全部 raw 恢复后重算并核 effective，最后闭合 cache/native 用户原件。不能把继承来的 effective profiles 写入 trnm 空 raw，也不能硬编码一个绿的 selector。

真实 launchd QA graph 仍要求精确 label 初始 absent、独立 generation/intent、已知 bootout 和进程树清空后才下一次 bootstrap。ready 文件不是 exec 成功；原结果、最终 stdout、真实退出、held T5/FD 和 owned cleanup 必须合取。label/path/args/PID birth 属顺序观察，不能称原子 PID 所有权。

实际失败必须保留原完整 failure envelope：没有 returned library ledger 就不能用 entry 的 FD 字段代替；inverse attempted 未 completed 或任何结果未知立即停链，不重派、不放宽上限。旧 current_input_size_bound UNKNOWN 与 PID11754 UNKNOWN 永久单列。

### Mac 当前真实服务与后续生产差额

实际观测的 ai.openclaw.gateway.plist 为 1420 B / e176c41f…，KeepAlive 与 RunAtLoad 都是 true，程序是 /bin/sh；其他七个参数目前只做摘要，尚未解析成完整 executable/script/config 依赖。实际 service env 为 722 B / 58a4e773…，仅公开 key/摘要。固定路径是：

- /Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist
- /Users/qianqi/.openclaw/service-env/ai.openclaw.gateway.env
- /Users/qianqi/.openclaw/openclaw.json

因此生产 manager 方案需要一次仅这两个服务定义的受控语义投影或等价私有绑定，不能因参数以 / 开头就公开它，也不能 source env 或执行脚本来枚举依赖。现有 QA wrapper 资格不释放生产 gateway 或它的 KeepAlive。

四个旧 relay label（proxy、bridge、egressguard、front）在原有限观测时运行。其现有 public 注册及文件保持；进程存在只证明注册/运行，不能证明全部业务请求经过它们，也不能自动批准 retirement。该项在真实新生产客户端闭合后按每个 exact entry 单独处理。

## 3. ROG：使用最新 disabled 基线，做六个真实消费者

最新 /home/qian-qi/.openclaw/openclaw.json 为 21,229 B / 6e3659907327039243c60a10b2925edb51e83e4c73f0925c60279ae6a8169819。六个配置模型均为 codex/gpt-6.1-sol；enabled=false、generation=203，main 仍在 order exclusion 中。原 finite46 因旧配置 SHA 不符而 exit1 的记录保留，不能把有用的新观察改写成原任务 PASS。

第一项源码工作是按实际 Linux installed runtime / registry / native lineage 明确六-agent 捕获与消费闭包。Mac 的 Darwin projection、5-agent/native 源以及 registry-only WAL 公共资格不能直接变成这台的 runtime 资格。确需新观察时，只从已知 config/code 引用生成封闭名单；各 main、WAL、SHM、journal 和每次父目录 lstat 都单独计数，不能漏 sidecar 后声称分母完整。

若在自有 fixture 中验证 AuthBus 功能需要 enabled=true，这必须是明确的 fixture-only 变更并源审；生产 enabled=false 不被更改。保持其他实际 flags、model、generation、order exclusion 和真实 selector；不能将禁用状态下的无操作当消费通过。

当前 gateway 是 enabled/inactive/dead、MainPID0。两项 accept-after-restart / restart-when-idle helper 是 static/inactive、ConditionResult=no、MainPID0，原 hold marker/drop-in 必须保持。旧 f458 中 gateway active/PID2436 只是更早历史。当前 unit 的 TimeoutStopUSec=6min、helper=1min30s 是服务配置，不自动成为新测试 wrapper 的预算。

完成六-agent 新产品初始/冷启/严格 inverse 后，再准备真实 systemd 生产迁移；exact unit、drop-in、两 helper 程序、marker 身份和服务前后状态必须进入一个具体受审动作。不能先删除 hold 来证明能启动。

## 4. Pocket4：复用已证两-agent 路径，不转移旧产品资格

原 R10/495033 core 真实通过 66 checks；initial/cold 各 128 records，两个 inverse 各 95 records。四个 phase 名唯一，但记录 label 并不都唯一，重复的 source.package.json 等由实际路径绑定，不能将 label 唯一性作为新的分母断言。

两 agent 为 main 与 tg8687951891。旧真实验证包括两个 managed 代际、实际 local5 选择、四次 native factory / 八次本地 RPC、tg 原 raw 零 profiles 的继承、独立 native4 原件和六 cache 保持，以及一次 renew、revoke、撤销后 403 和未分配 profile 403。它没有运行真实生产 systemd，没有模型/provider 请求，也没有全账号资格。[原始 core](references/pocket_r10_actual_core.public.json)

下一候选只最小替换新 Linux 1c665 server/source/normal receipts 和 fresh roots，保留原 prepare/preflight/current source guards、HTTP10 / consumer70 / rollback35 / controller440 / outer600。当前 registry 若与原 111,644,672 B main-only 观测不同，按原 guard 拒绝；不能自动延长原 whole-copy cap，也不能用它绕过 Mac 2.47GB 来源的 bounded-query 合同。

两个 exact held unit 是 openclaw-gateway.service 与 openclaw-authbus-restart-when-idle.service；drop-in 和 marker 的完整路径/SHA 在 CURRENT-HOSTS.public.json 及 f458 /host_rows/2/hold。只有后续已审 source-bound readiness transition 可以释放，不由本计划或旧 R10 pass 授权。

## 5. X230：先闭合实际角色，不制造客户端

最新有限观察证明 proxy disabled/inactive、三个旧 transient failed/MainPID0、oracle 容器 running/network=none/mounts=[]。这些证据不说明容器 writable layer 空、内容可丢弃、所有调用不存在，也不把 disabled proxy 当已迁移。

已恢复一个可以直接交审的下一项公开来源：

- host：x230
- path：/home/qian/heptabao-cutover-cleanup-inventory-20261104-r1/runtime-and-config-r1.public.json
- expected SHA256：df94b577ce539fa23316d686c287b8aaeb8f6f3ee2561a5d1875368c8420dbff
- 操作：仅此文件 file_info 后固定 version 的完整读取，≤2 MiB；原始字节/SDK 保留，whole SHA 不符就停止。

该路径/hash 直接来自 aa23 /hosts/3/runtime_receipt。先从报告实际字段恢复“标准应用路径缺席”的原检查名单；如果名单未含在报告中，继续只沿它的已证 public source 引用，不猜 /home 下路径、不递归扫目录。具体合同见 FINITE-NEXT-READS.public.json，本计划没有提交请求。

如果实际有限确认仍无已安装 OpenClaw 消费者，按该登记范围记录“不适用”；不要为了产生 PASS 安装一个新客户端。已有 disabled proxy、dev oracle、历史 restore 各按自身角色保留和核实。只有真实新增 active command/config/restore entry 才扩展对应范围。

## 6. 新生产 HA 目标必须形成的绑定

目前没有已核的新生产 cluster identity、地址、RoleID 或 SecretID 来源。既有 Mac/ROG/Pocket 配置指向 https://100.66.117.33:8200，仅作为旧状态记录；本线不访问它。LAN fixture 的 Mac1/ROG2/Pocket3 地址、证书和成员也不能填到生产表。

| 绑定 | 必须有的实际证据 | 缺失时的具体动作 |
|---|---|---|
| 产品与集群 | 新 binary 全件 SHA/来源，实际 endpoint、namespace、cluster ID、member set、实际冷启后的同一持久身份 | 由负责部署的已审流程给原始 public 回执；各 consumer source 只接受该精确元组 |
| TLS | CA 公钥 SHA、每节点 leaf 公钥证书 SHA、SAN/SNI、有效期和实际握手；私钥不进 public 包 | 先冻结来源和 server-name 规则，再对实际目标验证；不借旧 J3160 或 QA CA 代替 |
| 每主机 AppRole/SecretID | 角色名、RoleID hash、SecretID 私有路径/hash、实际发行或受证恢复回执、目标 cluster/namespace、用途/TTL 元数据 | 在实际目标按该主机最小 policy 发行或验证；值只保留私有 0600 来源 |
| ACL policy | exact installed source 的 route×operation×host/path 清单、完整 policy hash 与服务端 readback、正/负例 | 从原 flags/publishNew 等真实行为推导，不给无界 wildcard；inbox proposal 不冒充 canonical publication grant |
| 生命周期 | 一次实际 AppRole 登录与 issued token；真实 renew、revoke、撤销后拒绝、未分配 profile 拒绝 | 用实际 token 的已知响应和 public 摘要，不造成功；未知停止，不重发业务 |
| 服务与持久化 | 原精确 config/unit/drop-ins/holds；实际新进程 birth/executable/args；冷启后当前凭证效果与同一目标 | 每台一个受审动作；生产 KeepAlive/systemd 与 QA manager 分开 |
| 回滚 | 原始前态、预期后态、独立 checkpoint、一次 inverse marker、实际 restored readback 和 closure | 只在 expected-after 全匹配时逆向；partial/unknown 不重试 |
| 活动备份 | 实际 producer/restore 注册、payload/版本、来源 cluster、加密目的地、key custody、独立恢复验证 | 有已观察活动入口才绑定；新部署引入的备份流程必须显式登记 |

PRODUCTION-BINDING.template.public.json 中生产值全部保留 null / ready=false；原旧路径/hash 放在 prior references，绝不冒充新的签发来源。上述缺口不阻挡完成已限定的自有 current qualification，但必须在真实生产迁移前有对应实际证据。

## 7. 每次动作的原子可审证据与并发边界

一个动作对应一个 immutable intent、一个稳定 key、一个原绝对期限和一组 exact predecessors。公开包包含 controller/product/host pins、原 before identity/hash、expected-after、实际请求响应或 manager 状态、权威退出、完整流和全部资源闭包。它是可独立复核的动作单位，不等于跨文件系统或跨服务的原子事务。

生产切换前先持久化全部新的私有 credential generation，再在明确独占写者/服务控制合同下比较旧 config 并发布只变 address/caFile/roleIdFile/secretIdFile 的完整新文件。单文件 atomic rename 不等于对不合作外部 writer 的 compare-and-swap，也不等于多个凭证文件同时切换；无法建立该写者边界就拒绝执行，不能靠前后 stat 相同宣称原子性。

顺序为每台：已证 current fixture → 明确目标 tuple/policy/credential generation → exact predecessor 与服务 custody → 单次配置/manager transition → 实际消费和冷启 → 严格 inverse 演练/确认 → 独立实际接受。Mac、ROG、Pocket4、X230 分别给结果；不能从一台推另一台。

一旦动作已发而结果未明，保留 UNKNOWN，停止后续。仅允许对同一个原 job/operation 做已授权读取，不通过换 key、加 retry、续 budget 或额外杀进程把历史未知改成已知。任何旧资产删除或 hold 解除另需具体已审变更。

## 8. 备份：有限登记与一条历史恢复链

f458 明确将当前客户端配置、已安装启动注册、owner/system cron 的有限名单作为 planning inventory；未注册的假想 manual 路径不是额外 gate。只有实际新观察到活动 command/config/restore entry 引用 Bao/AuthBus 时，才重开那一个范围。[有限登记原件](references/finite_registration.public.json)

四台所选登记中均未确认活动的 Bao/AuthBus 备份 producer 或 scheduled restore。历史目录、旧 query bundle、OS font/audio/dpkg 条目、Apple SecureBackupDaemon 等不能仅凭名称存在被改成当前迁移依赖。现有旧材料保持；有限未观察到活动注册也不写成整机绝对不存在。

X230 的九张回执属于同一条链：2026-11-02 capture，2026-11-03 transport/restore，23 files / 7 nonempty databases / 6 auth stores，原 restore300s。其逻辑 source“main”与 Linux UID1000 /home/qian-qi 的历史上下文，不能套用为当前 Mac 的捕获。根已读完整九原件并核字节，本文保存 aa23 中精确九路径/摘要与该根确认来源，不重新访问 payload/key。

历史 securityStateCoherenceQualified=true 与 rawSecurityMetadataCohortStable=false、非跨-agent 原子快照同时保留；既有合格是 exact declared captured recovery，不是当前凭证有效、当前 SDK 消费或新产品生产备份合格。不要把九张回执拆成九个独立恢复范围，也不要为了 current capture 复用这条历史 whole-DB copy。

当新 HA 部署确实引入一个备份 producer 时，记录其明确注册、源 product/cluster、精确 payload 与 capture 时间、encrypted destination、private recovery-key custody、原预算内的 offhost restore 与新产品读取/客户端验证，及 endpoint/credential/startup 的必要重绑与逆向。没有新增入口时，不凭空造一个任务或任意地址。

## 9. 固定预算与准入边界

| 路径 | 保持的预算/上限 |
|---|---|
| Mac current | controller900 / supervisor1080；manager600 / cleanup60；共享 phase120；capture45；registry query3 包括结果、ROLLBACK/close、ledger 和同一完成时刻复核 |
| 当前凭证读取 | registry WAL≤5,969,912 B；row≤1 MiB；aggregate≤8 MiB；旧五-agent 零-WAL路线不变 |
| Mac native | 原 15 / 8 / 3 子步，夹紧同一 phase deadline；原 WNOWAIT 与信号前双身份保持 |
| Pocket 原路径 | HTTP10 / consumer70 / rollback35 / controller440 / outer600 |
| 复用 finite collector 时 | 单 host45、query10、每 pass≤32 个明确对象、总8 MiB、单读取64 KiB；不能按 pass 重置 |
| 新 public report 可选读取 | 一条固定路径≤2 MiB；若另建 controller，45/60 明示为新限额，不称原报告预算 |

同步 C/syscall 不一定能在内部硬抢占；晚返回必须在原绝对期限拒绝成功，不能继续业务或发布成功结果。只读 SHM 不等于零 O_RDWR 尝试，immutable 也不把活跃 DB 变成一致快照。源码和公共 synthetic 的范围都保留。

## 10. 文件索引与本包状态

- CURRENT-HOSTS.public.json：每台精确已观察配置、文件 pins、服务状态、raw pointer 和差额；不重序列化 unsafe integer identity。
- PRODUCTION-BINDING.template.public.json：生产值待填模板，ready=false，包含 per-host credential/policy/manager/backup 单位。
- ACTION-UNITS.public.json：M01–M03、R01–R02、P01、X01 和后续生产/备份动作的具体输入与通过条件。
- FINITE-NEXT-READS.public.json：只从已有来源导出的下一项有限观察合同，没有提交任何请求。
- BACKUP-BINDINGS.public.json：finite scope 与一条九回执历史链的分母/日期/来源限制。
- future-product-binding-template.public.json：已审 current 源的 1c665 最小绑定字段；实际产物仍待填。
- references/：十份原始公开字节及相应全 SHA/Git blob；旧错误/状态未改写。

本包不声称 full replacement、production cutover、all accounts、provider availability 或 cleanup 已完成。它给下一受控动作的精确来源和所缺 binding，并保留所有既有范围。
