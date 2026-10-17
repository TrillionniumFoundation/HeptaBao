# HeptaBao 下一阶段执行记录（2026-10-17）

## 当前结论

已取得三台物理机的 V5 HA 回归、独立 Google 凭证来源和多台实际 OpenClaw 客户端验收；native V6 的存储、共识、TLS 复制、Service 安装及授权接线已经进入实际集成回归。

**五项生产门槛尚未全部关闭。生产流量尚未切换，旧 OpenBao 尚未删除。** 本文中的每个结果保留自己的源码、二进制和测试范围，不把不同版本、组件或客户端的通过数相加为生产资格。

远程执行通道在 Mac R8g 任务启动后断连。原任务 `1a14a0b3e5d-1b6abb-13e` 已有持久化启动记录，当前结果未取回；恢复连接后必须先核对该任务，不能用重复运行替代未知结果的核对。

## 五项门槛

| 门槛 | 已完成且有证据的工作 | 尚需完成 |
| --- | --- | --- |
| KV2 正式存储 | 有界 locator 迁移、原子根/cursor 发布、迁移中断恢复、实际归档冷恢复；34 MiB 保留历史的 typed graph 与跨 barrier 重封装；native HA Service 接线通过编译 | 完整 Service 发布链路的运行回归、同源三机 native HA 运行，以及 HA 归档与恢复资格 |
| Mac / ROG / Pocket4 HA | V5 真实三 voter 的 62 项全部通过；native 共享闭包的真实 TLS 多数 fsync、缺块新主拉取和原截止组件回归通过 | 新的 89 项 native V6 三机测试、同一源码的两种原生 ABI 构建及每台回归 |
| 独立 AuthBus | 主机自身拥有的 Google API key 经官方端点验证；原插件与实际 SDK 的凭证读取、TLS、AppRole、Policy、续期、重启、备份、回滚和撤销实测 | Pocket4 修正配置后的完整重试、实际中央发布器闭环、全部原凭证与刷新归属的核对 |
| 逐台切换 | main、Mac、ROG 的隔离真实凭证链路分别完成 141 项；Pocket4 R1 保留原始失败结果 | 所有客户端和备份路径形成闭合清单；候选端点、实际凭证、重启和回滚全部合格后逐台切流 |
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

控制器：[authbus_pocket4_credential_canary_r2.py](../../qa/openbao-acceptance/authbus_pocket4_credential_canary_r2.py)。R2 尚未启动；恢复远程连接后使用新的 `r2` 目录执行。

## 中央 AuthBus 与凭证来源

原插件没有 inbox LIST、不可变 profile 写入或 manifest CAS 发布器。`leader=true` 的业务分支筛选并刷新 OAuth，然后把 `leader-refresh` 事件写入自己的 inbox。因此原插件 leader 测试不能代表中央发布器接替。

独立中央候选需要原生产者 → 按 host 核验的 inbox → 不可变 profile → manifest CAS → 原消费者的完整闭环。每次凭证替换绑定明确的当前/下一凭证摘要和来源身份；私有 fsync journal 保存未决操作，未知 manifest 回复只能由准确的当前版本或对应 KV2 历史证明，不能盲目重发。

现有 Google key 的来源完全独立于 J3160。它证明该 key 的所属来源和实际可用性，不代表旧 OAuth profile 已迁移或具备刷新资格。SDK 来源工具只通过原 SDK 的只读 persisted-owner API 读取明确列出的库，导出前后复核；private candidate 保留在来源主机。

另一个独立的 SDK enforced-deny 实验发现：SQLite 拒绝撤销写入后，当前和冷 resolver 仍可选择旧 grant。该实验整体验证失败，证据已保留。现有客户端使用 shadow、enforce=false；不把该实验的局部通过写成 enforced 模式已经合格。

## Native HA 备份仍是门槛

本地 `HBV6PK01` 使用节点 barrier；Raft 选择的共享 ciphertext closure 使用 replication key 和原始随机 nonce。相同明文重新加密不能生成旧共享叶引用。因此本地对象包及其摘要不能代替原共享闭包备份。

完整 HA 归档需要同时绑定两个对象包、实际根、完整 intent/publication LogId、enrollment、epoch 和本地 seal。只修复实际当前根的缺块，与在线恢复历史状态、无原 quorum 的灾备恢复是不同模式。

历史恢复需要真实已提交的 epoch transition、实际 TLS 多数 fsync 和一次原子根/epoch CAS。当前同 epoch 的检查仍然生效；尚未开放 native HA 历史快照恢复。

具体实现与验收边界见 [Native V6 HA 备份下一门槛](../storage/HEPTABAO_NATIVE_V6_HA_BACKUP_NEXT_GATE.md)。

## 源码及恢复执行顺序

编译通过的 R8h 本地 commit 为 `b941bf3e4af6d15776328c4d3703251234265e03`，tree 为 `98bdbb8992f036dd5e6c25b0ced9c13f2378f4ff`。GitHub 检查点 commit 为 `849b74f337f149458658f050aa1bcd83f7055de9`，其 tree 与本地受检树完全相同；提交元数据不同，不将两个 commit SHA 混称。

远程连接恢复后按以下顺序继续：

1. 核对原 Mac job `1a14a0b3e5d-1b6abb-13e`、其最终日志和源码完整性，保存失败或通过结果。
2. 使用冻结的新源码构建 Linux x86_64 与 Mac arm64 独立原生二进制，核对构建回执和源码摘要。
3. 在全新 owned roots 运行 [89 项 native 三机验收](HEPTABAO_NATIVE_V6_PHYSICAL_HA_GATE.md)，保留真实失败和不确定结果。
4. 运行 Pocket4 R2；执行只读客户端/备份清单及原 SDK 归属检查，再验证独立中央生产者/发布器/消费者链路。
5. 完成实际使用的全部凭证、客户端与备份路径的迁移、重启和回滚，才逐台正式切流。
6. 核对所有迁移与恢复证据后，按清单删除旧 OpenBao 服务、二进制和可再生成中间资产。

不能以编译通过、合成凭证、归档文件存在、未执行脚本或组件多数票代替以上真实门槛。
