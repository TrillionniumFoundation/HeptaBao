# Mac、ROG、Pocket4 逐台凭证迁移：本地源码核查 R1

本报告把下一步收敛为每台一个真实 SDK owner 和一个已知 SecretRef 消费入口，随后扩展到该台其余实际消费者与备份。现有 main canary 的真实服务交互、CAS 恢复、冷启和新 SDK 库恢复逻辑可以复用；它的主机、源凭证、SDK 版本及 fixture 回滚范围不能直接代表其他三台生产客户端。Pocket4 还存在已经观测到的插件源码差异。

本次仅读取已缓存源码和公开元数据，未访问远程、未读取凭证值、未改变客户端或旧服务。机器身份、SDK 版本、文件状态均须在实际执行时重新绑定；旧元数据中的 `host_label` 明确是调用方声明值。用户已经授权逐台真实读写、重启、回滚和切换，本报告不增加一次审批步骤。

## 1. 本次依据及其时间边界

完整来源身份、已知路径和未资格化状态保存在同目录 `per-host-migration-facts-r1.json`。这份派生清单只摘取旧公开字段，没有新增凭证内容。

| 来源 | 字节数 | SHA256 / Git blob |
|---|---:|---|
| `qa/openbao-acceptance/native_v6_authbus_owned_source_live.py` | 64050 | SHA `fb44eab74e56b5d098a8fe0656ff764332fcccca9fe6ab0c7bcc4f2dfe21c121`；blob `2f43f0c1fa57f7279c3b538993d8b91c20d095a7` |
| `qa/openbao-acceptance/authbus_sdk_owned_source.mjs` | 21459 | SHA `703cb463ce43488ff29f8a8394fab4bd591c69bc2a06c1c5ddc64d0abc1e14de`；blob `6b08ac1a22bcb4189381c7727e512b0ceaf3af1d` |
| `qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs` | 30284 | SHA `dc3120ba49f6088197dd4175054dd3c1d908efc79916599e9cee7ac85a46c4af`；blob `da5d8006b41986a94d66c67876a7a08cae9cc7e4` |
| Mac v3 公开元数据 | 194135 | `7e203aa01ac3c73af5419a6cb24327869e64b21496e14ec1cd185ca8b4efc868` |
| ROG v3 公开元数据 | 60402 | `f6e126f936ffb4f5560a5acb60f826d1c2b88bd72298476a5b7a87d77383f3ea` |
| Pocket4 v3 公开元数据 | 102812 | `d0085245623fff5ab94b131dc161e9c9f7357546b8fea954fcc36509a276acd4` |
| main v3 公开元数据 | 119093 | `3e5d8e12636487c08261a826f1dd03c29a5166765352fccdbbe33c640c35c0e9` |

v3 配置投影是 2026-10-18 02:29 UTC 的实际只读观察，SDK 库与插件条目则明确复用了 2026-10-17 14:19 UTC 的元数据，`freshly_scanned=false`。不能据此声称 10 月 19 日的源凭证、运行版本或 owner 仍相同。

main 原 canary 外层回执的实际字段为 `observed_checks=293`、`passed_checks=293`、`exit_code=0`，同时 `ok=false`；`timed_out=false`、`mutation_outcome_unknown=false`、`source_unchanged_after=true`。本地尚无它引用的 78725 B 内层回执（SHA `20740bac22ae330a02e573bfe504feec4c5bce8699997eeb3c73377d31d35370`），故保留这一矛盾，不能根据计数改写总通过标志。原二进制属于 `4f0bacd59be21d204783d69b500d2a19ef6af55a` / tree `9514b66b8cda559938e135d6c7c5b9606296fd4a`，也不能移作新候选 `9770bdd4ca77aa832ec8083a054760637e92cfa1` 的实际执行证据。

## 2. 逐机首个完整候选

三台旧配置的 AuthBus 都启用并指向 `https://100.66.117.33:8200`，公开投影明确 `references_j3160=true`。三台的 `main` 配置均未显式声明 agentDir，因此下表路径是已发现的实际 SQLite 候选；还须由各机真实 SDK 的 default-agent / persisted-owner API 确认。

| 主机 / 本地用户 | 首个 SecretRef 候选 | 首个 SDK owner 候选 | 原库大小 |
|---|---|---|---:|
| Mac / `/Users/qianqi`，旧 UID 501 | `.openclaw/credentials/secretrefs/gateway-auth-token.secret` → `/gateway/auth/token` | `.openclaw/agents/main/agent/openclaw-agent.sqlite` | 2469126144 B |
| ROG / `/home/qian-qi`，旧 UID 1000 | 同样的 home 相对 SecretRef 路径 → `/gateway/auth/token` | 同样的 home 相对 main SQLite 路径 | 2573303808 B |
| Pocket4 / `/home/alex`，旧 UID 1000 | 同样的 home 相对 SecretRef 路径 → `/gateway/auth/token` | 同样的 home 相对 main SQLite 路径 | 399716352 B |

三份 gateway 源文件在旧元数据中都是 49 B、0600、普通文件、归对应 owner 所有，尚未读取或资格化。它们是首个候选，因为三机都已有明确消费位置；此处不推测文件内值或 SDK selector。

各机旧配置 SHA：Mac `ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d`；ROG `b9418023037c96a99b3cee9d4a9b570b83f53ea476caf2e6de71837e30155649`；Pocket4 `3611380b8c77282e785e00e20d9eba8bc8cf0164b3b3f00e2ea5d1f52a441c98`。这些是新读取的比较起点，不是可以跳过变化核查的永久常量。

### Pocket4 必须单独绑定源码

Mac、ROG 的旧七文件指纹与 main canary 契约一致。Pocket4 的五个辅助文件相同，以下两份不同：

| 文件 | main / Mac / ROG 旧 SHA | Pocket4 旧 SHA |
|---|---|---|
| `index.js` | `b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b`，54455 B | `8e10c52df53d6d16d0e5890a6ccdaaff9515469e4419b46270b9bdc62b9be7af`，54578 B |
| `order-policy.js` | `16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301`，7376 B | `a1a9923368a1a6bd9adf691aa1beba02d443cf511232e17118c9868160a96e82`，8506 B |

下一步在 Pocket4 读取这两份实际源码并与各自旧 SHA 比较，核查变更含义，再以该机原样插件运行新 owner fixture；不能为了匹配 main 已过用例而悄悄换成 main 插件。

## 3. 可以直接复用的代码边界

| 原入口 | 可以复用的行为 | 必须保持的限制 |
|---|---|---|
| inspector `collectOwnedProfiles`、`selectOwnedProfiles` | 清 SDK runtime snapshot，实际调用 `loadAuthProfileStoreWithoutExternalProfiles`、`resolvePersistedAuthProfileOwnerAgentDir`、`findPersistedAuthProfileCredential`，对有效值和持久化 owner 做摘要比较 | 显式 owner 目录集合；不导入外部 CLI；不把遗留 JSON 当 SQLite owner；导出选择和源重读必须一致 |
| inspector `execute` 的 inspect/export | 配置已经支持显式 hostId、stateDir、agentDirs；只读生产 SQLite，导出到新的本地主机私有目录，落盘前后重读实际 owner | SDK 版本固定 `2026.7.1-2` 且五份模块 SHA 固定；不同版本需新契约和原样 API 审查，不能删检查；该 inspector 不解析 SecretRef |
| Python `read_owned`、`owned_directory`、`source_recheck` | 精确文件和 owner 约束、无符号链接、限定字节、同 FD 前后身份比较，发布前重新读 source / config / SDK | 保持 source-only 读取和私有导出；公开回执只含摘要；原 `remaining(deadline)` 不续预算 |
| Python `run_worker`、`pending_may_have_dispatched` | 唯一 CAS，真实冲突拒绝，已提交却丢应答后的 pending reconciliation，已知 dispatch 或未知结果禁止重放 | 原 operation、预期前版本、源摘要及收据不可换；不能用一次新 mutation 当恢复 |
| Python `client` / `restart` | 原插件、实际 AppRole、证书验证和完整 TLS、实际 SDK producer/follower 写读，SIGKILL 原样二进制后重新 unseal 与 native format 观察 | 新 fixture 凭证和新 owner；真实源没有 OAuth refresh；刷新租约和 provider 最终发送由各自真实流程单独证明 |
| canary 备份和 binding rollback 段 | 子进程关闭后备份新 follower DB/WAL；恢复到另一个新 owner 后实际 SDK 读；错误 CA 拒绝后恢复同一份 binding 字节再实际读 | 原 32 MiB 文件上限只覆盖新 fixture 库；不能声称已经备份 0.4–2.6 GB 生产库或完成生产配置回滚 |
| revoke / destroy / restart 段 | 实际 token read→revoke→403，销毁 SecretID accessor→login 拒绝，服务再次冷启后仍拒绝 | 注销的都是该次拥有的新凭证；不要把旧 J3160 未知状态当作已撤销 |

另有两个不可通过替换主机名解决的绑定：Python `validate_observation` 与 Node `validateOwnedCandidate` 固定为 main 的一个 `openai/oauth` 直接持久化 profile，明确 `hasSecretReference=false`；Node 的 `originalDeadline` 明确声明 Python monotonic 与 Node hrtime 共域是 Linux-only fixture 假设。Mac 适配要实测时钟域并保留同一个父操作终点；不能简单从子进程重新开始 360 秒。

## 4. 最小完整执行顺序

1. **在实际 host owner 下确定源和调用者。** 新读该机身份、配置、实际 Node/SDK 根及五文件契约、插件七文件、入口服务配置。对默认 main owner 调 inspector 的实际只读 SDK API，选出一个有明确持久化 owner 的 profile；将源选择、配置、SDK、插件与本次 host 身份绑定。ROG 与 main 恰好拥有相同 home 字符串和 UID，不能因此认作同一 owner。未发现该类型 profile 时报告实际类型，建立准确 adapter，不伪造 main 的 profile 选择。
2. **单独确定 SecretRef 消费链。** 从各机实际 SDK 的 file-provider 解析器与 gateway 调用入口取得 selector、类型和字节处理规则，在该机内部实际解析 gateway 值，并只在公开收据保存类型、长度及摘要。现有 inspector 明确不做这件事。若目标是由 HeptaBao 供给此 SecretRef，就必须通过实际 SDK provider 入口读回该目标值再验证消费者；只把文件副本写进 KV 不构成消费链迁移。如果该 file-provider 本来完全不依赖 OpenBao，应以实际调用者证明这一边界，而不是默认为它已迁移或必需改造。
3. **新建同机隔离 native / TLS / AppRole fixture，实际完成唯一读写。** 复用 main 流程的最小权限角色、原样插件、新 SDK owner、源发布前重读、唯一 CAS、丢应答 reconciliation 和 TLS 验证。SecretRef 使用它实际对应的 provider adapter；OAuth profile 使用实际 persisted-owner adapter。原生产源保持可对比且值只留 owner 主机。此阶段取得的是该机真实凭证在新 HeptaBao 及实际 SDK 中的证据，尚未标记生产流量切换。
4. **完成冷启、恢复和有效回滚。** 在新服务真正死亡、进程身份已核明后重开，实际检查同一源值 / KV 版本 / persisted-owner 摘要、token 与 SecretID 撤销状态。新 owner 的备份必须经过实际 SDK 恢复读取。接着为生产 owner 建立独立的一致备份：查明并协调实际 DB owner，关闭写者后流式复制该次真实 DB 及仍需的 WAL，或使用经当前 SDK/SQLite 契约确认的一致备份入口；保持同一快照的源身份和副本摘要。不能边复制活跃 DB 边声称 cold backup，也不能将旧 canary 的 32 MiB 上限抬高后整库读入内存。预算单独记录，既有 canary 的 360 秒不变。恢复副本到新隔离 owner 后须实际 SDK 读出同一选择，并保留非凭证库内容的完整性证据。
5. **按主机实施已经授权的生产切换。** 在前四步的该机证据齐备后，保存准确旧配置、binding 和可恢复 owner，完成实际消费者使用新 endpoint/CA/host AppRole 的读写；进行真实消费者重启，确认从同一目标恢复。执行一次记录在案的生产绑定回滚和消费者重启，读回原本已证明可用的本地 owner / SecretRef，再重新应用已验证的新绑定完成切换。当前旧配置仍指向 J3160，因此“把 endpoint 改回 J3160”本身不是可用回滚；必须先证明备用本地 owner/解析路径能服务该消费者。网络写入结果不明时只查状态，不重新发同一切换写入。
6. **扩到该台所有实际消费入口和备份，再清理旧版。** 先完成下节明确剩余范围，逐项保存新 source / consumer / restart / rollback 证据。旧服务、二进制和可再生文件只有在其消费者与恢复路径都已被具体替代时才进入删除动作。已知失败日志、原 source hash、不可再生凭证和唯一恢复材料不作为可再生中间资产删除。删除前依据实际引用和服务状态，不依据文件名或旧 metadata 的 `exists=true` 推断。

## 5. 单个候选通过后仍剩下的具体范围

| 主机 | 旧 SecretRef 数 / 有主配置消费位置的数量 | SDK scope 候选数 | 已列出备份/运行根数 |
|---|---:|---:|---:|
| Mac | 9 / 5 | 5 | 10 |
| ROG | 2 / 2 | 6 | 3 |
| Pocket4 | 8 / 2 | 2 | 8 |

Mac 除 gateway 外还发现 ollama、Google web search、Discord、Feishu 的配置消费位置；qwen-portal 及三个 google-authprofile SecretRef 未在这次主配置投影中找到消费者。ROG 的另一个明确入口是 `zbj-taskflow-webhook` → `/plugins/entries/webhooks/config/routes/zbjAutoIntake/secret`。Pocket4 除 gateway 外有 Google web search；memory search、两个 tg8687951891 model key、该 scope 的 authprofile key 及两个 env key 的实际消费入口仍需其真实 SDK/子作用域读取。没有主配置指针不等于未使用，更不等于可以删除。

Mac 的五个 SDK scope 为 main、hepta-backend、hepta-ui、hepta、trnm；ROG 为 main、azi2–azi5、zbj-llm-runtime；Pocket4 为 main、tg8687951891。ROG/Pocket4 的部分 scope 同时有旧 auth-profiles.json 与 SQLite，下一步要采用 SDK 解析的实际 owner，不能选择更容易读取的旧 JSON 作为事实来源。

Mac 还单独存在 `ai.openclaw.authbus-relay.{bridge,egressguard,front,proxy}.plist` 四个启动配置和八个 relay 依赖：两份 auth 文件、四个 bin、`cliproxy.runtime.yaml`、`state/bridge.json`。该 relay 不能由一次 gateway-token canary 代表。ROG 旧回执另外列出 accept-after-restart 和 restart-when-idle 用户服务；Pocket4 列出 restart-when-idle 服务；Mac 列出对应 macOS 脚本。这些只是已知启动代码候选，不是实际完成重启的回执。

三台的备份/运行根共 21 处；加 main 的 17 处，四台共 38 处，包含 33 个 backup reference、4 个 AuthBus runtime 根和 1 个 Mac relay 根。目录子项扫描有显式范围和数量限制，这不是完整递归备份清单。所有 v3 backup-consistency / restore / migration / cutover 资格字段仍为 false。X230、其他未检查主机与 private CI 在该元数据中是独立未检查边界，不能借此次三台报告推成“没有客户端”。

## 6. 最先应执行的源码读取

根线程可先并行读取三机实际 SDK 安装位置、package version、上文五文件、main 默认 owner 只读 SDK 结果；同时取得 Pocket4 两份差异插件实际源码。若 SDK 契约相同，现有 inspector 可通过新配置直接承担 inspect/export，无需弱化旧代码。随后读取实际 gateway SecretRef file-provider 的实现及调用入口，建立有真实 source/target 消费证明的新小 adapter。该准备不会依赖 J3160，也不会要求先改生产认证状态。

本报告没有执行新 SDK inspection、SecretRef 解析、生产库备份、重启或切流。它提供实际候选和现有源码可以复用的准确范围；所有后续通过项由根线程实际执行回执决定。
