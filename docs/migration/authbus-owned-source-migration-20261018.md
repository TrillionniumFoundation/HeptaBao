# AuthBus owner 来源与迁移阻塞清单 — 2026-10-18

四机实际扫描均取得 `metadata_received`，公有原件完整字节/hash 与 controller 对齐；四个当前配置均匹配原 SHA，扫描末 metadata 一致。**本清单仍为 metadata-only，迁移、恢复、生产切流及旧版清理资格全部 false。** 来源：[controller 公有回执](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-controller-public-receipt.json)。

四机当前 AuthBus 静态端点仍为 `https://100.66.117.33:8200`（J3160）。以下目标统一为 HeptaBao；实际 endpoint、KV mount/key、目标文件路径尚未由这些回执证实，JSON 中保留 null，待对应 owner 确认。所有动作均 pending。

## 实际观察与阻塞

| 主机 / 原件 | SecretRef | backup/runtime | bindings | fresh 缺失 agent 检查 | reused client scope | bounds / 错误 |
|---|---:|---:|---:|---:|---:|---|
| [main](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-main.public.json) | 0 | 17 | 3 | 2 | 8 | 无 bounds hit；FileNotFoundError=12 |
| [macbook-pro](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-macbook-pro.public.json) | 9 | 10 | 3 | 0 | 5 | maximum_depth, per_directory_entries |
| [rog](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-rog.public.json) | 2 | 3 | 3 | 0 | 6 | 无 bounds hit |
| [pocket4](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-pocket4.public.json) | 8 | 8 | 3 | 0 | 2 | 无 bounds hit |

19 个 SecretRef 文件均存在、owner 匹配、mode 0600 且配置仍指向原路径；载荷未打开、凭证来源/真实消费者尚未取得资格。9 条有批准配置投影中的 consumer pointer；Mac 4 条、Pocket4 6 条共 10 条没有该 pointer，**不能因此判为未使用或可删除**。12 个 AuthBus binding 文件均存在但内容未读；Pocket4 的 CA mode 为 0644，其余 binding 为 0600。证据及逐路径观测见下表对应原件和 JSON pointer。

main 两个配置各明确出现一次，仍指向原缺失路径；两个目录和各自五个原列文件，共 12 次 `FileNotFoundError`：

- `trillionnium-os-agent`：`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent`；后续 M1。
- `hepta-luna-teacher`：`/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent`；后续 M1。

Mac `/Users/qianqi/.openclaw/authbus-relay` 观察 97 个子条目；`/Users/qianqi/.openclaw/authbus-relay/maintenance` 命中每目录条目上限，另有 68 个已记录目录因 depth 2 未递归，`auth` 子树仅 metadata。没有完整枚举或恢复资格；逐个截断/跳过路径保存在 JSON，后续 B3。

**旧观察单独保留：** 21 个 client scope 与其 client-store metadata 来自 2026-10-17 原回执，全部 `freshly_scanned=false`，原 observed_at 未改写；本次 fresh 存储路径检查仅限 main 上述两个缺失 scope。原入口 metadata 也保持 reused。

## 待完成动作

| 动作 | owner 必须完成的结果 |
|---|---|
| S1 | 确认该精确文件的可信来源，经 owner 受控流程将凭证导入已确认的 HeptaBao KV；确认实际 mount/key、最小 Policy 及版本/回滚方式。目标值未从文件名推测。 |
| S2 | 将本条消费者与目标 SecretRef 绑定，取得真实凭证读写和真实消费者 canary，再验证 owner 进程重启与回滚；全部通过后才逐台切流。 |
| S3 | 批准的当前配置投影未列出本条 consumer pointer；由 owner 核实实际消费位置和是否仍需保留。空数组不证明未使用，不删除。 |
| A1 | 从独立于 J3160 的可信权源绑定 HeptaBao 服务身份/CA，实际验证 TLS 链、名称及拒绝错误身份；保留原信任绑定的回滚证据。 |
| A2 | 确认新 AppRole 的 role 名称、最小 Policy、TTL 与绑定，受控签发 RoleID/SecretID；实际验证 AppRole、TLS、KV、Policy、续期和撤销。当前文件存在不是可信凭证来源证明。 |
| A3 | 为本条信任/身份绑定完成真实凭证读写、进程重启及回滚回执，再将实际客户端端点切至已确认的 HeptaBao。 |
| B1 | 逐项确认数据及配置依赖，取得一致性快照/备份目录清单；在隔离目标完成 cold restore 与回滚并保留校验回执。metadata、配置投影和文件存在均不构成恢复成功。 |
| B2 | 确认实际运行消费者、状态与备份依赖，迁移到已确认的 HeptaBao 后分别验证重启、恢复和回滚；本条旧 runtime 资产保留至资格完成。 |
| B3 | 对本条已记录的 maintenance 枚举截断、depth2 未跟随目录及敏感 auth 子树分别建立 owner 认可的后续有限清单；不从本回执推断未枚举内容或完整可再生性。 |
| R1 | 将四个启动项和八个依赖绑定到实际进程、上游/下游消费者；二进制 magic、静态配置和未跟随引用不能证明运行行为。验证实际路由/凭证消费、重启和回滚。 |
| M1 | 当前配置明确引用本条路径，但目录及原列五文件仍缺失。由 owner 确认实际挂载/目录/配置归属或是否正式退役，在真实 owner 路径建立后取得 SDK 与凭证/恢复回执；不因缺失而判定已迁移或可删除。 |
| C1 | 逐台收齐真实凭证读写、消费者 canary、重启与回滚证据，最后执行正式切流并记录结果。 |
| L1 | 只有全部 owner、备份路径及 pending 主机/CI 边界完成迁移，并形成明确恢复/回滚证据，才评估删除旧服务、二进制和已证明可再生的中间资产。 |

## 19 条 SecretRef：精确来源 → HeptaBao owner 确认的 KV/消费者绑定

全部行实际状态为 `metadata_only_payload_and_consumer_unqualified`；目标 mount/key 未确认。

| 主机 | 精确文件路径 | 已观察 consumer pointer | pending 动作 |
|---|---|---|---|
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/gateway-auth-token.secret` | `/gateway/auth/token` | S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/ollama-api-key.secret` | `/models/providers/ollama/apiKey` | S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/qwen-portal-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/google-websearch-api-key.secret` | `/plugins/entries/google/config/webSearch/apiKey` | S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/discord-token.secret` | `/channels/discord/token` | S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/feishu-app-secret.secret` | `/channels/feishu/appSecret` | S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-main.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-hepta-ui.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| macbook-pro | `/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-trnm.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| rog | `/home/qian-qi/.openclaw/credentials/secretrefs/gateway-auth-token.secret` | `/gateway/auth/token` | S1, S2 |
| rog | `/home/qian-qi/.openclaw/credentials/secretrefs/zbj-taskflow-webhook.secret` | `/plugins/entries/webhooks/config/routes/zbjAutoIntake/secret` | S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/gateway-auth-token.secret` | `/gateway/auth/token` | S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/memorysearch-remote-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/google-websearch-api-key.secret` | `/plugins/entries/google/config/webSearch/apiKey` | S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/tg8687951891-model-minimax-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/tg8687951891-model-minimax-cn-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/tg8687951891-authprofile-minimax-cn-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/env-gemini-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |
| pocket4 | `/home/alex/.openclaw/credentials/secretrefs/env-google-api-key.secret` | 本投影未见；需 owner 核实 | S3, S1, S2 |

## 12 条 AuthBus binding：精确来源 → HeptaBao TLS/AppRole

均为现存普通文件、仅 metadata；可信来源及切换尚未取得资格。

| 主机 | 类型 | 精确文件路径 | 实际 mode | pending 动作 |
|---|---|---|---|---|
| main | caFile | `/home/qian-qi/.openclaw/credentials/authbus/ca.crt` | 0o600 | A1, A3 |
| main | roleIdFile | `/home/qian-qi/.openclaw/credentials/authbus/role_id` | 0o600 | A2, A3 |
| main | secretIdFile | `/home/qian-qi/.openclaw/credentials/authbus/secret_id` | 0o600 | A2, A3 |
| macbook-pro | caFile | `/Users/qianqi/.openclaw/credentials/authbus/ca.crt` | 0o600 | A1, A3 |
| macbook-pro | roleIdFile | `/Users/qianqi/.openclaw/credentials/authbus/role_id` | 0o600 | A2, A3 |
| macbook-pro | secretIdFile | `/Users/qianqi/.openclaw/credentials/authbus/secret_id` | 0o600 | A2, A3 |
| rog | caFile | `/home/qian-qi/.openclaw/credentials/authbus/ca.crt` | 0o600 | A1, A3 |
| rog | roleIdFile | `/home/qian-qi/.openclaw/credentials/authbus/role_id` | 0o600 | A2, A3 |
| rog | secretIdFile | `/home/qian-qi/.openclaw/credentials/authbus/secret_id` | 0o600 | A2, A3 |
| pocket4 | caFile | `/home/alex/.openclaw/credentials/authbus/ca.crt` | 0o644 | A1, A3 |
| pocket4 | roleIdFile | `/home/alex/.openclaw/credentials/authbus/role_id` | 0o600 | A2, A3 |
| pocket4 | secretIdFile | `/home/alex/.openclaw/credentials/authbus/secret_id` | 0o600 | A2, A3 |

## 38 条 backup/runtime：精确来源 → owner 一致性快照、恢复与回滚

38 条均存在；包含 33 个 backup 引用、4 个 AuthBus runtime 和 1 个 relay runtime。每条 `restore_qualified=false`、`backup_consistency_verified=false`；未命中 bounds 也不代表完整备份清单。

| 主机 | 精确路径 | 实际观察 | pending 动作 |
|---|---|---|---|
| main | `/home/qian-qi/.openclaw/authbus` | 目录，观察子条目 34 | B2, L1 |
| main | `/home/qian-qi/.openclaw/backups` | 目录，观察子条目 6 | B1, L1 |
| main | `/home/qian-qi/.openclaw/backups/authbus-fallback-reset-20260823T144330+0800` | 目录，观察子条目 0 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.backup-before-telegram-residents-20260506_171100` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.backup-before-telegram-residents-20260506_171116` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.bak.1` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.bak.2` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.bak.3` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.bak.4` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.pre-restore-telegram4-20260511_193137.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.telegram-dns-20260503_154420.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.telegram-fix-20260503_154311.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.telegram-ipv6-strict-20260503_154947.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/openclaw.json.telegram-menu-20260503_155952.bak` | 普通文件，受限配置投影 | B1, L1 |
| main | `/home/qian-qi/.openclaw/tmp-antigravity-pairing-backup` | 目录，观察子条目 7 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/authbus` | 目录，观察子条目 31 | B2, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/authbus-relay` | 目录，观察子条目 97；枚举截断；depth 2 截断 | B3, B2, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/backups` | 目录，观察子条目 12 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.bak` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.bak.1` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.bak.2` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.bak.3` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.bak.4` | 普通文件，受限配置投影 | B1, L1 |
| macbook-pro | `/Users/qianqi/.openclaw/openclaw.json.r81-a2a-allow-backup-20260620T051653+0800` | 普通文件，受限配置投影 | B1, L1 |
| rog | `/home/qian-qi/.openclaw/authbus` | 目录，观察子条目 27 | B2, L1 |
| rog | `/home/qian-qi/.openclaw/backups` | 目录，观察子条目 1 | B1, L1 |
| rog | `/home/qian-qi/.openclaw/openclaw.json.bak` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/authbus` | 目录，观察子条目 37 | B2, L1 |
| pocket4 | `/home/alex/.openclaw/backups` | 目录，观察子条目 0 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.bak` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.bak.1` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.bak.2` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.bak.3` | 普通文件，受限配置投影 | B1, L1 |
| pocket4 | `/home/alex/.openclaw/openclaw.json.bak.4` | 普通文件，受限配置投影 | B1, L1 |

## Mac relay 的 4 个启动项与 8 个依赖

四个 plist 均匹配原 SHA，`new_references_not_followed=[]`；环境变量只记录字段名。四个可执行文件仅读取各 16 字节 magic，均为 `MachO_or_fat`，未执行。两个 auth 文件只取 metadata。配置中的 loopback 地址/端口是静态投影，不证明实际监听、转发或凭证消费；`bridge.json` 的批准投影未产生端点，同样不能断言无依赖。

| 精确路径 | 实际观察 | pending 动作 |
|---|---|---|
| `/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.bridge.plist` | plist 匹配 baseline；未验证运行 | R1 |
| `/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.egressguard.plist` | plist 匹配 baseline；未验证运行 | R1 |
| `/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.front.plist` | plist 匹配 baseline；未验证运行 | R1 |
| `/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.proxy.plist` | plist 匹配 baseline；未验证运行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/auth/cliproxy.internal.key` | 仅 metadata；载荷未读 | S1, R1 |
| `/Users/qianqi/.openclaw/authbus-relay/auth/nodes.json` | 仅 metadata；载荷未读 | S1, R1 |
| `/Users/qianqi/.openclaw/authbus-relay/bin/authbus-relay-bridge` | 16 B Mach-O/fat magic；未执行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/bin/cli-proxy-api` | 16 B Mach-O/fat magic；未执行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/bin/egressguard` | 16 B Mach-O/fat magic；未执行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/bin/relayfront` | 16 B Mach-O/fat magic；未执行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/config/cliproxy.runtime.yaml` | 受限静态投影；未验证运行 | R1 |
| `/Users/qianqi/.openclaw/authbus-relay/state/bridge.json` | 受限静态投影；未验证运行 | R1 |

## 保持 pending 的边界与公有来源

`x230_owner_source`、`ai395_owner_source`、`private_ci_client_sources` 按原 pending 记录保留，paths 均为空；不补猜测目录。此处也没有 HA 断主/选主/ReadIndex、真实 provider liveness、凭证撤销或生产切流的成功证据。

全部实际观测时间为 2026-10-18T02:29:05–02:29:07 UTC；完整精确时间、每条 source JSON pointer、原 reused 时间、目标待定字段及动作状态保存在 [机器可读完整清单](authbus-owned-source-migration-20261018.json)。

| 原始公有文件 | 字节数 | SHA256 |
|---|---:|---|
| [authbus-migration-gap-v3-r1-controller-public-receipt.json](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-controller-public-receipt.json) | 6850 | `ebbe3b43fed4a0f955de0cc518902fa41dfd7d5c3198e7a693affaf327f45767` |
| [authbus-migration-gap-v3-r1-main.public.json](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-main.public.json) | 119093 | `3e5d8e12636487c08261a826f1dd03c29a5166765352fccdbbe33c640c35c0e9` |
| [authbus-migration-gap-v3-r1-macbook-pro.public.json](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-macbook-pro.public.json) | 194135 | `7e203aa01ac3c73af5419a6cb24327869e64b21496e14ec1cd185ca8b4efc868` |
| [authbus-migration-gap-v3-r1-rog.public.json](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-rog.public.json) | 60402 | `f6e126f936ffb4f5560a5acb60f826d1c2b88bd72298476a5b7a87d77383f3ea` |
| [authbus-migration-gap-v3-r1-pocket4.public.json](../../qa/openbao-acceptance/evidence/next-gates-20261017/authbus-migration-gap-v3-r1-pocket4.public.json) | 102812 | `d0085245623fff5ab94b131dc161e9c9f7357546b8fea954fcc36509a276acd4` |

公有回执源码 SHA：`6e36468e50e6f458cd970779c2a1d7dda7aa761547381edacdb5e1d37e34d2ce`；canonical PLAN：`a37331721a7560b60029c08db9423dd5eda57dc3855c889c492a4a6b79729644`；receipt-set：`bf03a5819e325fac277a2de74768c2639dcb9650cf47285d87e77d26a2f1068c`。本清单未改动 scanner、controller、QA 或实际客户端。
