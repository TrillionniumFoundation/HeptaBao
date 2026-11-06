# R38：源码后继、独立检出与 Mac 探针原始证据

截止 **2026-11-06 07:54:07 UTC**。工作继续；**全量替代 OpenBao 2.7.1、生产切流、所有客户端及备份迁移、旧版清理均未完成。** 本检查点保留每条原始失败，不用源码检查数代替运行结果。

## 本轮已完成

| 工作 | 可复核结果 | 当前边界 |
|---|---|---|
| PKI/JWT 源码 | `33b814c7034ec853151b1ff13e7529c83f65ea70`；3 文件精确后继；两份实际格式化 Rust 输出完整重建；接受测试中两处状态归一化已在源码中移除 | 尚未 Cargo、149/166 测试或 PKI HTTP12 |
| PKI/JWT 独立检出 | 原 ROG `1a1afcbafab-fc05-6bb0` exit0、374B 完整摘要；根34核原7调用/2观察器/2页 | 独立详细报告 metadata/body 尚待完成；未把摘要当全源码资格 |
| 快照旧候选独立检出 | `8c95fb0…` 的3928文件/62460068B/index逐项核对；59直接子命令退出、旧源及旧失败目录前后栅栏、增量bundle均由完整报告支持；根48 | 仅该未格式化候选；bundle未独立传到Mac |
| 快照穷尽匹配修补 | 新 `b6949024dc5d0922ca9b27d865923d28982286c3`；24旧fixture加65行明确拒绝arm，0删除、0新测试，原断言/期限不变；根173 | 未格式化或编译；下步46 Rust文件并集；不含PKI33b |
| Mac fresh Python 诊断 | 同一进程两次原reader观测：固定sys launcher正确，内核image path不同；五个数值谓词均真、路径旧等式为假；根45 | 只证明fresh路径观察；不证明kernel文件bytes/full9，不回填原R3字段 |
| Mac R4 公共探针 | 原 `1a1afc5dbd9-fc05-6b85` exit1，18131B全文；根75核16调用/3观察器/9页、5直接helper、33+3 FD闭合 | home_ready失败；新launchd注册/managed进程闭合未证实，outcomeUnknown=true；没有凭证业务 |

## 两个必须保留的失败

旧 CLI 的 B04 备用节点保存失败仍成立；B05 即使 CLI 返回0，真实基线没有恢复、主节点审计400，仍不合格。新快照转发的23组件测试及4类真实Service审计失败回归尚待运行。

Mac R4 的 bootstrap 返回0，但这没有建立 ready身份握手。两次原 print 各2276B，仅保留同一摘要，原正文未保存。根检查确认 frozen源码中的11个 parse_print 固定拒绝码没有进入公开错误表，因而可能显示null；具体原拒绝项仍未知。下一次工作是只读该新注册及已有公开控制文件，恢复当前可判定的状态；不重放失败探针，不猜测旧EX_CONFIG原因。

## 五个用户门槛

| 门槛 | 已有证据 | 继续条件 |
|---|---|---|
| KV2正式可迁移可恢复 | 既有4e808基线：Mac/X230各31/31，34MiB正式存储导入、快照、恢复和冷重启 | 新候选编译后重验受影响路径；补齐全体客户端/备份及OpenBao档案互通边界 |
| 真实三机HA | 既有Mac/ROG/Pocket4真实leader进程SIGKILL、重新选主、ReadIndex、失去多数派和冷重启98+12 | 新快照/转发候选与真实局域网及大载荷回归；既有结果不自动转移 |
| AuthBus不依赖J3160 | 本轮未接触J3160；public环境诊断原链完整 | 先解决新注册状态，再建立可信来源并完成AppRole/TLS/KV/Policy/renew/revoke |
| 逐台切换 | 当前未正式切流 | 每一实际客户端真实凭证读写、重启、回滚和备份路径证据 |
| 旧版清理 | 本轮未清理旧服务/旧二进制 | 所有客户端及备份迁移完成后才能删除，保留可验证的最新版服务 |

## 编译分母与诚实边界

明确计划为 **149项唯一测试 / 166个配置实例**：file17、default17、legacy63、native-auth69；现有132项＋JWT15＋PKI2。启动器旧15项形状检查已修正；独立source/prebound控制仍须实际报告和控制出版收据才能启用。原计划文档一个payload大小118231残留已说明，修正17的实际大小118239；后续绑定从实际字节重新计算。

API/路由静态覆盖不能代替完整OpenBao兼容证据。原生数据库/Kubernetes/RabbitMQ、ACME/EAB、外部KMS/HSM、root/rekey/plugin和受保护namespace等门槛仍在 STATE 中明确保留。

## 证据入口

- [完整状态与范围](STATE.public.json)
- [挂载清单与每件字节/SHA](MOUNTS.public.json)
- [Mac R4 固定错误码根源码说明](R4-PARSER-SOURCE-NOTE.json)
- [PKI/JWT 冻结证明](../PKI-source-freeze-proof/ROOT-PKI3-FREEZE-PROOF.json)
- [快照24后继冻结证明](../Snapshot-fixture24-freeze-proof/ROOT-SNAPSHOT24-FREEZE-PROOF.json)
- [快照独立检出完整资格](../Snapshot-stage-complete-root/ROOT-COMPLETE-STAGE-QUALIFICATION.json)
- [Mac R4 原始失败资格](../MacR4-PKI33b-terminal-root/ROOT-MAC-R4-FAILURE-QUALIFICATION.json)
- [PKI33b 原始终态资格](../MacR4-PKI33b-terminal-root/ROOT-PKI33B-TERMINAL-QUALIFICATION.json)

本树仅新增证据子目录；上一检查点、既有产品源码及原始UNKNOWN保留。后续实际调用与编译结果在下一检查点追加。
