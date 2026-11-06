# R35 — H2 原件通过；CLI standby 仍失败；AuthBus 根因与 JWT 实测继续

冻结时间：2026-11-06 03:49:20 UTC。这是正在推进中的证据检查点，**全量替代、生产切换、所有客户端与备份迁移、旧版清理均未完成**。

## 本次新增结论

H2 的原始完整报告已独立核验。H01、H02、H03 分别覆盖 HTTP/1 控制快照、实际 TLS/ALPN h2 转发的 KV2 读取，以及 h2 原生快照下载。121 项是证据一致性检查，不能当成121项产品测试。原任务仅启动一次，11个原观察、46页及114条进程回收记录完整。这次范围是同一物理机上的三个进程，不能替代34MiB H2、真实多机或官方CLI恢复验证。[完整原件](../H2-complete-qualified/SUMMARY.public.json)；[根核验](H2-root-qualification.public.json)。

官方 OpenBao2.7.1 CLI 实际任务以 exit1 结束，输出完整且已持久化。原摘要报告 B01–B03 为真，B04默认standby保存、B05默认standby恢复为假。848065字节报告的文件版本及摘要已实际核对，完整正文尚待13段原始读取闭合；因此本检查点不把前三项摘要提升为独立通过，也不先断言后两项的根因。[权威终态与原摘要](../CLI-known-failure-original/OWNER-RELEASE.public.json)；[实际文件元数据](../CLI-result-info-actual/FILE-INFO.original.json)。

Mac AuthBus 原业务任务仍是失败，已完成业务操作为0。两次只读诊断确认原标签没有PID、runs1、not running，last exit code为78: EX_CONFIG；原解析器不接受这个整数加符号格式。第二次诊断发现原错误日志为空，未取得启动原因。69项独立检查确认该诊断本身的11个描述符、2个辅助进程和原读取任务已闭合；它不证明原标签及历史进程链闭合。只读固定路径诊断正在执行；解析器修复及同标签清理仍只有候选源码。[第二次原件](../AuthBus-stderr-diagnostic-actual/actual-RELEASE.public.json)；[根核验](AuthBus-stderr-root-qualification.public.json)。

JWT 原生实现候选 e3afc157 已在ROG上完成隔离检出，原进程exit0，传输链已核验。27581字节完整检出报告的元数据已实际取得，正文原观察仍在收齐；格式化、编译、产品测试均未运行。计划的147个不同测试、162个配置实例是未来门槛。default feature下的File V6测试也不能等同分布式JWT HA。[原阶段输出](../JWT-source-stage-original/stdout.original.txt)；[阶段元数据](../JWT-stage-info-actual/actual-metadata.public.json)。

## 保留的既有基线

已通过的Mac/X230正式KV2 34MiB迁移恢复、Mac/ROG/Pocket4多机HA及冷重启、Mac与ROG正常回归，以及X230比较，仍绑定4e808d0e。这次证据整理没有重跑或改变这些范围，也没有把它们转移给未编译的JWT候选。完整数目与边界记录在[状态文件](STATE.public.json)及先前R33/R34检查点中。

## 接下来必须完成

先收齐CLI报告并修复确证的standby兼容性问题；查明Mac启动失败并完成可信AuthBus凭证业务闭环；对JWT候选做格式检查、冻结实际源码、编译和真实测试。随后继续未完成的原生认证、外部secrets效果、PKI/Transit集成、管理操作与插件路径。逐台真实凭证读写、重启、回滚和流量切换，以及所有当前备份路径的迁移，必须有实际证据。旧OpenBao及旧HeptaBao资产此时仍保留。

## 证据完整性

本目录只新增20个已逐文件完整读取的原件或SOURCE子树及根复核文件，共858个子树叶子、9004366字节（不含root-current）。旧失败、旧Git mutation UNKNOWN、两个AuthBus非Native本地归档缺口及其他历史归档缺口均保留。原对象的早期pending字段按原样保存，由时间更晚且单独签定的根核验解释，未覆写原件。SOURCE检查与真实产品测试分别记录。

[挂载与摘要清单](MOUNTS.public.json) · [机器可读状态](STATE.public.json)
