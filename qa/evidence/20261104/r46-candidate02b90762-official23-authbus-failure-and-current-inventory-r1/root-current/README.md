# R46 — 候选 02b90762、官方 ACL23 与剩余迁移门槛

截至 2026-11-06 18:33:16 UTC。任务继续执行；**全量替代、正式切流、全部客户端及备份迁移、旧版清理均未通过**。

## 已固定的候选

候选提交 `02b90762b3d6cc8699cc88bffb6f76cb1f07e270`，源码树 `9781e9615ac5fb068d217241c74bb54bf87942cf`，独立分支 `codex/heptabao-snapshot49-jwt147-9781e961-20261106`。相对025b共有61个文件变化，其中16个新增、没有删除；全树3932个文件、62537554字节。父提交、16段至495的真实祖先链、全部文件身份及Git遍历顺序索引均已核对。[发布原证据](../candidate-publication-proof/PUBLICATION-PROOF.public.json)

本候选整合49项快照源码、Identity测试投影修复、JWT权限及策略存储修复。JWT角色配置不再自动写入default，登录时依据token_no_default_policy决定注入；历史缺失标记保留原语义，新的语义要求schema147，并阻止持久化或恢复降级。root策略仍不能在JWT登录时签发，续期保留原授予策略。Native JWT batch仍明确501。

计划246个不同测试、268次配置运行：file22、default229、HA17。源码机械检查、差异往返与测试清单核验已完成；**这些不是Rust测试执行结果，且本候选没有取得格式化资格**。ROG唯一独立源码准备已启动：`1a1b21f5945-fc05-7c77`；本截点仍等待完整终态和报告，不执行Cargo、产品或formatter。[源码](../jwt-production-source92/PROPOSAL.public.json) · [运行清单](../combined246-runner-source25/PROPOSAL.public.json) · [源码准备GO](../bound02b90762-source-stage-root-go/ROOT-GO.public.json)

## 官方 OpenBao 2.7.1 实际23项

651803字节原报告已完整取回。TLS和发行包成员/运行二进制对应已确认；23项原始状态均匹配修订后的官方源码预期，8个204请求实际改变完整状态，其他15项保持不变。403共12项、204共8项、200共2项、405共1项；未归一化状态。四个原子进程均同一Popen等待一次并闭合，原二进制及安装包前后full9一致。安装包元数据中的whole-hash标记原值false保留；真实运行身份另有哈希证据。

| 行为 | 原始实际结果 |
|---|---|
| DELETE角色，仅update或update+sudo | 403 |
| DELETE角色，delete或delete+sudo | 204 |
| 裸GET角色集合，read | 405 |
| 裸GET角色集合，list | 403 |
| LIST或GET?list角色集合，list | 200 |
| 已有角色POST，update | 204 |
| 新角色POST，create | 204 |
| 新角色POST，只有update+sudo | 403 |
| JWT配置POST，update | 204 |

角色输入省略policy时，真实读回包含空token_policies。这23项未测试显式空策略、root签发或role no-default边界。**这只证明官方侧；候选侧及总体parity仍为false。** 838/853次有界HTTP记录、原91个Native调用及两次原观察恢复全部保留；旧UNKNOWN不改写。[完整原报告](../oracle-complete-aggregate662/actual/result.public.json) · [原始语义复算](../oracle-complete-aggregate662/verification/verifier.actual.json)

## Mac AuthBus 实际失败

原作业`1a1b1d28dc2-fc05-7afe`退出1，211872字节stdout和空stderr已完整闭合。当前HeptaBao测试服务完成TLS初始化16个HTTP请求，管理器记录1个操作，消费业务阶段记录仍为0。错误发生于完整BSD信息/PID检查；原报告未捕获count或errno，因此不能倒推ESRCH、PID复用或特定系统原因。

观察链关闭不等于托管进程关闭。原两个注册、lineage及两个ps helper的历史闭合仍未证实；overall outcomeUnknown和allAccountsQualified=false保持。后继只读提案核对原标签、固定PID和公开结果文件，不重派bootout，不从当前缺席推断历史reap。凭证值未公开、未联系J3160、未改生产服务。[原完整证据与失败](../auth-runtime-complete507/README.md) · [只读提案](../auth-original-reconcile-core9/CONTRACT.public.json)

## 当前客户端及备份

X230用户目录搜索触及4096条遍历上限，未覆盖有效文件；零结果不是不存在。systemd有界名称搜索发现一个OpenBao代理单元，读取时为loaded、inactive/dead、disabled、MainPID0；用户域not-found。该单元尚未与UID100的bao容器进程建立对应。

固定PID2031533前后身份相同，允许的cgroup显示Docker scope；exe readlink返回EACCES，原探针exit1/overallOK=false，未绕过权限。路径、镜像与版本仍不明。Pocket4当前网络读数与历史192.168.0.9对应，但物理/双通路身份仍需实际交叉核对。所有客户端和备份路径尚未完整迁移。[当前只读结果](../root-current-inventory-actual/RELEASE.public.json) · [固定PID原证据](../fixedpid-original-observation/release.public.json)

## 必须继续通过的门槛

1. 原候选完成构建、准确测试枚举、246/268运行，随后strict HTTP12及官方23候选侧比较。
2. 修复AuthBus观察/所有权问题，在可信当前凭证来源上执行AppRole、TLS、KV、Policy、续期、撤销、重启、回滚，并最终绑定同一候选。
3. Mac与X230重跑正式34MiB迁移/恢复，Mac、ROG、Pocket4重跑同候选断主、重新选主、ReadIndex、持久化及重启。
4. 补完每台当前客户端和备份清单，每个客户端先读写、重启和回滚，之后逐台切流。
5. 全部迁移证据通过后再清理旧服务、二进制及可再生资产，保留最新版合格服务。

历史4e808的Mac/X230各31项34MiB、Mac/ROG各61项普通回归和三机98+12仍仅是历史基线。新快照CLI失败修复、新JWT及未覆盖的插件/管理能力不可继承这些资格。

## 证据与恢复

本检查点挂载48个精确树、2216个文件、42919008字节，完整索引见[ROOT-INDEX.public.json](ROOT-INDEX.public.json)。18:12:54 UTC所有代理临时缓存失效时无Native在途、候选尚未开始创建；已从固定Git对象恢复，重算源码树逐字节一致，未重跑任何原Native作业。本地执行器仍不可用，原始观察、失败及恢复界限保留。检查点记录进度，不标记任务完成。
