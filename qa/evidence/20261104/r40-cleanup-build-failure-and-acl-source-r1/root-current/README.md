# HeptaBao R40：QA 标签闭合、原始构建失败与 ACL 源码修正

事实截止：2026-11-06 10:06:00 UTC。接续 R39 `1badf75b2c541abcebad269adc7be8020bf9e63c`，工作继续。**全量替代 OpenBao 2.7.1、生产切流、全客户端及备份迁移、旧资产清理均未达成。**

本轮可核验事实、原始请求、SDK、结果、文件长度和摘要分别见 [STATE](STATE.public.json)、[MOUNTS](MOUNTS.public.json) 和 [独立复核索引](ROOT-INDEX.public.json)。复核检查数用于判断证据或源码，不能计作产品测试通过数。

## 实际结果

| 范围 | 已观察结果 | 本轮边界 |
| --- | --- | --- |
| Mac 当前固定 QA 标签移除 | 原 job `mac/1a1b0305ba9-fc05-6ee6` exit0/full/durable；一次固定 bootout 返回0且空输出，随后两次 print 精确返回缺失113；4个 helper 和21个应用 FD 全部闭合，最终元数据校验通过 | 当前标签移除成功；旧 R4、helper87650、旧 AuthBus PID11754 的历史 UNKNOWN 保留 |
| Mac libproc R3 只读观察 | 原 job exit0，2次固定注册项观察、6次有限 libproc 调用；2个 helper 和21个 FD 闭合 | ESRCH 仅作为查询结果，未据此推断历史进程离开或被回收 |
| snapshot2379 源码暂存 | 3930个跟踪文件、62,486,000字节、61条原始命令，直接子进程全部闭合 | bundle 有前置提交要求 |
| 49文件格式化 | 原 job exit0/full/durable；49行声明中23个发生变化、26个不变 | 详细 report 和实际文件正文仍待取回；未冻结格式化产品提交或运行27项回归 |
| JWT/PKI33b 构建 | 原 job `rog/1a1b029a998-fc05-6eb2` failed/exit1，原输出完整且持久化 | 截止本记录时，149 unique/166 instances 只是预检分母；实际编译测试数量和失败原因待原详细报告 |

相关整件报告和核对脚本均可从 [ROOT-INDEX](ROOT-INDEX.public.json) 直接定位。

## 原始读取错误和有限恢复

**格式化报告 BODY0** 的固定 public binary_read admission 返回 MCP -32603 timeout，没有 operation ID。key、路径、版本、范围、intent、armed、SDK 整件保留；原 journal 仍 paused/pending，BODY1没有提交。原请求是否受理、可能存在的 future 是否关闭，继续标记 UNKNOWN。当前仅准备恢复源码，未换 key 或重放。[UNKNOWN 原件](../Snapshot2379-format-body0-UNKNOWN10/STATE.public.json)

**构建报告 BODY** 的原 binary_read 已确认 completed/stored/inactive。49,765字节不可变 payload 已取得前32,768字节，第三页交付 timeout。原错误和暂停状态保留。单独 SOURCE/GO 允许新 retrieval context 仅按同一 operation ID 取回 offset32768、49152两页，各 cap16384；该 API 不派发新的业务操作。截止时第一页取回在途；完整36,998字节报告、实际失败原因和 Cargo target 可复用性尚未在此 checkpoint 中确认。[取回计划](../PKI33b-original-body-tail-source22/PLAN.public.json)

## 源码修正

### Mac 的 Python 身份检查

三个组件分别核对固定 Python 启动器路径和系统报告的进程镜像路径，保留独立启动器整件校验及原 PID、出生时间、UID、PGID 约束。严格正反补丁为3/2/2处，完整 AuthBus outer `12a6fa7a…` 逐字不变。这个比较问题尚未被证明是旧 EX_CONFIG78 的原因。

组件仍含旧根目录和标签，尚非可执行的新候选。新的 HOME 公共控制/T5 业务候选继续保留完整五 agent 初始及冷启动链、真实 AppRole/TLS/KV/Policy、续期和撤销，不复制旧私密 capsule 或放宽原凭证期限。[完整集成计划](../Auth-launcher-kernel-components-source22/PLAN.public.json)

### JWT ACL

两个生产层共同修正原角色存在性与授权的关系：原角色缺失时捕获 create，存在时捕获 update，并保留该能力到 publication/delivery；DELETE 要求 delete，缺失角色返回204且不分配空 mount；裸集合 GET 要求 read 后返回405，LIST仍要求 list；config 要求 update。原 validate_assignment、JWT验证、时钟、审计、发布、mount/tune及revoke-orphan约束保留。

初始测试 fixture 的角色 actor 缺少 default 委派前提。R2 仅将4个角色 actor 明确设为 `[default,name]`；其余5个保持 `[name]`，仍使用 `no_default_policy:true`，并断言发行响应和独立 lookup 的完整策略集。1个旧 ACL 测试被3个新的 FileV6 实际生命周期测试替换，其他14个测试函数逐字不变。[66项源码同行复核](../JWT-ACL-R2-peer4/PEER.public.json)

源码尚未格式化、编译、执行或冻结为产品提交。官方23例 ACL实际执行数仍为0；原 no-default actor 委派前提仍须解决。HTTP12 的两个 PKI 状态精确对照也未通过。新源码不会改写原33b的149/166失败任务。

## 已有基线和剩余门槛

先前 `4e808d0e…` 基线上，Mac/X230 正式34MiB KV2迁移与恢复各31/31；真实 Mac/ROG/Pocket4 的主进程 SIGKILL、重新选主、ReadIndex、失去多数派和持久化冷启动为98+12。X230 对照仍为67项状态精确一致、2项 PKI归一化。通过范围保留，不能自动授予当前候选。

旧 CLI B04 standby SAVE 和 B05 standby RESTORE 仍失败。B05 的 CLI exit0没有证明实际恢复，第二次上传字节及内部400原因未知。先前小归档 H2 结果也未覆盖34MiB、多机或原生 OpenBao归档互操作。

下一步继续取回原报告和编译日志、修复实际失败、冻结格式化正文并运行23+4回归、完成 JWT/PKI真实对照及新的 AuthBus 全链。外部数据库/Kubernetes/RabbitMQ、ACME/EAB、KMS/HSM、OIDC/MFA、rekey/root、插件与受保护 namespace 等差距完整保留在 [STATE](STATE.public.json)。

每台真实客户端均需凭证读写、重启、回滚和备份迁移证据，再正式切流；旧资产删除仍受这些完成条件约束。本 checkpoint 挂载 56个整件证据包、1159个文件、10,496,993字节。产品源码和旧路径不变，无删除；截止后的实际结果留给后续 checkpoint。
