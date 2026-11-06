# R37：JWT 实际格式源码冻结，AuthBus 与 PKI 证据继续闭合

事实截点：2026-11-06 06:12:09 UTC。前一验证提交：`b3113cd09cfba131dc7339e2c2267ad87a87d283`。

**全量替代 OpenBao 2.7.1、正式切流、全部客户端与备份路径迁移、旧资产清理均仍为 false。** 本检查点新增证据，并记录独立源码分支的格式后继；验证分支中的产品源码和历史结果保持原样。任务继续。

## 已完成：JWT 的实际格式后继

已冻结 [808e45d690f177ecb922e13d1ed19f7877156094](https://github.com/TrillionniumFoundation/HeptaBao/commit/808e45d690f177ecb922e13d1ed19f7877156094)，树 `0506d30b02f5a2a2dc7d6364299365ae8d1d7cc7`，唯一父提交为原候选 `e3afc157447d35c861f275a761b29da3e42aff8e`。九个请求文件中六个变化、三个不变，其余 3,910 个叶子逐项一致。源码分支非强制 CAS 与回读完成。

固定 38 项输入共 3,701,083 字节，经 EOF、SHA256、命名路径与持有描述符的 full9 身份核验。完整 167,436 字节报告由三个固定版本范围、21 次原调用、15 个不可变结果页重建；九份源码均完成严格正向与反向差异核对。最终 46 个自有 FD 闭合另由终态 stdout 和 authority 支持。根端共 289 项证据核查通过，**不是 289 个产品功能测试**。[完整资格](../JWT-actual-formatted-source-and-root/qualification.json)；[源码冻结证明](../JWT-freeze-proof/proof.json)。

原 formatter 九个直接子进程已回收，但共享 supervisor 进程组，不宣称九个独立空进程组。文件观察是顺序观察，不是原子文件系统快照。新源码尚未编译或运行产品测试，不能借用旧基线资格。

## 用户五项门槛

| 门槛 | 已有实测 | 尚未闭合 |
| --- | --- | --- |
| KV2 正式迁移与恢复 | 原 4e808 的 Mac、X230 正式 34MiB 各 31/31，包含原生恢复与冷重启 | 新候选验证、全部客户端及备份迁移 |
| 真实多机 HA | 原 Mac、ROG、Pocket4 三机 98/98，加独立冷重启 12/12 | 快照转发修复后的真实多机验收及全量切流资格 |
| AuthBus，不依赖 J3160 | 两轮固定日志观察的原调用全部闭合 | 原服务退出原因、可信凭证链及 AppRole/TLS/KV/Policy/续期/撤销业务验收 |
| 逐台切换 | 原隔离结果和有限当前清单保留 | 每台真实凭证读写、重启、回滚、正式切流 |
| 旧版清理 | 清理条件保持冻结 | 需先证明全部当前客户端和备份路径迁完 |

表内旧实测属于固定 `4e808` 二进制。本轮没有把结果转移到未构建的新候选，也没有删除旧服务、二进制或恢复资产。

## AuthBus：诊断闭合，根因仍未知

原固定日志投影失败保留，其未导出的 817 字节未恢复。新 schema 查询观察到两个对象：第一个的标签、进程、时间窗口匹配；第二个缺少全部八个选定字段，其语义类型仍为 UNKNOWN。[根核验](../Auth-schema-root-actual/ROOT-QUALIFICATION.public.json)。

之后的新查询逐对象使用原分类器，观察两个、接纳一个、拒绝为未知一个。接纳对象的 28 个固定错误类别、errno 和路径布尔值全部为 false；这不证明日志完整、没有错误或已找到启动根因。[逐对象核验](../Auth-admitted-events-root-actual/ROOT-QUALIFICATION.public.json)。

新查询也产生 817 字节，但相同长度不证明与旧失败查询的字节相同。原未知 label、私有 capsule 和旧 Git UNKNOWN 保留；没有访问 J3160。截点时独立 launchd 探针仍在准备源码，无新探针 GO 或执行：拟先在 home 记录真实 birth/握手，再尝试新 T5 目录及公开 sentinel。launchd 管理的进程不冒充可 wait/reap 的直接子进程。

## PKI：原 formatter 及收据元数据通过，正文与十文件待验

原任务 `rog/1a1af6d62a1-fc05-686a` exit0、full、durable、confirmed；七次原调用、两个 observer、两个结果页闭合，stdout 921 字节、stderr 为空。摘要报告生产文件不变，测试文件格式后 42,909 字节。根端 39 项检查只授予原调用链与摘要资格，两个实际子进程、工具、配置及十个文件仍需进一步证据。[原调用资格](../PKI-two-file-formatter-root/qualification.json)。

收据独立 file_info 为 4,907 字节，SHA256 `7b2560af593a62c7de4b8ca3a8cb7c2fffaed1408b2f1b356a302a38a7617776`，版本 `66306:28071628:4907:1793944550782366173:1793944550782366173`，0600、1000:1000、单链接。三次原调用及一个结果页已通过 21 项根核验。[元数据资格](../PKI-receipt-info-root-actual/qualification.json)。在此截点，收据正文尚无读取 GO，十个输出也未授予资格。

原 X230 比较仍是 69 项中 **67 项状态码精确一致、2 项 PKI 状态归一化**。代码与新增测试目标为到期/撤销租约查询精确返回官方 400；尚无新的实际通过。TTL 2 秒、等待 2.3 秒和请求顺序不变。后续 12 项真实 PKI HTTP 检查单独记账。

旧 BUILD26 的 147 个唯一测试、162 个 profile 实例保持不变。加入两个 PKI 回归后的新计划为 149 个唯一测试、166 个实例：File V6 17 个、默认 profile 149 个。它仍需绑定最终 JWT+PKI 源码，此截点执行数为零。

## 快照 CLI：B04、B05 继续是实质阻塞

原 B04 standby save 退出 2、incomplete_snapshot，无合格归档。原 B05 使用完整未改动的 B03 归档，CLI 退出 0，但主节点审计 400、standby 307；三节点真实状态仍为修改后的状态，冷重启亦如此。恢复未成功，退出码不能替代状态证据。原 415 项核验和五场景结果不改写。

新的 binary body、mTLS transport 和 Service 集成仍为源码。transport 六个测试源中五个走实际 socket/mTLS、一个只检查构造阶段截止时间；均未编译执行。固定 rustls 0.23.44 的源码审查不代替半关闭实测。

本检查点挂载的 Service 草稿保留真实 SnapshotTransferPlan、原 Auth/Actor、私有实际文件和双向字节摘要，但 HA/HTTP 接线和提交后失败处理尚未完成。已经提交恢复后的交付失败必须保留真实收据，明确 UNKNOWN、禁止重放。原 1MiB JSON 与 32MiB HTTP2 ingress 上限未扩大。

## JWT 权限与其余全量范围

根端重新从 OpenBao 固定提交读取五份 JWT/HTTP/ACL 源码及 logical response mapper，六份文本与现有原件完全一致。named role 以 ExistenceCheck 区分 Create/Update，Delete 使用独立能力；集合只支持 List。当前 native owner 与 handler 都保留旧 sudo/update 及集合 GET 行为，必须一起修正。

[23 项矩阵的源码检查](./JWT-ACL-primary-inspection.public.json)包含九项预期状态差异。全部仍是推导；真实非 root 凭证、共同合法 PEM/role/config、原始 HTTP 状态与独立状态变化对照尚未执行。403、404、405 不归一化为通过。

OIDC/Kubernetes/MFA、外部 provider 单次副作用与恢复、ACME/EAB、外部 KMS/HSM、rekey/root 管理、插件变更、受保护 namespace 等门槛继续保留；当前客户端和备份清单没有宣称全覆盖。

## 归档与继续工作

本检查点挂载 38 个 whole 数据包、694 个挂载文件、12120593 字节。这是本检查点的挂载总数，不是产品测试数或全历史唯一对象数。[挂载清单](./MOUNTS.public.json)；[机器可读状态](./STATE.public.json)。旧失败、未知调用和旧本地归档缺口全部保留。

继续收齐 PKI 实际输出，冻结三文件修复后独立 stage 最终源码并运行明确测试计划；完成快照转发接线与 AuthBus 探针，再推进每台客户端、回滚和备份验证。清理条件尚未满足。
