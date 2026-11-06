# R48 — 编译阻断已定因并修补，新候选 5767739c 待实际验证

证据截止：2026-11-06 21:19:08 UTC。任务继续执行；本节点不是迁移完成报告。

## 当前结论

全量替代 OpenBao 2.7.1、正式切流、全部客户端及备份完成迁移、旧版清理均为 **false**。正式客户端切换数为 **0**。截止时 A/B/C/root 的 Native process/call/future 全部为 0；后续操作须继续遵守最多两条 Native 执行通道。

新候选为 [5767739cd25e458ac052dc8d384019bab8688ae0](https://github.com/TrillionniumFoundation/HeptaBao/commit/5767739cd25e458ac052dc8d384019bab8688ae0)，树为 42477d622dcf96e1e2b0929fe9ecc6b7ba484740，父提交为 02b90762b3d6cc8699cc88bffb6f76cb1f07e270。只有五个 Rust 文件发生变化。全部 3,932 叶、62,553,540 字节的树及索引已核对；把五叶替回旧值后精确复得旧候选索引。新候选尚未编译或执行测试，旧版的通过记录不计入新候选。

## 编译阻断与修复

实际 ROG job rog/1a1b282ded0-fc05-7e57 的 release Cargo build 以 101 退出，耗时约 360.19 秒，未超时，直接子进程已回收，没有剩余子进程，也没有开始任何运行测试。完整 stdout 384,182 字节、stderr 20,639 字节已经按固定版本读回并核对 SHA256。stdout 的 442 行均为合法 Cargo JSON：396 条 compiler-artifact、45 条 build-script-executed 和一条 success=false；其中没有 compiler-message。

stderr 给出 9 条 E0599：两份 snapshot forwarding 文件把仅实现于 Mutex<HaProcess> 的 HaLock 方法用于 Arc<Mutex<Service>>。修补只改九个 Service 锁表达式，使用既有 request_deadline::lock_until，并分别传入原 self.owner.deadline 或原 peer deadline。原 map_err、guard 作用域、审计、最终交付和 outcome_unknown 路径保持。两条 E0277 仍须由新候选真实编译确认，不能仅按推测标记解决。

[完整原报告与日志](../build02b-logs-actual22/)以及[两文件最小修复](../snapshot-service-lock-fix-source20/)保留原始失败和核查来源。整个原 job 的 88 calls、17 observers、53 pages 已关闭；没有重派该 build。

## Native 本地 JWT batch

新增实现复用原 JWT issuer 和单次 verifier lifetime，检查真实解封 batch 的 Identity、namespace、policies、metadata、expiry、无 Service backing row 等属性，再通过已有 Auth/Namespace 配对生命周期及审计后的响应证明交付。没有引入第二次 JWT 验签、第二个铸币器或新存储 schema；远程 JWKS/子 namespace 等没有因此获得资格。

独立源码审查未找到可具体成立的新生产安全或 Rust 接口阻断项，但指出失败前后快照漏掉完整 Namespace 生命周期对象。R2 已增加完整 state.namespaces 和 auth.namespace_batch_registry，保留原 Auth/Identity、batch_authority、Zeroizing 和 erase_json；定点复审确认这个测试证据缺口已修正。源码审查不等于运行验证。

新测试计划为 **252 个唯一测试、280 个配置实例、18 组**：file28/default235/ha-native-v6-peer-ingress17。六个新回归覆盖类型矩阵与冷重启、无逐令牌行、错误签名及过期、真实 Identity 禁用/重启、forced batch TTL/uses、no-default/root policy、审计失败及发布后交付保护。原 negative 测试仅移除 batch 不支持假设并改名，保留 remote/bad-signature 拒绝。[源码与完整计划](../successor5767739-candidate/)、[独立审查](../jwt-batch-independent-review/)、[快照补强复审](../jwt-batch-r2-correction-review/)均在本节点中。

## Mac、X230 与 LAN

Mac 的旧候选 02b 已在 UUID FB804D1B-24CB-4D6E-AEA7-A9E180807758 的 T5 上完成独立源码落盘及严格校验：原源码未改、没有 Git alternates 或共享对象硬链接、全部跟踪内容/模式一致，46 个 Git 子进程均成功回收。没有启动编译器或服务。该资格只属于 02b 的源码，不能替代 5767739 的 source/build/runtime 证明。

新 Mac source 模板已绑定实际 5767739 提交和树，计划以已验证的 T5 02b 源为只读 base，使用 ROG 产生的唯一 02b→5767739 增量 bundle。bundle bytes/SHA、carrier、request 和实际 job 均尚未填充。normal 后继保留原 61 项，并准备新增明确的 default28/file28 JWT/PKI 组；full34 仍保留原 17×2 MiB、31 检查。上述都只是准备，未启动。

X230 的已知 OpenBao 2.7.1 容器经实际查询为 network_mode=none、restart_policy=no，命令含 server/dev 字面参数。这说明这个精确容器的配置，不证明没有 docker-exec 客户端、其他实例或备份。此前 Mac/ROG/Pocket4 路由身份验证和旧 4e808 的正式 34MiB、LAN98+12 冷重启结果仍保留为历史，5767739 的 Mac/X230/真实 LAN 验证全部待做。

## AuthBus 的实际阻断

唯一公共 Node 探针在 PID51494、父51483 下 SIGABRT 退出，stdout/stderr/进度 marker 均为空，探针未调用 SDK、凭证或 provider。固定崩溃文件完整 6,809 字节读入及身份围栏均已完成。七个非路径关联条件通过；procPath 的闭集字面形式为 /opt/homebrew/*/node，原实际路径比较仍为 false，未把星号的意义推断为事实。

R3/R4 均观察到 EXC_CRASH/SIGABRT、termination code2/flags582。R4 的 namespace 是字符串但未通过原大写字符限制，29 个固定诊断槽全部不存在，因而**原因仍未知**。诊断 job 正常结束仅证明读取闭合，不是 Node 或 AuthBus 通过。下一步准备一次足够定位的有限读取，包含该 namespace 的有界文本和唯一崩溃线程的公开符号栈；没有启动新的 Node 或业务探针。

旧私有 AuthBus 流程的进度未知仍保持未知。新的可信 issuer、真实 SDK AppRole/TLS/KV/Policy/续期/撤销以及客户端重启/回滚都未获得资格，不能用单纯凭证生成或测试 fixture 替代。

## 必须继续完成的门槛

1. 新候选真实构建、252/280 测试、严格 HTTP12 和 OpenBao 2.7.1 的候选侧对照；失败须保留并修复。
2. 同一最终候选在 Mac/X230 的正式 34MiB 迁移、恢复和存储重启回归；Mac/ROG/Pocket4 的真实断主、选主、ReadIndex、持久化及重启。
3. 不联系 J3160 的新可信 AuthBus 凭证来源及实际 SDK 全链路验证。
4. 已登记的 Mac/ROG/Pocket4/X230 客户端逐台完成真实凭证读写、重启、回滚和登记备份恢复后再切换。有限登记边界已用于规划；不会凭空增加“所有未登记手工路径”的无限扫描门槛。新观察到的真实消费者或恢复路径仍须纳入。
5. 全部迁移后才清除旧 OpenBao、旧 HeptaBao 服务/二进制与可再生中间资产。当前未执行清理。

数据库、Kubernetes、RabbitMQ 及既有记录中的远程认证、插件、seal/root/rekey、ACME/EAB 等能力缺口继续列为未验证。不能把所选业务路径通过宣称成全功能等价。

## 证据结构

[STATE.public.json](STATE.public.json) 是截止状态；[MOUNT-INDEX.public.json](MOUNT-INDEX.public.json) 逐叶记录全部挂载的 blob、字节数和 SHA256。所有 25 个挂载包的 898 叶、8,971,499 字节均已整读核对。原失败、纯准备错误及其修正、原始返回、观察器闭合和有限授权均保留。上一发布节点为 a693cc9d0062f6b1479ab6ee4a3d4f361b7fae52。
