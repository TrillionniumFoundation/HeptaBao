# Linux combined 验证包：离线输入与隔离审查

此包保存了最终源码 `f80d2d54800ba7e932d91572c084f930af3e5714` / tree `667ae96b264c5e7f4b9290933612125d883b9e69` 的全部输入，以及 19 个唯一组件测试的隔离依据。**没有提交构建、测试或服务启动请求。** 当前只有本地离线组装、内容校验和源码审查。

## 当前硬门槛

ROG 只读预检作业 `1a1a93e525e-fc05-3335` 的启动结果仍未知。根任务对同一身份核对得到了 `launch_unknown` / `status_unavailable` 与远端 job directory 不存在；这些没有证明它未执行或已结束。这里没有创建新预检 key，也没有以其他平台、较窄 guard 或旧结果取代它。

`control/candidate-input.draft.public.json` 明确保持：

- `execution_enabled=false`，`unresolved_preflight_job` 仍为 3335。
- `mode`、`authoritative_preflight_resolution`、`current_toolchain_pins`、`current_resource_and_ownership_review` 和 `process_request` 均为 `null`。
- 没有实际开始时间或截止时间。3600 秒仅是新的独立候选控制包提案，包含 preflight、准备、格式化、strict、libtest 编译、命名测试和条件生产链接；不续用任何旧预算。3900 秒只用于外层监督与收尾，不延长成功资格。

## 完整源码输入

物理 Linux 基线仍以待重新核验的 `70714605c39014bea93545f7f6aa4217d2a23544` / tree `ef0ae63704a06b7dda1038e02abcc3233a2a438f` 为条件。

7071 → combined 是完整 **33 文件**变化：22 Rust、6 Python、5 历史 evidence 文件。不能只应用 21a 最后的三个修复。每份原文均从不可变 Git source 取回或按同一 Git blob 复用，已在本地重算完整 UTF-8 字节数、SHA256 和 Git blob：33/33 匹配，总计 **1,607,590 字节**。根任务另以完整树 delta 独立复算，结果亦为 33/33。

完整内容封在 draft 的 `source_files_gzip_base64` 中；gzip 原文 321,912 字节，SHA256 `e4105775e10727d556b334d871fd6641d179af4f35298bbdaa83d9f89e65d2bf`。解压后的闭合集合 JSON 1,667,491 字节，每个路径/内容都受 `control/combined-input-manifest.public.json` 绑定。此 gzip 仅为源码传输容器，不是产品 snapshot。

输入树必须在实际应用后精确等于 `667ae96b…`。之后只允许已声明的 22 Rust 路径产生 rustfmt 差分，必须保存实际差分并重新冻结实际物理 commit/tree；不能把格式变化后的源码仍称作原 review commit。原 62 文件与新 33 文件的并集为 84 个具体 pin，完整 Git tree/clean 检查仍另外执行。

## 19 项的真实范围

`control/critical-tests.public.json` 列出全部模块名、源码文件、函数位置和不可变 blob。旧的 `native_archive_rejects_truncation_concatenated_gzip_and_corruption` 已被分拆，不在本清单中。

| 类别 | 数量 | 网络与存储边界 |
|---|---:|---|
| FormalApiPipeline | 9 | 自建三 voter，Raft 与 API 均为独立 loopback 地址，私有 Root/PKI/合成数据 |
| 缺 API origin 拒绝 | 1 | 自建三 voter，HTTP 是实际 parser/Service/writer 的内存入口，故意没有 API origin |
| 纯协议元数据拒绝 | 1 | 无 socket、文件或子进程，不构造真实 receipt 权限 |
| 本地 unsupported owner | 1 | 私有 Service 与 bound loopback 假 provider，明确要求 provider 没有连接 |
| cold unsupported archive | 1 | 私有三 voter 与独立恢复 bundle，假 provider 无连接，拒绝时不发布目的状态 |
| 单 Service HTTPS | 2 | 每请求自建 loopback TLS；完整响应/EOF、worker join、私有目录和冷 reopen |
| outer archive Service | 4 | 无网络或子进程；私有 Service/spool，真实 restore、错误保真、冷 reopen |

前述 HTTP/Pipeline 请求仍使用原 15 秒预算。Outer 4 项沿原 Service 测试帮助函数的 30 秒 scope 与 test clock `now=100`，没有把它们改成或宣称为生产 HTTP 15 秒验证。第 19 项专门覆盖新增的 POST/PUT × snapshot/force 四种真实 HTTPS 204 空体、TLS EOF、历史回退与冷 reopen，不能由另一项单次 HA 204 推授。

全部测试都不引用 r10 的目录、固定局域网 peer、生产根或真实客户端凭证。控制器将为每个 exact libtest 子进程使用一个新的 0700 TMPDIR；Root 的 PID/序列或随机名称在这个私有目录下创建。测试中的 OpenSSL 子进程只生成自己的证书，继承原受控测试进程组。

这建立了**源码层面的功能隔离**，不是当前 ROG 的资源准入。原 guard 只处理配置 UID 下的 compiler/unit-test；普通 `heptabao-server`、`bao` 和 Python watchdog 不自动属于它的 active 集合。因此 timed 阶段必须另有当前 ROG fixture 归属结论，并重复原资源与互斥检查。Mac 的未知外层仅保留为 Mac blocker，不推断整个 LAN 永远不能做独立 loopback 验证。

## 下一版控制器的约束

只使用现有 ROG `source` 和 `cargo-target-normal`；原 r6 retained 二进制、源码 ref 和结果保留。新的 output/control/TMPDIR 必须不存在才创建。源码使用新的独立 branch，实际物理 commit 与 GitHub review alias 分别报告。

原 normal profile、原 guard 连续代码片段、严格 `--release --locked --offline` 和唯一 `--exclude qrcode` 保留。编译阶段可独立产出 `compile_only`，不得冒称 19 个测试或生产链接通过。完整模式只有实际 libtest `--list` 确认 19 名各一次后，才逐项 `--exact` 执行一次；已知失败保留后继续其他不同名测试，unknown/timeout/清理失败立即停止。任何失败阻止正式 server/seed 链接。

OwnedRunner 使用原未 reap 的直接子进程作进程组清理身份锚，先观察与收尾、最后 `Popen.wait`，不在 reap 后发送 group signal。编译/测试共用同一个绝对截止时间。每条命令记录原 argv、exit/timeout、原始 stdout/stderr 哈希、原子数目分母与 owned group 终态。

此版未包括控制器实际执行资格，也未证明 full workspace、正常 server HTTPS observer、物理三机 HA、X230 新候选全量迁移、切流或旧服务删除。普通 KV NoForward 与全局 TTL precision 的独立闭包仍未包含；native-disabled V5 sync 的错误优先级也仍无本清单覆盖。
