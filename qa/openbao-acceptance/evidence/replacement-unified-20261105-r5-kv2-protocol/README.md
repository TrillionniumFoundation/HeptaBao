# R5 正常 KV2 与严格协议对照的实际证据

本目录只记录冻结源码 `1f188df0f2affebb92702222e9fe5dfb4712194c`、树 `74bcb2b2af2fc9d349f007cd847fc2f16c08c01a` 的实际运行。Mac 正常服务二进制 SHA-256 为 `8b42f0a6bc2de0647e558c065f517b52736c208b619902943663fe4a768f44d0`。

## 已观察的结果

| 实际运行 | 结果 | 证据边界 |
| --- | --- | --- |
| `mac/1a1ab90bddc-fc05-4ead` | 正常 `native_v6_file`、新建合成 OpenBao 2.7.1 源，原 31 项 KV2 检查全部通过 | 包括导入、历史/API/存储核对、冷启动、快照回滚、软删除/销毁/CAS；未迁移真实凭证，独立完整冷备恢复 25 项尚未执行 |
| `mac/1a1abaa7b24-fc05-4f84` | 同协议 KV2 对照失败；6 项守卫通过、21 项缺失 | 官方 OpenBao 的建挂载请求收到严格 204 响应；HeptaBao 对应请求传输结果未知，没有重试；不能推断其写入效果，也不能比较完整负载性能 |
| `mac/1a1abc19672-fc05-504e` | 独立诊断完成，但产品传输被拒绝 | 新建未初始化实例，仅发一次无凭证 GET 健康请求；收到完整 204 字节 HTTP 204 后发生 `SSLEOFError / UNEXPECTED_EOF_WHILE_READING`，没有认证的 TLS EOF |

第三项的执行器 `succeeded/0` 表示诊断材料收集完成。其产品判定仍为 `transport_accepted=false`。诊断没有重试先前的建挂载请求；先前请求的效果仍为未知。

## 独立读取与存档

`r5-kv2-and-protocol-evidence.tar.gz` 包含实际 API 原始返回、完整终态和输出、实际文件原字节、诊断控制器及归档复核脚本。`manifest.public.json` 逐文件记录大小与 SHA-256。打包后重新打开归档，逐文件比对原始字节。

31 项运行和独立 TLS 诊断均检查了原始 worker request、started、nonce、请求摘要、执行器终态及完整 stdout/stderr。31 项公开 summary 由原始 binary_read 分块重组并逐块核验，保留原始整数精度。

同协议失败的原始启动 API、执行器终态、完整输出、结果、对照记录和进程回收记录已经取得；其独立 worker `request.json` 和 `started.json` 尚未复制到本归档。因此该项只作为有明确来源的失败记录，不授予完整阶段准入。后续补齐须形成追加证据，不能修改已经存档的失败内容。

归档控制器第一次验证因误把实际 `log_bytes.{stdout,stderr}.{seen,stored}` 当作标量而失败；该本地验证错误也已保留。修正的是解析器的字段形状，产品结果与原始 API 字节没有改动。

## 当前不能批准的事项

完整冷备恢复、真实多节点 HA/ReadIndex、AuthBus、真实凭证与依赖客户端、逐机切流、旧版删除以及完整 OpenBao 替代均未通过。本目录不授权这些后续动作。各阶段须依次由实际运行取得独立证据，后续源码版本不得复用本版本的通过结论。
