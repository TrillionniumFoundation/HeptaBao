# 两个真实来源的最新上游结果：受管 1 为 401，native 4 为 200

这份证据核对 **两个不同账号来源**。复核结果一致，不代表两个 provider 测试都通过。

| 来源 | 实际作业 | 唯一 GET 结果 | 当前资格 |
|---|---|---|---|
| ROG 受管 profile 1，来自此前 HeptaBao 恢复后原 SDK 的实际选择 | `rog/1a1a750676e-fc05-2af5` | TLS 验证通过，HTTP 401 | 上游返回 `token_expired`，当前不可判为可用 |
| ROG 原 unmanaged native user profile 4 | `rog/1a1a7514ff4-fc05-2afc` | TLS 验证通过，HTTP 200 | 此次只读 usage 请求可用，仍保持 unmanaged 身份 |

两次均由固定已安装 SDK 的 usage 函数构造请求，使用它给出的 bearer 与 account header，目标仅为 `https://chatgpt.com/backend-api/wham/usage`。各执行一次，未知结果 0、重试 0。没有 OAuth refresh、新登录、模型请求或 J3160 访问。

## 来源绑定与失败的含义

受管 1 的凭证摘要仍为 `bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1`，与此前 V6／SDK 冷恢复的实际选择完全一致。当前 SQLite 来源、私有 SDK 选择、请求 header 与响应后的来源再次核对均吻合。原 236 个存储／SDK／回滚断言并未因此失效；它们不包含当前 provider 有效性。

334 字节的原 401 响应在主机私有文件中持久化后才交给 SDK 解析，SHA-256 为 `2dd8af6137cc2b1f408e76a00ccf6479db404b03f3d383befcb5bc67c3ba2cce`。后续断网、只读分类仅公开白名单错误码：`error.code=token_expired`、`detail.code=token_expired`、`error.type=invalid_request_error`。没有公开原响应、账号或凭证。JWT 中尚未到期的时间不能推翻服务器实际返回的 401，也不能据此把原因归给 HeptaBao。

native 4 的摘要为 `63a40b812af24584847961eeaff54e780eacc66625970ee40ea2d9b1e0a70398`，与原 user home 的 native auth 文件及 SDK 第 3 条记录的账号、access、refresh 三者一致。它与受管 1 是不同身份。此次 200 不能证明受管 1／2 健康，不能据此将 native 4 纳入 canonical managed 集合或改变默认账号。

## 执行边界

生产目录与代码保持内核只读，只有各自新建的私有 case 目录可写。继承原主机网络，不修改 VPN、代理或模型配置；实际 PID 命名空间在两次请求后均退出。15 个冻结输入与生产网关 PID 2436 在各次观察前后保持不变。

请求 ledger 在 GET 前 fsync。原响应在 SDK 解析前 fsync；秘密值、账号身份与实际额度数值不进入公开结果。SDK 网络请求使用 18 秒 AbortController，socket 使用 15 秒无活动超时，整个子进程上限 35 秒；这里没有宣称完整流程都受单一 18 秒绝对截止限制。

先前 r2 在任何 provider 请求前因 SDK 临时目录不可写而失败，requestCount 为 0、ledger 不存在。该失败与断网诊断完整保留。r3 只为正式 SDK 的临时目录契约提供新 case 内的 0700 `TMPDIR`，主机 `/tmp` 和其他生产目录仍保持只读；随后先通过无真实 token、断网预检，再提交上述两个独立请求。

## 尚未获得的资格

本轮未证明 managed 2、全部账号、模型调用、OAuth 刷新所有权、native factory retire／reopen、生产网关重启或流量切换。两次结果只适用于 ledger 中记录的实际时间和精确代际。

原始清单包含 27 个本目录文件和 11 个依赖，含早期失败以及固定 SDK usage／tmp 源码。根复核逐字节检查清单和原 SDK 回执，重算 98 个证据一致性断言，并独立检查阶段 pins、两个原始 intent 和计划。

```sh
python3 qa/evidence/20261104/authbus-fresh-source-61ff-r3/root_review.py
```

输出明确区分 `evidence_consistent=true` 与 `all_provider_cases_passed=false`，不会把成功整理失败证据误写成 provider 成功。
