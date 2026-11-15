# AuthBus owned-source R2 公有证据核对

真实 driver 成功；原 wrapper 因事件标签不唯一保持失败。本记录只解释并绑定已有证据，没有重跑，也没有改动原回执。

## 原件及结果

| 原件 | 字节数 | SHA-256 |
|---|---:|---|
| [driver 公有回执](authbus-owned-source-actual-r2-public-receipt.json) | 78,725 | 20740bac22ae330a02e573bfe504feec4c5bce8699997eeb3c73377d31d35370 |
| [wrapper 公有回执](authbus-owned-source-r2-controller-public-receipt.json) | 2,115 | d0c98be6fcc5e41e6c83f28089fcf1030be808f9d22fba1acbaf049a162439ea |

driver exit=0、ok=true；293 条事件通过，292 个不同标签。wrapper ok=false 原样保留。逐项重算外层表达式，唯一失败叶子条件是名称唯一性；valid 和总 ok 因此为 false。全部实际值及冻结代码绑定见 [reconciliation JSON](authbus-owned-source-r2-reconciliation-r1.json)，SHA-256：c538266b6a3305be6043061a1ee3ae1d58eee4d4c7a27f839b8a44b5c0f24895。

## 两次捕获的依据

唯一重复是 actual_manifest_cas_race.captured_actual_token，原数组零基索引 72、73。冻结 driver 在 CAS race 中建立独立 competitor，capture() 按 [client, *secondary] 保存 bearer；收集时没有给标签加 ordinal。实际 action 记录两次 AppRole 登录及真实 HTTP 400 CAS 冲突。

全程 15 次捕获，经 dict.fromkeys(issued) 按内容去重后，仍实际执行完整的 15 组撤销前 200、撤销 204、即时拒绝 403、冷重启拒绝 403。这支持两个 race bearer 不同的**推断**，它们对应全部捕获的零基 ordinal 4、5。未读取 token 或 candidate 私密内容；没有删除第二条事件，没有放宽为接受任意重复标签。

## 可以承认的范围

main 上单节点新 native fixture 使用一个真实 owned source A，完成独立 coordinator、原 producer/follower SDK、AppRole、真实 TLS、KV/CAS、Policy 拒绝、崩溃恢复、SDK SQLite 备份恢复、CA 绑定回滚，以及同一 bearer 的实际 renew API。15 个捕获 bearer 与三个 fixture SecretID 全部完成撤销及冷重启拒绝。六次成功 plugin 调用记录了 37 条授权成功且未复用 session 的 TLS 观察。

来源 export receipt 固定 SHA 为 41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907；绑定 driver 中记录五次 owner 重验。最终重验 receipt SHA 为 2a5dbb05d5378c7b8c634cab90bcfe27cf579f1c1bc7d39e93cfaa09d7e763b0，owner、凭证、身份、配置及 inspector 摘要保持一致。本次没有另行打开来源 export receipt；JSON 区分了直接读取的公有原件与原件内记录的来源证据。

## 清理和未覆盖范围

最终原 Popen 的 kill/wait 成功，由冻结 finally -> instance.stop() 控制流与 driver exit 0 支持。该运行走 owned_process standalone 兼容分支，没有独立 Owner 收据、kernel birth 验证或最终主机进程清单，因此不声明全主机零残留或严格进程身份清理资格。fixture root token、unseal key、原 provider credential 及私有备份均未被本记录声明为已撤销或删除。

本记录不覆盖 OAuth refresh 所有权、provider 当前存活、真实 A→B 轮换、强制 scheduler、多机 HA、逐台生产切流、全部生产备份迁移或旧服务清理。原 wrapper 不因本记录变成通过。

## 生成与保全

authbus_owned_source_r2_reconcile.py 只读固定 SHA 公有原件及源码，断言准确 293/292、唯一重复索引、15 组 bearer 和三组 SecretID 向量，用 O_EXCL 写新文件。它不执行 QA、网络操作或凭证读取，不覆盖现有记录，并在写入前后重验所有原件字节。
