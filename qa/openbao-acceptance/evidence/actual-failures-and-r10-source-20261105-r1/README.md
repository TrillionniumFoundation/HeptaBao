# HeptaBao：实际构建失败与 R10 源码修复检查点

本检查点不授予正式 KV2、物理 HA、AuthBus、流量切换或完整替代资格。正式 DR25 实际执行仍为 0。

## 已取得的实际证据

| 对象 | 实际结果 | 本包范围 |
| --- | --- | --- |
| Mac R6 | 普通 release 的 Cargo 退出 101 | 原 worker、终态、完整执行器输出、构建结果及编译器 stderr |
| Mac R8 | 普通 release 的 Cargo 退出 101 | 原编译错误与执行器闭包；与 R6 分开保存 |
| Mac R9 | 普通 release 退出 0；server libtest 退出 101；整项构建失败 | 两个原阶段回执、完整错误、原 worker 与完整执行器输出；没有运行 181 或 observer16 |
| Pocket4 R9 | 本检查点取得的是原作业正在运行的观察 | 原 worker 身份、真实 8 GiB cgroup、源码准备结果、旧候选 12 个固定文件前后相同；不代表最终构建结果 |
| R10 | 已发布一个仅增加测试初始化字段的提交 | 原 Git 文件、完整候选、补丁、独立审查、原 Git 发布对象；不是构建或测试通过 |
| R5 matched27 | 保留既有失败结论 | 新取回的原 worker request/started 补充；不改变写入效果未知的结论 |
| R5 历史客户端 | 已取得原冻结字节 | 精确 `71a817…` 严格 TLS/HTTP 204 客户端及原 preparation；没有替换成内容不同的 Git 版本 |

R9 普通服务保留二进制 SHA-256 为 `50ecac89156c862e6111f1460ed8f73b4872c61a9ef7fd9a9e4bc640f5981b73`。本检查点验证了它在原阶段结果和执行器输出中的绑定，未把这一阶段成功视为整项构建成功，也未由 root 在本地重新计算远端二进制散列。

R10 为 `b33b8d0de9c7689ff89f8ed11cd2151726972f4f`，tree 为 `89a8af5b7bcb1d7472e1f12e1dec7adb7d2cf726`，唯一父提交为 R9 `fa37c0fc6f28317d5f432bbbc2bbae062c4be064`。唯一变更是在原短写错误测试的 `ResponseWriteObservation` 初始化中增加 `status: None`；原断言、生产代码及预算不变。

## 明确保留的缺口

`scope.public.json` 列出完整缺口。此包尚未包含 R6、R8、R9 的四份完整原 Cargo stdout，以及 Pocket 源码准备作业的完整原 527 字节输出。R9 Pocket 终态不在此初始观察检查点中。后续取回的原件应作为补充证据保存，不能覆盖或改写原失败。

R7 异步读取操作的原始失败返回也被保留；读取失败不等于被读取的 control42 测试失败。该测试的实际终态仍需独立读取。

R10 物理 128 用例的父适配器仍为 `DRAFT_ONLY=True`，仅派生源码和路径绑定，函数 AST 保持不变。新的三机 owner21 没有提交，物理产品测试没有执行。

## 独立校验

将本目录中的 `manifest.public.json`、归档及 `verify_archive.py` 放在同一目录，执行：

```sh
python3 verify_archive.py
```

校验器检查归档原字节 SHA-256、全部成员名称、长度和 SHA-256，不启动产品或访问任何主机。`build_checkpoint.py` 保留原打包方法，归档曾被确定性重建并逐成员解包比较。主分支和旧服务均未修改。
