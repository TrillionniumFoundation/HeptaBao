# 真实 systemd 常驻服务与原始 SDK 的同场景验证

ROG 上的实际任务 `1a1a68f04ec-fc05-26de` 已正常结束：58.939 秒，退出码 0，1,107 条动态检查全部通过。共 1,106 个不同检查名称，其中 689 条为服务管理器观察及其断言；这些数字包含运行期间的重复观察，不应解释为 1,107 个独立功能场景。

这次验证把实际安装入口、真实 systemd 系统服务、原始 OpenClaw 2026.7.1-2 SDK 和正常构建 HeptaBao 放在同一隔离场景中。产品源为 `33cafa4c6e29f0bde1553e041550d21b4c725d9c`，tree `cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`，Linux 二进制 SHA256 为 `7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`。使用 `native_v6_file` 和正式 `sys/storage/native-v6/activate` 入口，没有启用额外测试 feature。

## 实际覆盖

原先 330 条检查的名称与通过结果完整保留。组合场景共有 16 次真实 SDK 运行：13 次正向、3 次预期拒绝；80 次正向 HTTPS 观察均独立完成完整 TLS 握手并验证同一服务器证书。凭证世代从原入口 API 的 A/B，延续到常驻服务发布的 C，以及提交后退出 73、服务器冷重启、管理器恢复后的 D。

systemd 实际安装临时系统单元并以 UID/GID 1000 运行；独立的只读进程观察核实代码和配置在真实挂载视图中只读，状态目录可写。`systemctl restart` 产生不同 PID 和 InvocationID，并确认旧身份消失。恢复过程沿用原 owner、锁和持久化状态，实际清理 pending，未重放已经提交的 manifest。

同一场景还保留真实 CAS 冲突、三个服务器 SIGKILL 冷启动、SDK SQLite 备份恢复、错误 CA/绑定拒绝和绑定回滚。27 个已捕获的实际签发 token 被撤销，冷重启后仍拒绝；三个 SecretID 被销毁。续期调用真实 renew-self API 并保留同一 bearer，但测试只推进了客户端本地的到期调度时钟，没有等待完整租期。

清理记录绑定到实际安装的 root 单元文件 inode、SHA256、UID/GID 和 mode，删除的是同一文件。终态为单元 not-found/inactive、MainPID 0、runtime 文件消失、无本场景遗留进程。产品源、构建、SDK 和插件的精确哈希前后相同；观察到的三个现有生产配置/凭证文件的哈希前后相同。该边界仅指被明确观察的文件。

## 保留的失败与尚未关闭的门槛

`retained-r1` 保留输入前缀错误造成的 SDK 拒绝。原 consumer 的 synthetic-only 保护未被修改，后续仅修正测试输入。

`retained-r2` 保留一个真实客户端缺陷：生产者尚未确认 canonical C 就生成本地 D 时，原插件把 D 覆盖成 C，未发布 D 事件。公开收据保存了 before/after 凭证摘要和 `publishedEvents=0`。r3 按既有 A→确认→B 协议，在生成 D 前实际确认 C，因此本次通过**不证明未确认连续轮换安全**。此缺陷正在独立修复，未更改生产安装的插件。

本次捕获并撤销的 27 个 token 不包含常驻 manager 进程内未暴露的 bearer。SecretID 销毁后的 manager 冷启动拒绝已经验证；daemon 原有会话 token 的撤销仍是独立缺口，不能混称已经覆盖。原 transport 将失败登录保守分类为 `mutation_outcome_unknown`，manager 按原协议退出 3，6 秒观察窗内没有自动重试，也没有进入 KV 写入。

所有 provider 凭证为合成值，没有调用 provider 或 J3160，也没有切换生产客户端。这份证据不证明 provider 凭证存活、OAuth 刷新所有权、强制刷新调度或 OpenBao 2.7.1 全量替代。

## 复核与重现

完整结果 `public-receipt.json` 为 335,452 字节，SHA256 `223a2ba21c5cf448e3aa4479a11fe8daf86151fb93f536466b521176d541b68e`。保留完整驱动、adapter、原安装入口/核心、单元辅助器、源哈希、外层观察、原始失败、实际任务终态及独立根审。

运行 `python root_review.py` 只会读取这些证据并输出核验结果，不发送请求、不启动服务、不重放任何操作。它同时确认已通过的组合范围和两个仍为 false 的资格字段。
