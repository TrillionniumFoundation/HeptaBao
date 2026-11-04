# SSH r5：实际测试通过，仍不可推广

ROG 上固定源码 `830f28505af7306bab898a648918a65a9e3e8c60`、tree `112394355eb52c4f88e90a0eea40e3a8ea6daef4` 的普通构建实际执行了 22 项 SSH 测试，22 项通过、0 项忽略，其中 3 项覆盖 HA。这里的 HA 是同一测试进程创建的实际 HA fixture，不是 Mac、ROG、Pocket4 三台物理主机的部署验证。

已独立读回完整测试 stdout、stderr、测试清单和精确 Cargo 编译产物记录，并核对回执 SHA256。编译产物明确启用默认 `native-v6-storage`、`native-v6-ha`，未启用诊断 fixture；release 优化级别 3，debug assertions 和 overflow checks 均开启。编译 1350.30 秒，测试 41.94 秒。所有阶段退出 0、未超时、所属进程已结束，原源码和保留的二进制均未改变。

保留的 libtest 二进制 SHA256：`6026cd5d54d63a9ec13dcf28c37536afb866ea6d0e76a2f6c3ccdbdcb5073470`。durable job 为 `rog / 1a1a688e298-fc05-2698`，根任务再次读取其终态为 succeeded / exit 0 / output complete。

## 仍阻止推广的问题

r5 的 HA 原始响应协商使用 `GET */public_key` 后缀选择。这也可能匹配普通 KV2 同名键，使大体积 KV2 响应走错帧格式。后续候选必须在转发两端核对实际挂载的 SSH 引擎类型，并验证普通 2MiB KV2 同名键、伪 raw 字段、自定义 SSH 挂载以及错误协商拒绝路径。静态检查或其他工作线程的候选文件不能替代本候选的实际执行证据。

本回执不代表完整 OpenBao 2.7.1 替代、物理三机 HA、正式流量切换或新组合候选通过。没有生产服务被修改。

## 复核

运行 `python root_review.py` 可核对本目录完整运行流、编译产物特征、逐项清单与执行一致性、原始回执、durable job 终态及未关闭的推广门槛。

完整编译 stdout 未下载，本目录保留精确 compiler-artifact/build-finished 记录以及整个编译流的 SHA256。完整编译 stderr 的一次远端读回遇到 SSH 断开，未重跑；成功编译的原回执及 stderr SHA256 保留。运行期 stdout 和 stderr 均完整读回并验证。

`source-chain` 保留从已发布等价基线 `054d17cd50951efa46d78db3911ad1d277a0c584` 到 r4、再到实际 r5 的两份补丁及源文件清单。根任务再次只读检查 ROG r5 工作树与 git blob，19 个修改文件均与本地源文件字节一致；第二份补丁还实际重建了最终 4 个更改文件，SHA256 与执行源码一致。
