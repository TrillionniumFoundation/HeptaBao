# ROG 只读短时预检：待审，未发送

这份控制包只观察已知 ROG 工作区、工具链和当前进程。它没有创建或提交 Runtime 作业，没有启动 Cargo、HeptaBao、OpenBao 或任何测试。新的 combined 源码不在此动作中应用；基线必须仍为物理 70714605 / tree ef0ae637，原 62 文件逐一核验。

## 唯一拟请求

`control/preflight-exact-request.public.json` 是完整请求，`stdin` 与 `control/preflight-input.public.json` 逐字相同。请求使用 configured host `rog`、原 `/usr/bin/python3 -I -S -B -u -c`，不调用 shell。包内源码、原 guard 和原 frozen manifest 都有 SHA256 绑定。这里只保存请求；没有发送它。

观察期限从 bootstrap 开始固定为 60 秒，包括读取 stdin、哈希和所有检查。Runtime 监督期限为 90 秒。脚本不发送任何进程信号；只读 Git 子进程保持在原 Runtime 进程组中，以原 `Popen` 对象等待回收。观察失败后不再检查或重试，只允许等同一个子进程至 75 秒；若它仍未退出，保留父进程等待，由原 90 秒监督界限处理整个原作业组。该异常路径输出 incomplete，不会声称清理或准入成功。

## 读取与不变边界

- 读取当前 UID、实际 Linux 架构、hostname、boot ID；当前 Python、Git、Cargo、rustc、Clippy、rustfmt、OpenSSL 文件的 SHA256。这些是新观察，不能冒称已经与既往工具链 pin 相等。
- 两次实际 Git HEAD/tree/branch/clean 观察，中间核全部 62 个原源码文件。Git 关闭可选 index 写入、全局/系统配置、hooks、fsmonitor、untracked cache 和子模块递归；不允许交互，不运行用户 shell。
- 检查 source、target、旧 cache、Cargo home 的实际路径与 owner；对两个现有空 release `.cargo-lock` 只读打开，尝试一次非阻塞 flock 后立即释放。这个结果不是持续锁租约，也不保证未来 Cargo 准入。
- 保留原 r6 compiler 和 timed-test guard 的完整内嵌函数字节。原逻辑仍仅覆盖配置 operator UID，资源门槛仍为可用内存与盘各 32 GiB、1 分钟 load 不高于 CPU 数的一半；只有原精确 foreign Cargo 身份例外可以进入编译阶段，timed-test guard 没有该例外。
- 单独记录同 UID 的 exe、cwd、父 PID、start clock，及只落入我们的 source、target、cache、Cargo home 的 fd 路径。不读取其他进程 argv/env 或凭证内容，不停止任何进程，不扫描其他项目的文件内容。

原 guard 不把普通 `heptabao-server`、`bao` 或 Python watchdog 自动当作 unit-test。因此即使原 guard 返回允许，这个预检仍输出 `execution_admitted=false` 和 `timed_test_execution_admitted=false`。当前进程归属、资源与组件隔离证据须由随后控制包独立绑定；Mac 的未释放窗口仍保留，也不因此宣称整个 LAN 被无限阻塞。

## 原 guard 字节来源

原件为 Git commit `c1b2c50ef32a112149dc61bce1685972f32549b0` 的 `docs/evidence/20261104-unified-61ff-checkpoint-r1/controls/r6-exact-process-start-request.public.json`，blob `a60a0855b37237205840253c74c634a21855f765`。从其中 `args[-1]` 提取完整 guard docstring 起至 `exclusive_timed_test_admission` 结束的 11,400 字节，SHA256 为 `b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59`，在 `control/original_r6_admission_guard.py` 原样保留。旧回执所写 `108ea3…` 是其先前组件文件身份；这里不把该旧声明冒作当前内嵌片段的实算 SHA。

## 已完成的本地验证

`review/preflight-local-syntax.public.json` 记录三份源码的 AST/compile 成功、request/input/bootstrap 逐字绑定、无脚本 signal dispatch 调用。它只来自本地离线检查，没有执行封装的预检源码，不能作为 ROG 实际准入、资源、清理或构建结果。所有远端结果仍为空。
