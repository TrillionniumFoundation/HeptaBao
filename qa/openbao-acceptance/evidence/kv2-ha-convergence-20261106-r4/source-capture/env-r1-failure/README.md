# Mac 独立 Python 环境 r1：保留失败原件

本包记录新环境的第一次真实准备，不改变原 DR、产品或业务资格。

1. 固定5输入阶段 job 1a1b172e794-fc05-78d2 实际 succeeded/0，0.009077 秒；按原52/60预算create-only上传并逐字回读，未安装。
2. 安装启动首个 MCP 调用发生响应超时。原错误保留；使用原请求、原幂等键对账，返回 reused=false 的 job 1a1b17696b2-fc05-78ea。不能据此声称此前传输未到达服务器；本包只认权威幂等身份对应的这一作业。
3. 作业实际 failed/1，未到 Runtime 180 秒超时，未取消。固定控制器在20.033305秒触发首wheel原20秒截止。仅留下pip26.3的65,536字节partial（应为1,950,951字节）；其余3wheel未创建。固定控制器只在HTTP200、精确URL及正确Content-Length之后打开该文件，因此观测闭合到响应体阶段。没有证据进一步断言代理原因或整个域被封锁。
4. 0个子步骤、0个子进程、0个venv/包安装；18个Darwin控制未执行、不可准入。业务数据库、provider、J3160、服务、仓库requirements均未触及。

原失败目录和partial留在Mac。本包公开固定stdout、权威terminal、MCP错误与partial/缺席metadata；完整start/request原件包含Runtime内部账号路径，留在相邻restricted目录，不发布。没有真实凭据内容或凭据猜测指纹。所有新后继传输/环境必须独立建根、独立预算及结果，不能把本次失败改成通过。
