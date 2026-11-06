# A R4 公共 home→T5 探针：独立窄 SOURCE peer

结论：在本次限定的源码与绑定范围内未发现新增阻断。实际执行了 252 项独立 V8 字节、差分及定点准入检查；没有执行候选、Python、作者 checker 或 Runtime。输入树 690747178bd9d66eedca0e704719727bd4cd5a3a 的 28 件已整件核对。此结论不授予执行 GO。

## 精确变化与原行为

constants 的唯一一处 hunk 只新增 KERNEL_PYTHON_IMAGE；common 的唯一一处 hunk 只将 validate_process 的 executable 等式右侧从 PYTHON 改为该固定值。身份形状、整数类型以及 pid/pgid/uid/birth 五个数值判据均为原字节。journal 两处 hunk 仅新 slot、exact request pin 和 observer key 前缀。

对 controller 和 managed child 进行独立逆替换，并恢复原 child base64/bytes/SHA 后，两整件分别精确等于原 R3 bf69252fe9a2431ccf09740d5e5bed7eb6231248（168464 B）和 2649636d559f401a5068de2b92ed3bf7d6db7d72（36358 B）。parent-core 原含一个前导换行的 31586 B 整件命中 8ee0b29ea750d1b752b8ab26e27914a377dc61dd。原父核心、嵌入 helpers、Signals、FD登记与整个 close 循环 critical、HeldT5 初始化完成记账、finally 判定均无变化。该字节证明承接原已审逻辑，没有再次宣称完整运行资格。

原 sys.executable / Native executable / launchd ProgramArguments 的 PYTHON 路径保持；原 regular launcher full9、whole SHA、只读 FD 准入也保持。新增路径只作为原 ProcessReader 返回值的等式比较右侧；没有新增备用路径、前缀匹配、fallback 或该 kernel image 的文件读取/授权。

## 新路径证据与限制

fresh self 的原 stdout 4e28d3301fa4409b06efe23bd9834779173aaa71（2453 B / 66b796413137843516dcd2398c8827036a5f312e65353e653b86df2456237d1d）中，两次原 reader 对同一数值身份与 birth 返回的 publicExecutablePath 均逐字等于新常量；五个原数值判据为 true，原 executable==launcher 判据为 false，sysExecutableEqualsFixedLauncher 为 true。该证据支持本次精确路径分离。它不是 kernel image 文件 full9/SHA 证明，也不反向补造原 R3 未输出的字段或启动原因。根已给 fresh self 的独立资格 110d8f083a05e5cb478fdb60917d0406b54bc276；本 peer 没有重审该实际观察链。

## 准入和预算

main 中 io.absent(HOME)、io.absent(WORK) 和 fresh_label_initially_absent 都在首个 mkdir 之前。原同一 fresh roots / label 不因旧 R3 早期失败获得可重用资格；实际一旦存在仍拒绝，mkdir 竞争、无符号链接、固定名称与权限检查均保留。父45秒、child父锚定25秒、helper35秒准入、外壳60秒不变；child自己的30秒初始上界仍必须收窄到原父绝对截止。无新恢复或自动重试。

精确 request 158c70818b4cab3e39f87c31a5075a35e25dab6c / 170971 B / 34115f596b8942341d1eb6f89fd86aa2371bc44fba31ca53d1c51e280d1828ee：host mac、原 regular PYTHON、[-I,-S,-B,-]、cwd /Users/qianqi、stdin 全文等 controller fb453c023c1de1299e1875078ae8720b20a441de / 168844 B / 87ddc49599abfd6b09b023287fbeefe1e0c833c1b806cf9c753755f706eaaa6c、outer60。journal 03e72b0bd32b4fe9219b98b0c6d4dab57182bead 对其整件 pin 精确绑定；新 slot 未在本审初始化。

此 peer 只核 SOURCE 变更和公开 fresh 观测的引用。实际 launchd managed child 能否从 home 进入 T5、真实 registration/FD/期限闭合、旧 UNKNOWN、Auth/SDK/凭证及产品替代资格均不在本次结论内。
