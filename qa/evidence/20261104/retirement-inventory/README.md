# 四台主机的清理前只读盘点

固定脚本 `tools/production/inventory_retirement_boundaries.py` 的 SHA256 为
`7b3f7e3283bc472cbf138d5bc01f4e8a5359cd756a1c7ef0d91cd83287fd99fa`。
Mac、ROG、Pocket4、X230 四个实际作业均退出0，原始输出和权威终态完整保存。
没有读取凭证文件、进程参数或进程环境，没有改动服务或文件。

| 主机 | 服务相关路径候选 | 第一层备份路径候选 | 当前发现 |
| --- | ---: | ---: | --- |
| Mac | 7 | 34 | AuthBus启用，仍指向J3160地址；gateway与四个relay存在 |
| ROG | 9 | 33 | AuthBus启用，仍指向J3160地址 |
| Pocket4 | 6 | 7 | AuthBus启用，仍指向J3160；gateway为enabled但inactive；两个agent均在原顺序管理排除列表 |
| X230 | 2 | 5 | 旧OpenBao代理unit及其rollback文件存在；unit为disabled；固定2.7.1对照容器仍运行 |

共24条服务相关路径，包含目录和备份文件，不能称为24个已安装服务。
79条备份候选来自几个明确目录的第一层列举，没有递归检查内容，不能称为完整备份清单。
常用可执行文件目录中未发现匹配项，不表示T5、项目目录或容器内没有旧二进制。
Pocket4的Docker列表命令退出1，这一范围没有取得成功观察，不能把空结果解释为没有容器。

Mac、ROG、Pocket4当前地址均为 `https://100.66.117.33:8200`。
这些现存客户端与后续恢复流程尚未迁移，因此本次盘点不给予任何旧版删除资格。
X230的OpenBao2.7.1容器是差分验证基准，后续回归仍需使用，必须保留。
现存X230验证swap也没有被修改。

`root-review.public.json`逐项关联四台的实际作业、原始输出SHA256和候选数量。
同级 `retirement-<host>-*` 保存Mac、Pocket4、X230原件，本目录 `rog-*` 保存ROG原件。
下一步仍需补全其他实际客户端、精确识别旧安装用途，并验证各恢复入口使用新地址后才能进行最终清理。
