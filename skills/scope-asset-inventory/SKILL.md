---
name: scope-asset-inventory
description: 整理已有目标范围；需要规范化 URL、IP 与 CIDR、去重并形成可追溯资产清单时使用，不进行网络探测。
category: 资产整理
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON input; Linux and Windows
---

# 目标范围资产清单

输入为 UTF-8 JSON 对象，`targets` 是 1–10000 个字符串的数组，文件上限 8 MiB，每项上限 8192 字符。接受 HTTP(S) URL、IPv4/IPv6 地址及 CIDR，不接受裸域名、嵌入凭据、区域标识或无效端口。

1. 从任务范围或已有资产记录导出输入文件，保留导出证据引用。此流程仅整理输入，不证明目标在线或可访问。
2. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/scope.json`。退出码 0 的标准输出为 JSON；退出码 2 的标准错误为 JSON，`target_index` 是无效项的零基索引。按索引修改原文件，错误不会回显目标值。
3. 检查 `assets`、`duplicate_count` 和 `urls_with_query_or_fragment_removed`。主机名使用小写 IDNA，默认端口省略，空路径转为 `/`；URL 的查询与片段被移除，不输出参数值。保留路径和非默认端口，不将路径大小写或尾斜线视为等价。
4. CIDR 中的主机位归零，IPv6 压缩；CIDR 不展开，单个地址与包含它的网段分别保留，不能把去重后的数量当成实际主机数量。
5. 将输出与 `input_sha256`、任务 ID 和原始范围版本一起保存。提交资产变更前检查网络归一化是否符合原范围，尤其是输入含主机位的 CIDR。脚本不写数据库、不修改文件、不发网络请求。

仅依赖 Python 标准库。参考：Python `ipaddress` 与 `urllib.parse` 官方文档，<https://docs.python.org/3/library/ipaddress.html>、<https://docs.python.org/3/library/urllib.parse.html>。本工作流与脚本由 ARTEX 编写。
