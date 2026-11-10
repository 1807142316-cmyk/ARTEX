---
name: har-api-inventory
description: 从已保存的 HAR 流量整理 API 接口；需要按来源、路径、方法汇总调用次数与响应状态分布且不输出请求凭据和正文时使用。
category: HTTP 证据分析
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline HAR input; Linux and Windows
---

# HAR 接口清单

输入为 UTF-8 HAR JSON，顶层 `log.entries` 是数组，上限 50000 项与 32 MiB。每项需要 `request.url`、`request.method` 和 `response.status`。空数组允许，表示没有观测到请求；不是采集成功证明。

1. 导出已有浏览器或任务流量，记录采集时间、任务 ID 和原证据引用。该流程只读取文件，不重放请求。
2. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/traffic.har`。标准输出是 JSON，退出码 0 表示清单已生成。退出码 2 时读取标准错误 JSON；`entry_index` 指出无效记录的零基索引，不回显原始 URL、头或正文。
3. 使用 `endpoints` 的 `origin`、`path`、`method` 识别独立接口，`count` 和 `status_counts` 描述本次采集实际观察到的行为。状态 0 保留为未获得 HTTP 状态，不能当作成功。路径与方法大小写保持原样，HTTP 方法区分大小写；参数、片段被移除，默认端口归一化。
4. 输出不包含 Cookie、Authorization、查询值、请求正文、响应正文，也不读取这些字段作为结论。嵌入凭据的 URL 会使整个处理失败。路径仍可能含用户标识或业务数据，分享前根据任务的证据管理规则检查路径；不根据字符串样式臆测或删除路径段。
5. 将 `input_sha256`、原证据引用、采集范围与清单一起存入报告材料。接口未出现只说明 HAR 未观测到，4xx/5xx 或接口出现本身不能确认漏洞；后续验证必须保留独立证据。

依赖只有 Python 标准库。参考 HAR 1.2 格式：<https://www.softwareishard.com/blog/har-12-spec/>。工作流与脚本由 ARTEX 编写，不复制上游内容。
