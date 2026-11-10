---
name: saved-header-review
description: 分析已保存的 HTTP 响应头证据；需要检查安全响应头缺失、保留证据哈希并给出配置复核建议时使用。
category: HTTP 证据分析
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON input; Linux and Windows
---

# 已保存响应头复核

输入为 UTF-8 JSON 对象，含 `url` 字符串与 `headers` 名称到字符串值的映射。使用已记录的一次响应，不为本流程发送网络请求。上限 4 MiB。

1. 确认输入记录了响应来源、采集时间及任务证据引用。必要时从现有流量记录导出单条响应，Cookie 和凭据保留在任务证据存储中。
2. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/headers.json`。退出码 0 表示分析完成，标准输出是 JSON；退出码 2 的标准错误提供输入或文件错误，纠正后重跑。
3. 将 `evidence_sha256` 与原证据引用一起保存，检查 `missing`、`checks` 与 `warnings`。HTTPS 才将 HSTS 列为适用。输出不包含 Cookie 或头值。
4. 对缺失项查明代理、CDN、应用及页面类型的实际配置。检查 CSP 的完整策略和页面行为；仅存在 CSP 并不证明有效。HSTS 应在 HTTPS 正确部署后配置，`nosniff` 应与正确 MIME 类型配合，Referrer-Policy 应按信息披露要求选择。
5. 输出可追溯配置观察：证据引用、哈希、适用性、缺失项、人工复核结果与修复建议。未完成上下文验证时保持候选状态，不能由头缺失直接确认可利用漏洞。

依赖只有 Python 标准库，无 MCP 或额外网络工具。路径中的空格需要引号。参考依据：OWASP HTTP Headers Cheat Sheet，<https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>。本包工作流及脚本由 ARTEX 编写，参考链接用于依据核验。
