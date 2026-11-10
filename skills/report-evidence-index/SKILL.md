---
name: report-evidence-index
description: 编写报告前关联任务、发现与证据索引；需要保留原始处置状态、检查缺失引用和证据版本不一致时使用，不据证据数量判定漏洞成立。
category: 报告整理
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON input; Linux and Windows
---

# 报告证据索引

输入为 UTF-8 JSON，包含 `task`、`findings`、`evidence`；文件上限 16 MiB，两个数组及单个发现的引用数组各不超过 10000 项。输入由已有任务与证据清单整理而来，脚本不会连接平台或读取证据正文。

1. `task` 包含 `id` 和原始 `status`。每个发现包含 `id`、同一 `task_id`、`status`、非负整数 `evidence_version`、`report_evidence_version` 及 `evidence_refs`。引用包含 `snapshot_id` 和 `role`，角色为 `baseline`、`proof`、`verification` 或 `supporting`。保留平台真实状态，不能为导出方便把 pending 改成 confirmed。
2. `evidence` 每项包含 `id` 与经实际读取检查得到的 `status`，可为 `available`、`missing`、`unreadable`。不要仅因数据库有引用就填 available。标识可为正整数或最多 160 个字母、数字及 `_.:-` 字符，不填 URL、凭据或正文。
3. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/report-data.json`。退出码 0 的标准输出为 JSON。退出码 2 的标准错误 JSON 描述文件、形状、重复标识、跨任务引用或状态错误。纠正输入再运行；脚本不更改平台记录。
4. 检查 `report_stale`：两个证据版本不一致表示报告需要重新核对。检查每个 `evidence_refs` 的状态，清单中不存在的引用标为 `unknown_reference`；这与已确认丢失的 missing 区分。`unreferenced_evidence_ids` 仅标明清单里未被引用的项目，不能据此删除文件。
5. 将索引、`input_sha256`、导出时间和原记录引用关联到报告。`finding_status_counts` 按真实处置状态统计，包括误报、忽略、重复及风险接受；不把这些合并为确认漏洞。支持的发现状态与平台一致：`pending`、`in_progress`、`confirmed`、`resolved`、`fixed`、`false_positive`、`ignored`、`duplicate`、`risk_accepted`。

输出仅保留上述索引字段，不包含摘要、请求头或证据正文。available 只说明提供的可读取状态，不能证明证据有效或独立验证成功；confirmed 也只是忠实引用输入，报告结论仍需证据核验。依赖只有 Python 标准库。字段依据本仓库的发现状态和流量证据绑定；摘要算法参考 <https://docs.python.org/3/library/hashlib.html>。工作流和脚本由 ARTEX 编写。
