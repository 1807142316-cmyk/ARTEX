---
name: evidence-inventory
description: 为本地任务证据生成文件清单、字节数和 SHA-256；需要报告交付清单、备份核对或跨阶段证据完整性检查时使用。
category: 证据整理
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; local files only; Linux and Windows
---

# 证据目录清单

输入为已有证据目录，输出每个常规文件的相对路径、大小与 SHA-256、总字节数及跳过的符号链接。不会读取内容到输出，也不会上传文件。最多 10,000 个文件、合计 1 GiB。

1. 固定需要交付的目录内容；停止向其中写入。确认目录已经按任务隔离，文件名也不能包含不应复用的凭据。
2. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/evidence > /path/outside/evidence-manifest.json`。输出文件必须在输入目录之外，避免把正在生成的清单纳入自身。
3. 退出码 0 后保存 JSON 清单。退出码 2 表示路径、权限、上限或读期间变化错误；修复后重新生成完整清单。链接会记录到 `skipped_symlinks`，不能将其报告为已包含的证据。
4. 需要核对备份时，对恢复目录运行同一命令，比较路径、字节数与哈希；目录绝对位置不参与输出。对不一致项核实原件，不能把清单自动视为真实性证明。
5. 在报告中引用清单路径及任务，明确缺失或跳过内容。清单不包含文件正文，检查和脱敏仍由原任务流程负责。

依赖只有 Python 标准库，无 MCP。SHA-256 行为依据 Python hashlib 文档：<https://docs.python.org/3/library/hashlib.html>。本包工作流及脚本由 ARTEX 编写。
