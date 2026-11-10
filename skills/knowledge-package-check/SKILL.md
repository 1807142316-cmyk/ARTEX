---
name: knowledge-package-check
description: 在知识库导入前检查 JSON 内容包；需要核验来源版本、字段长度、重复编号和正文哈希且不修改数据库时使用。
category: 知识整理
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON input; Linux and Windows
---

# 知识内容包预检查

输入是知识导入接口对应的 `{"items": [...]}` UTF-8 JSON，对象只接受 `items`，1–100 条，文件上限 16 MiB。条目字段为 `code`、`category`、`kind`、`tier`、`summary`、`body`、`source_url`、`source_version`，均为字符串。编号、摘要、正文、来源 URL 与来源版本必填；本内容工作流比接口对来源的最低要求更严格，以便追溯分发版本。

1. 记录原始材料来源、许可与版本后编写内容包。`source_url` 必须是无嵌入凭据的绝对 HTTP(S) 地址；它只用于来源记录，脚本不会下载或认证来源。自编条目使用可追溯仓库地址及提交或发布版本。
2. 运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/knowledge.json`。退出码 0、标准输出 `valid: true` 表示本地包结构通过检查。退出码 2 时读取标准错误的 JSON，按 `item_index` 和 `field` 修正；错误不回显正文或来源 URL。
3. 字段上限依次为编号 160、分类 120、类型 120、层级 80、摘要 4000、正文 80000、来源 URL 8192、版本 240 字符。编号折叠空白、其余字段去除两端空白；编号比较忽略大小写。NUL 与孤立代理字符被拒绝。
4. 检查 `duplicate_bodies`，用零基索引回查可能重复条目，判断保留、合并或修订；相同正文不必然相同知识。重复编号是错误，避免导入时发生编号冲突。`content_sha256` 按知识版本字段顺序计算，`body_sha256` 只计算规范化正文。
5. 输出与 `input_sha256` 一起保存。检查仅覆盖这个输入包，不与现有库比较，也不证明内容正确、来源可分发或条目已验证。脚本不修改文件、不导入条目、不改变发布状态。随后通过平台导入接口创建草稿，按正常验证、脱敏审核与发布流程操作。

依赖只有 Python 标准库。字段依据为本仓库知识导入接口与 `db/knowledge.go` 的规范化和版本哈希；摘要规则参考 <https://docs.python.org/3/library/hashlib.html>。工作流和脚本由 ARTEX 编写。
