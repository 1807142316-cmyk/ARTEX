---
name: sshd-effective-config-review
description: 离线复核 sshd -T 有效配置；需要检查登录方式、空密码、转发、认证次数及日志配置并保留未知字段时使用。
category: 主机配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; saved sshd -T JSON; Linux and Windows
---

# SSH 服务有效配置复核

输入 UTF-8 JSON，`effective_config` 是已经保存的 `sshd -T` 标准输出字符串。文件上限 1 MiB、文本最多 512000 字符。采集时保留 OpenSSH 版本、配置路径和 `-C user=...,host=...,addr=...` 上下文，分别采集重要 Match 条件；脚本自身不连接服务器或执行 sshd。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/sshd.json`。退出 0 输出 JSON；退出 2 的标准错误 JSON 表示格式、重复检查项或值不符合有效配置格式。Include/Match 源指令会被拒绝；脚本不推断默认值、不处理配置源文件、不会回显用户列表等未检查字段。

复核 `checked_values`、`issues`、`unknown_checks` 并关联 `input_sha256`。当前检查根登录、密码及交互认证、空密码、公钥认证、X11/TCP 转发、MaxAuthTries、PAM 是否已知及日志等级。MaxAuthTries 大于 6 是复核线索而非通用合规标准；PAM 的 yes/no 只记录，不脱离认证栈判定。转发或密码认证可能有明确业务用途，应记录例外和配套限制。

缺失项保持未知。单一有效配置上下文不能代表全部用户、来源或 sshd 实例；公钥状态也不能证明密钥质量或账户隔离。完成配置评审后按平台正常变更流程修复，保留控制台恢复能力，再采集有效配置比较，脚本不修改任何配置。

依据：<https://man.openbsd.org/sshd.8>、<https://man.openbsd.org/sshd_config.5>。脚本与工作流由 ARTEX 编写，运行只需 Python 标准库。
