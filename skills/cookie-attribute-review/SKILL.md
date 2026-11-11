---
name: cookie-attribute-review
description: 复核已保存 Set-Cookie 属性；需要检查 Secure、HttpOnly、SameSite、前缀约束和重复属性且隐藏 Cookie 名值时使用。
category: HTTP 配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON; Linux and Windows
---

# Cookie 属性复核

输入 UTF-8 JSON 含 `scheme`（http/https）和 `set_cookie`（每个元素是一条独立 Set-Cookie 头，最多 1000 条）。文件上限 2 MiB、单条 16384 字符。保留响应中的每条头，不按逗号合并或拆分，否则 Expires 会被破坏。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/cookies.json`。退出 0 输出按 `cookie_index` 编号的 JSON；退出 2 的标准错误 JSON 给出输入项索引或结构错误，不输出 Cookie 名值、域或路径。保存 `input_sha256` 与原证据引用，按索引回查原始头。

检查 Secure/HttpOnly/SameSite、`__Secure-`/`__Host-` 与 Partitioned 约束、重复属性及带值的标志。SameSite=None 需要 Secure；Host 前缀还需要 Path=/ 且没有 Domain。缺失 HttpOnly 对需由 JavaScript 读取的非敏感 Cookie 可能合理，需记录业务用途；没有 SameSite 不能假定所有浏览器相同行为。重复属性需核对浏览器实际接受结果，不由脚本猜测优先级。

脚本只整理已观察到的属性，不验证 Cookie 载荷语法、有效期、公共后缀、域匹配或会话安全，也不判断是否可利用。根据业务与浏览器兼容要求修复后重新采集。依据：<https://www.rfc-editor.org/rfc/rfc6265>、<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>。工作流和脚本由 ARTEX 编写，仅依赖标准库。
