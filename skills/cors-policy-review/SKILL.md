---
name: cors-policy-review
description: 复核已保存响应的 CORS 策略；需要区分无策略、通配符、指定来源、凭据不兼容及缓存 Vary 风险时使用。
category: HTTP 配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON; Linux and Windows
---

# CORS 响应策略复核

输入 UTF-8 JSON，含 `request_origin`（HTTP(S) 序列化来源或字符串 `null`）、`credentials_mode`（include/omit/same-origin）、`response_headers`（name/value 对象数组，保留重复头）。文件上限 2 MiB、最多 1000 头，每头名 256 字符、值 16384 字符。使用已有请求响应记录，不生成探测流量。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/cors.json`。退出 0 输出 JSON；退出 2 的标准错误 JSON 描述无效输入。输出不包含头值、来源或凭据，保存 `input_sha256` 与原证据引用。

检查 `policy`、`origin_permitted` 和 `issues`。通配来源与 include 不兼容；缺少 Allow-Origin 表示此响应没有跨源读取许可，并非缺陷。单来源响应缺少 Vary: Origin 需要结合动态策略和缓存配置复核，不自动判定缓存泄漏。重复单值 CORS 头标为 ambiguous，字符串 null 的许可需单独审查来源隔离。

`origin_permitted` 仅按此条记录的来源和凭据字段判断，不验证预检、方法、请求头、重定向或不同来源反射。same-origin 在跨源请求中不携带凭据；一个已许可响应不证明存在跨域数据泄漏。结论需关联实际可读数据及完整浏览器行为，修复后用已有正常业务流程重新采集。

依据：<https://fetch.spec.whatwg.org/#http-cors-protocol>。脚本和工作流由 ARTEX 编写，仅依赖 Python 标准库。
