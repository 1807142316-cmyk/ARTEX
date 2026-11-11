---
name: tls-observation-review
description: 复核已有 TLS 握手及证书验证记录；需要检查旧协议、证书有效期、主机名与信任链观察状态时使用。
category: TLS 配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline JSON; Linux and Windows
---

# TLS 观察复核

将已有连接记录整理成 UTF-8 JSON：`observed_at`、`protocol`、`cipher`、`cipher_bits`，以及 `certificate` 对象。对象含 `not_before`、`not_after`、`chain_verified`、`hostname_match`；时间为含时区的 ISO 8601，验证字段为布尔或 null。上限 1 MiB。记录采集来源与工具版本；未知验证状态填写 null。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/tls.json`。退出 0 的标准输出是观察结果 JSON；退出 2 的标准错误 JSON 表示字段或时间无效，修正原证据后重跑。脚本不连接主机，也不解析或验证证书签名。

核对 `issues`、`unknown_checks`、`certificate_time_state` 与 `seconds_until_expiry`，将 `input_sha256` 和证据引用保留。TLS 1.2/1.3 以外列为旧协议；有效期按采集时间判断，低于 128 位的已记录对称强度需复核。有效期内或套件位数足够都不证明信任链、名称、套件策略和服务器整体配置合格；一次握手不能证明所有可协商协议。验证失败与未执行分别保留，不能把 null 当通过。

根据资产兼容要求复核协议及证书部署，修复后使用真实连接记录复测。依据：<https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>、<https://docs.python.org/3/library/ssl.html>。本工作流和脚本由 ARTEX 编写。
