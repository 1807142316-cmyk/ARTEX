---
name: iam-policy-review
description: 离线复核 AWS IAM 策略权限范围；需要定位 Allow 通配操作、资源与主体，并将条件、Deny、NotAction 等复杂语义单列复核时使用。
category: 云配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline AWS IAM policy JSON; Linux and Windows
---

# IAM 策略范围复核

输入是已经导出的单份 IAM 策略 JSON（不是 IAM API 的封装响应），最多 4 MiB、1000 个 Statement。Statement 可为对象或数组；Action/Resource/Principal 支持标准字符串与数组形式，Principal 也可为主体类型到字符串/数组的映射。保存策略类型、绑定对象、版本与采集时间的外部证据引用，不输入访问密钥。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/policy.json`。退出 0 输出 JSON；退出 2 的标准错误 JSON 表示结构或字段值不符合支持格式。输出只保留 statement_index、Effect、条件是否存在、计数和检查代号，不输出主体、资源或条件值，保留 `input_sha256`。

复核 Allow 中操作、资源及主体的通配符。带 Condition 的语句保留 conditional，不能将其忽略为无限制；Deny 也不能从单份文档中直接抵消 Allow。NotAction/NotResource/NotPrincipal 标为 manual_review，脚本不求补集、不计算最终权限；没有 Resource 的信任策略保持待关联上下文。通配资源可能是特定操作的必要表达，结合 AWS 服务的资源级权限支持判断。

该工作流不验证完整 AWS 策略语法、条件运算符、服务动作存在性或所有策略组合。最终访问受身份和资源策略、权限边界、SCP、会话策略、条件以及显式拒绝共同影响，需要在正常配置评审与 AWS 权限分析流程复核。脚本不调用云 API、不收集凭据、不执行权限操作。

依据：<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>、<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>。本工作流和脚本由 ARTEX 编写，依赖仅为 Python 标准库。
