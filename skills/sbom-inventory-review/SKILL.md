---
name: sbom-inventory-review
description: 复核已导出的 CycloneDX/SPDX 依赖清单质量；需要定位缺版本、包标识、许可及强哈希的组件并保留可追溯清单时使用。
category: 依赖与供应链审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; CycloneDX 1.4-1.6 or SPDX 2.2-2.3 JSON; Linux and Windows
---

# SBOM 依赖清单质量复核

输入为已生成的 CycloneDX 1.4–1.6 或 SPDX 2.2/2.3 JSON，最多 16 MiB、10000 个组件、32 层嵌套。保存生成工具、构建产物版本、锁文件与采集时间引用；不要用依赖声明替代已构建产物的完整清单。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/sbom.json`。退出 0 输出 JSON；退出 2 的标准错误 JSON 指出格式、缺失名称、重复组件标识或限制错误。CycloneDX 遍历 components 嵌套，SPDX 遍历 packages。空清单可输出 0 项，不作为完整性通过证据。输出按组件索引保留名称与版本，分享前检查内部包命名，保留 `input_sha256`。

复核每项缺少版本、PURL/CPE 标识、许可与哈希的情况。SHA-256/384/512 只有算法及十六进制长度正确才计为有效强哈希声明；脚本不访问产物验证摘要。SPDX NOASSERTION/NONE 不代表已识别可用许可，需跟踪人工确认。PURL/CPE 仅识别声明前缀，不声称完整语法验证；许可表达式也未按 SPDX 语法解析。

这是清单质量工作流，不下载依赖、不查询漏洞库、不据包名版本声称漏洞存在或可达。下一步应将真实组件与匹配的公告、运行路径和修复版本独立核验；保留来源和审阅结果，不能把没有告警当作没有风险。

依据：<https://cyclonedx.org/docs/1.6/json/>、<https://spdx.github.io/spdx-spec/v2.3/package-information/>。本工作流及脚本由 ARTEX 编写，依赖仅为 Python 标准库。
