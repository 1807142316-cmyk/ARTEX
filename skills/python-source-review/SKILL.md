---
name: python-source-review
description: 对已有 Python 源码做离线 AST 清点；需要定位函数、导入和动态执行或子进程调用的人工审查位置时使用。
category: code-audit
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; one saved UTF-8 source file; Linux and Windows
---

# Python 源码审查清单

输入是一份已保存的 UTF-8 Python 源码，保留版本、来源与任务证据引用。脚本上限为 1 MiB、25,000 个 AST 节点，每个输出清单最多 1,000 条。它按运行脚本的 Python 版本解析语法；其他语言和不受当前解释器支持的语法需要相应分析工具。

1. 运行 `python3 "${SKILL_DIR}/scripts/run.py" --input /path/to/source.py`；也可将文件路径作为唯一位置参数。路径含空格时使用引号。仅依赖 Python 标准库，无 MCP 或网络依赖。
2. 退出 0 后保存标准输出 JSON 与原证据引用。`input_sha256` 对应原始文件字节，`counts` 记录函数声明、导入语句、调用节点及待复核位置数量。`functions` 包含同步及异步函数；`imports` 保留模块、别名和相对导入级别。行号从 1 开始，`column` 是从 0 开始的 UTF-8 字节偏移。
3. 逐项查看 `review_sites`：`eval`/`exec` 及 `builtins` 同名调用、以 `subprocess.` 开头的字面调用链，以及任意调用中常量 `shell=True` 的位置。脚本不输出参数文本或源码正文，也不导入或执行输入文件。它不创建确认漏洞或修复代码。
4. 人工回到对应位置，核对输入来源、调用绑定、参数构造、边界条件和实际执行环境。这里仅识别字面名称，不解析导入别名、重绑定、反射、数据流、间接调用或跨文件关系；同名用户函数可能被标记，别名调用可能遗漏。清单为空或存在标记都不能证明安全或可利用。将确认依据和未覆盖范围写入审查结论。
5. 退出 2 的标准错误是 JSON `error`，标准输出为空。缺失/非文件路径、无效 UTF-8、语法错误和超限输入需要先修正；保留失败记录，使用相应语言/版本工具继续审查。未生成完整报告时不按部分结果验收。

依据：Python 官方 [ast](https://docs.python.org/3/library/ast.html) 的语法树和位置定义、[subprocess 安全说明](https://docs.python.org/3/library/subprocess.html#security-considerations)。本工作流与脚本由 ARTEX 编写，链接是语义依据，未复制上游实现。
