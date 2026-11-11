---
name: binary-format-inspection
description: 对已保存的 ELF 或 PE 文件做离线头部与节区结构清点；需要确认位数、字节序、架构、入口和有界节区元数据时使用。
category: reverse-engineering
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; saved ELF32/64 or PE32/PE32+ file; Linux and Windows
---

# 二进制格式结构清点

输入为一份已保存的文件，保留来源、版本及任务证据引用。脚本只按 ELF／PE 规范读取文件字节，不加载或执行输入，不反汇编、不解包、不联网。支持 ELF32／64 的大小端格式及 PE32／PE32+；输出属于结构观察，不构成完整逆向分析、漏洞判断、签名核验或可运行性判断。

1. 运行 `python3 "${SKILL_DIR}/scripts/run.py" --input /path/to/saved.bin`，也可将文件路径作为唯一位置参数。路径含空格时使用引号，仅依赖 Python 标准库。
2. 退出 0 后保存标准输出 JSON 与原证据引用。`input_sha256` 是原始文件字节哈希。`header` 保留位数、字节序、机器代码及有限名称映射、文件类型、入口值；未知代码显示 `unknown`，不能根据位数推定架构。ELF `entry_point` 是头部原值；PE `entry_point_rva` 是相对虚拟地址，`image_base` 是声明的首选基址，二者都不是文件偏移或已确认运行地址。ELF 的 `shared_object` 类型也可能是 PIE 程序，类型字段本身不能区分用途。
3. `sections` 是通过边界检查的节区表记录。ELF `declared_size` 保留声明大小，NOBITS 的 `file_size` 为 0；无节名表时 `name` 为 null。PE 同时保留虚拟地址／大小与原始文件偏移／大小；名称只读取头部内的 8 字节字段，不解析 COFF 字符串表。名称按 ASCII 解码，其他字节转义，JSON 会转义控制字符。名称、权限标志和入口均不能证明节区实际被加载或执行。
4. `imports.status` 固定为 `not_inspected`：本工作流只清点头部和节区，不解析导入、符号、动态依赖、资源或重定位；没有导入清单不能表述为“没有导入”。进一步结论需使用相应格式工具并另存证据，保留这里的未覆盖范围。
5. 文件上限 64 MiB；最多 1,024 个节区、1,024 个 ELF 程序头，ELF 节名最多 256 字节。ELF 扩展编号及非 PE32／PE32+ 可选头会明确拒绝。所有声明的表格及有文件内容的区段都需在输入内；虚拟 NOBITS 不按文件数据检查。截断、越界、无效名称表、超限、缺失／非文件路径和不支持格式退出 2，标准错误返回 JSON `error`，标准输出为空。失败时保留记录，不按局部结果验收。结构检查不替代完整格式一致性或装载器验证。

依据：ELF System V ABI 的[文件头](https://gabi.xinuos.com/elf/02-eheader.html)及[节区](https://gabi.xinuos.com/elf/03-sheader.html)，Microsoft 官方 [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)。工作流与脚本由 ARTEX 编写，链接是字段语义依据，未复制上游实现。
