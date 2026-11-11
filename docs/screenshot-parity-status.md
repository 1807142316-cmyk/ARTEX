# 截图功能对齐实施状态

实施分支：`codex/screenshot-parity-integration`。最新产品及技能审查修复为 `8039cb6`。父 issue #1 尚未全部完成；#2、#3、#4、#5、#6、#7、#11 已完成，#8–#10 保持开启，即 10 个子任务中完成 7 个。最新 Linux 数据及内容验收见[实际运行记录](screenshot-parity-linux-validation.md)。

## Ticket 覆盖

| Issue | 已交付与证据 | 剩余事项 |
| --- | --- | --- |
| #2 仪表盘 | 快速开始、阶段目标、现有设置继承、持久化幂等、真实统计、范围明确的资源接口；真实浏览器及 HTTP/PostgreSQL 验证；Linux 进程及 cgroup v2 限额口径验收通过 | 采样非精度基准；整套容器发布由父 spec 跟踪 |
| #3 发现 | 严重性、检索、分页、展开及保留原详情操作；真实 HTTP/PostgreSQL 验证 | 原始截图无法从当前上下文重新取图做像素对照 |
| #4 知识库 | 导入/去重/版本/审核/验证/发布/撤销、逻辑调用去重、`kb_search`/`kb_get`、六条实质草稿；候选来源分页、正文搜索开关、来源证据预览及解绑后 GC 保留；真实 HTTP/PostgreSQL 与浏览器闭环 | 已关闭；Linux 整体验收由父 spec 跟踪 |
| #5 CVE | 官方全量421,793条在独立 Linux Compose PostgreSQL 实际导入；原库及恢复库认证 HTTP 检索、统计、原始记录、离线查询、备份恢复和重启检查通过 | Ticket 数据验收完成；整套应用镜像部署和升级仍由父 spec 跟踪 |
| #6 模板 | 固定 Nuclei 3.4.10；11 条官方 MIT 原文模板及 3 条原创检查；status/word/regex、正文/头匹配及提取；原子离线导入、历史快照、候选证据、取消和任务代理；Linux 8 项 HTTP/实际引擎与 5 项语法/包测试通过 | 已关闭；兼容范围见 SCANNING.md，完整社区格式及父 spec 整体内容对齐不能据此判定完成 |
| #7 技能 | 16 个新增 Python 标准库工作流，保留原 3 包；分类/目录/导入/编辑及绑定保护、精确加载上下文、固定离线工作流输入摘要/输出/退出结果；Linux 31 项 CLI、16 包哈希及 6 项真实 HTTP/PostgreSQL 验收通过 | 已关闭；执行报告标为操作方上报，未知私有技能目录与完整截图能力对齐由父 #1 跟踪，不能据此宣称全部复刻 |
| #8 代理池 | 原有池/租约/健康/故障/审计与任务 HTTP/录制/模板接线；Windows 和 Linux 实际 Agent MCP/Chromium 双任务不同出口验收通过，Linux 6 项网关 HTTP/PostgreSQL 回归通过 | 原始 TCP/UDP、DNS及忽略代理设置的程序不受透明强制，完整目标流量策略尚不满足，保持开启 |
| #9 C2/WebShell | 新增认证的外部会话观察登记、心跳/过期/断开、任务资产关联、审计、页面及实际 HTTP 健康观察 CLI；5 项真实 HTTP/PostgreSQL 测试通过 | 观察模块不等于 C2/WebShell 控制适配器；真实 HTTP/PHP 协议操作未交付，交互式浏览器验收未运行，保持开启 |
| #10 内网拓扑 | 新增显式主机/网段/会话/隧道元数据/凭据引用关系、失效传播、任务筛选及审计；不按同网段推断边 | 依赖的真实控制会话适配器及 worker 内网上下文未交付，保持开启 |
| #11 CVE更新 | 默认定时同步、立即更新/开关、持久化状态/游标、互斥、恢复、遗漏窗口协调、缓存校验/保留策略；真实 HTTP/PostgreSQL 测试覆盖 | Linux整体验收仍由父 spec 跟踪 |

## 实际运行证据

- Windows 主机上启动独立 PostgreSQL 17，新增功能 HTTP 集成测试实际执行；没有将跳过的测试记作成功。
- 最终 `bcaee3b` 在全新 PostgreSQL `parity_final_release` 运行 28 项顶层 HTTP 测试、2 项暂停/删除子测试，共 30 项通过、0 跳过、0 失败，覆盖幂等任务、发现、知识生命周期/候选、技能实际加载及统计、CVE导入/同步/并发一致状态、指标认证、代理并行租约/故障/录制/SOCKS5/CONNECT取消及真实模板执行/任务停止/任务代理。原始 JSON 事件日志保存在本机 `%TEMP%/artex-final-release-server-tests.jsonl`。
- 全仓库 Go 编译检查、CVE/模板单元测试、前端 TypeScript、Next.js 生产静态构建通过。
- `6c4aa76` 集成后新增及相关功能的 25 项顶层 HTTP 测试通过，0 失败、0 跳过，包含实际 Chromium/Nuclei、14 包 Agent 加载、会话观察、高位 task ID 和迁移中断；Windows Python 显式指定实际安装路径。JSON 事件日志位于本机 `%TEMP%/artex-parity-content2/integrated-http-tests-final.jsonl`。该定向回归不替代下文注明的全量旧测试环境问题。
- Linux 17 项 Python 技能命令测试、14 个原创包哈希以及实际 Agent 加载/计数通过。原三个技能内容与绑定未覆盖改写。
- 后续 `e7cddcc` 的 31 项技能 CLI 测试及 16 包哈希在 Windows Python 3.11 和 Linux Python 3.10.12 全部通过。`8039cb6` 在独立 Linux Compose PostgreSQL 上通过 6 项认证 HTTP 测试，0 失败、0 跳过：包括 16 包实际 Agent 加载/计数、分类及绑定保护、加载上下文、真实 CLI 上报、不可变历史、包修改/删除后的重试、任务删除/应用重建及控制字符输出。日志归档哈希见 Linux 运行记录。技能详情新面板通过 TypeScript 和 36 页静态构建；本轮没有新增交互式浏览器验收。
- 公共 norma Bash/curl 实测池模式清空继承的 `NO_PROXY` 后经过代理，旧模式继续保留原绕过行为。真实子进程分别输出 13 MiB stdout、stderr 和错误文件，三种有界处理均通过。
- 浏览器实际验证快速开始与阶段切换、知识检索/正文匹配开关/来源证据预览/候选整理/来源历史、完整 CVE 语料检索/原始记录展开/自动开关，以及真实 Nuclei 执行/完成记录/请求响应预览/待审发现标记。
- 代理管理页面已实际验证添加/检查/观测 IP/分配。Windows 和 Linux 实际 Agent MCP/Chromium 导航都验证双任务不同出口及继承 `NO_PROXY=*` 的处理；Linux 的 6 项网关测试通过。Linux 浏览器验收使用 `8039cb6`，独立测试 6.30 秒通过、零跳过，工具及库仅解压至验证目录，未安装系统包或修改现有服务。
- 官方 `cve_2026-11-10_1900Z` 基线导入421,793条：402,649条 PUBLISHED、19,144条 REJECTED。ZIP SHA-256与来源见 `content-manifests/cve-baseline.json`。
- `pg_dump` 完整导出并恢复至独立库，重新启动新版本应用后经认证HTTP确认统计仍为421,793，且可检索 `CVE-2021-44228`。
- 本地内容在 `content/cve/`，包括官方ZIP、manifest及数据库备份；大文件排除Git。跟踪的manifest足以重新下载并核验原始ZIP。

完整服务端测试仍有 Windows 环境失败：Python执行别名返回9009、证据目录 fsync 返回 Access denied。已在未修改的 `f3e3f54` 基线复现；本次修复了技能路径分隔符失败，其余不冒充回归通过。

## 双轴审查

`034de93...e7cddcc` 技能增量的独立 Standards/Spec 审查共同发现一项 P2：旧报告重试依赖当前技能文件。`2ce0588` 在客户端 ID 事务锁内先读取历史、仅首次写入验证当前包，并补充真实 HTTP 回归；修复合入 `8039cb6` 后在 Linux 再次通过。Spec 复核确认该问题已解决，16 包分类矩阵已同步，#7 的原始四项验收满足。Standards 未发现硬性规则违反；多处固定目录是低优先级维护建议，当前保留运行器、服务端的独立边界及测试的独立预期。

本轮 `66ba72c...8c41006` 再次进行两轴独立审查，修复于 `6c4aa76`：Standards 的类型化拓扑节点建议消除了 bigint 经 float64 舍入；Spec 的两项问题分别修复了密钥迁移中断后旧副本清理，以及详情心跳/断开状态未随轮询刷新。独立 PostgreSQL 的 8 项顶层回归及 5 个启动子场景通过，TypeScript/Biome 通过。Linux 内容证据对应 `8c41006`，未将后续修复冒充已在 Linux 重跑。

Standards：未发现明确仓库规则硬性违反；已修复测试初始化错误被跳过、缓存无限积累、YAML锚点丢失及候选证据保留问题。后续修复模板输出上限被继承方法绕过、代理租约变化后旧连接存活及切换请求取消误暂停任务；实际子进程与公开 HTTP 回归通过。

Spec：已修复缺增量包时游标提前推进、坏缓存阻止重试、CVE技能丢失受影响条件、同步状态快照竞态，并补齐候选来源闭环。后续修复关联任务停止后模板仍执行、代理监控总超时误暂停其他任务；复核未发现新的可操作问题。上表列明的范围缺口仍存在，父 issue 必须保持开启。

## Linux 交付边界

新增 `Dockerfile.source` 和 `compose.source.yml` 从本分支源码构建，步骤见根目录 `DEPLOYMENT.md`。Ubuntu 服务器已用于独立 CVE、模板、技能、代理及实际 Chromium、密钥回归与 Linux 指标口径验收，见[Linux记录](screenshot-parity-linux-validation.md)。整套应用镜像冷启动/升级仍未验收。源码 Compose override 已新增私有 JWT/config 持久卷；首次升级旧容器必须先按文档保存并恢复原密钥。整套平台部署曾被自动审批拒绝（`blocked by policy`），未替换服务器原 ARTEX；数据及受限工作流验收不能代表平台发布完成。
