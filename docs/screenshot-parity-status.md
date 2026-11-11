# 截图功能对齐实施状态

实施分支：`codex/screenshot-parity-integration`。最新一轮为 #8–#10 补全与双轴审查修复，位于 `codex/issues-8-10-integration`（`10134e2`）。父 issue #1 尚未全部完成；#2、#3、#4、#5、#6、#7、#11 已完成，#8、#9、#10 在本轮交付并总结关闭依据，即 10 个子任务全部有结论。最新 Linux 数据及内容验收见[实际运行记录](screenshot-parity-linux-validation.md)。

## Ticket 覆盖

| Issue | 已交付与证据 | 剩余事项 |
| --- | --- | --- |
| #2 仪表盘 | 快速开始、阶段目标、现有设置继承、持久化幂等、真实统计、范围明确的资源接口；真实浏览器及 HTTP/PostgreSQL 验证；Linux 进程及 cgroup v2 限额口径验收通过 | 采样非精度基准；整套容器发布由父 spec 跟踪 |
| #3 发现 | 严重性、检索、分页、展开及保留原详情操作；真实 HTTP/PostgreSQL 验证 | 原始截图无法从当前上下文重新取图做像素对照 |
| #4 知识库 | 导入/去重/版本/审核/验证/发布/撤销、逻辑调用去重、`kb_search`/`kb_get`、六条实质草稿；候选来源分页、正文搜索开关、来源证据预览及解绑后 GC 保留；真实 HTTP/PostgreSQL 与浏览器闭环 | 已关闭；Linux 整体验收由父 spec 跟踪 |
| #5 CVE | 官方全量421,793条在独立 Linux Compose PostgreSQL 实际导入；原库及恢复库认证 HTTP 检索、统计、原始记录、离线查询、备份恢复和重启检查通过 | Ticket 数据验收完成；整套应用镜像部署和升级仍由父 spec 跟踪 |
| #6 模板 | 固定 Nuclei 3.4.10；11 条官方 MIT 原文模板及 3 条原创检查；status/word/regex、正文/头匹配及提取；原子离线导入、历史快照、候选证据、取消和任务代理；Linux 8 项 HTTP/实际引擎与 5 项语法/包测试通过 | 已关闭；兼容范围见 SCANNING.md，完整社区格式及父 spec 整体内容对齐不能据此判定完成 |
| #7 技能 | 16 个新增 Python 标准库工作流，保留原 3 包；分类/目录/导入/编辑及绑定保护、精确加载上下文、固定离线工作流输入摘要/输出/退出结果；Linux 31 项 CLI、16 包哈希及 6 项真实 HTTP/PostgreSQL 验收通过 | 已关闭；执行报告标为操作方上报，未知私有技能目录与完整截图能力对齐由父 #1 跟踪，不能据此宣称全部复刻 |
| #8 代理池 | 原有池/租约/健康/故障/审计与任务 HTTP/录制/模板接线；新增透明任务出口沙箱（`egress_sandbox_enabled`）：任务进程树内的 Bash/脚本、原始 TCP 与 DNS（UDP/TCP 53）在具备 `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` 时强制经本任务租约，其余出站丢弃；故障沿用暂停/切换/显式直连策略并留审计。Linux 7 项 `egress` 单元/沙箱测试与 4 项任务级沙箱验收（双任务不同出口+DNS、建立失败暂停、中继死亡策略、显式直连）通过；6 项网关 HTTP/PostgreSQL 回归与 Windows、Linux 实际 Agent 浏览器双出口验收通过 | 任务进程树之外的外部 MCP/浏览器服务、应用自身出站、非 DNS UDP、ICMP 及 SOCKS5 UDP ASSOCIATE 不透明强制，已在 PROXY-POOL.md 与界面写明；完整容器发布由父 spec 跟踪 |
| #9 C2/WebShell | 交付 `http_phpcmd` 真实适配器：连接配置、上线/离线与显式断开原因、后台心跳巡检（`connection_heartbeat_seconds`，默认 60、最小 15）、任务/资产关联、能力约束操作与请求/完成/失败/超时/不支持记录（含 `session_sequence` 与 `output_ref`）、凭据受控密封与不回显、分页列表、C2/WebShell 页面。Linux 真实 PHP 8.3 容器 + 真实 PostgreSQL 下全部通过，含真实 `exec`、失败退出码、超时与输出上限；Windows 与 Linux 合计 33 项相关顶层测试通过 | 交互式浏览器验收仍未运行；其他 C2 协议按 kind 明确拒绝 |
| #10 内网拓扑 | 显式主机/网段/会话/隧道元数据/凭据引用关系、失效传播、任务筛选及审计；不按同网段推断边。边新增可读原因（会话失联/断开、节点失效、凭据过期、隧道失效、任务不匹配）与任务筛选摘要。`worker_intranet` 上下文以会话为门槛，凭据作为附加上下文且过期即排除；禁用/认证失败/不可达适配器名下的会话不展示并报 `integration_unreachable`；`intranet_exec` 接入真实适配器，每次调用重校验任务归属与有效状态。真实 HTTP/PostgreSQL 与真实 PHP 会话验收通过 | 交互式浏览器验收未运行；无会话或无凭据时的空态已在页面明确展示 |
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

- 本轮 `593e9f4...10134e2` 在 Windows 独立 PostgreSQL 17 与 Linux（Ubuntu 22.04，独立 PostgreSQL 18 容器）分别运行：`TestConnection*`、`TestIntranet*`、`TestSessionInventory*`、`TestProxyPool*` 共 33 项顶层测试通过，0 失败；Linux 侧带真实 PHP 8.3 容器（`artex-php-fixture9`，仅绑定 127.0.0.1:18081）执行，`TestConnectionAdapterRealPHPFixture`、`TestIntranetExecUsesRealPHPSession` 均实际通过，无跳过。
- Linux 侧 `ARTEX_EGRESS_SANDBOX=1` 运行 7 项 `egress` 包沙箱测试与 4 项任务级沙箱验收全部通过：双任务不同出口并各自解析 DNS、沙箱建立失败暂停、中继死亡按策略处理、显式直连回退留审计。`TestProxyPoolRealAgentBrowserKeepsTaskExitsSeparate` 仍为环境门控（需显式提供浏览器路径），不计入本轮通过数。
- 真实 PHP 夹具协议冒烟（ping、echo 退出码、超时、错误密钥 401、查询串 400、超限 413）在 Linux 全部通过。夹具仅存在于 `tests/fixtures/php-webshell/`，不进入生产构建路径。
- 新页面通过 TypeScript 检查（`tsc --noEmit` 无输出）；`go build ./...` 与 `go vet ./server ./db ./agent ./egress` 在 Windows 与 Linux 均通过。

完整服务端测试仍有 Windows 环境失败：Python执行别名返回9009、证据目录 fsync 返回 Access denied。已在未修改的 `f3e3f54` 基线复现；设置 `ARTEX_TEST_PYTHON` 指向真实解释器后相关用例通过，其余不冒充回归通过。

## 双轴审查

本轮 `593e9f4...10134e2` 的 #8–#10 增量也做了独立 Standards/Spec 审查，修复落在同一分支（`4005725`…`c8601e5`，另加两项测试稳定性修复 `7a6d502`、`10134e2`）：

Standards：已修复列表未分页、操作记录缺会话 sequence 与输出引用、连接凭据密封逻辑重复且直接取自 JWT 密钥（改为统一领域分离派生并保留旧格式回退）、超时范围文档/校验/schema 不一致、UTF-8 截断、编辑适配器无条件重置健康状态、LIKE 转义重复与派生表 `SELECT *`、约束名冲突字符串匹配。未发现其他硬性规则违反。

Spec：已修复心跳仅手动（新增后台巡检并提取共用同步路径）、内网上下文错误地同时要求会话与凭据（改为以会话为门槛）、探测把协议级失败误判为不可达、内网上下文展示禁用/认证失败适配器的会话、未文档化的 `adapter_id` 入参与多余密钥头。审查确认后补上适配器到 `intranet_exec` 的真实执行接线。已知范围边界（外部 MCP、非 DNS UDP、SOCKS5 UDP ASSOCIATE、交互式浏览器验收）未作为缺陷处理，已在文档与页面写明。

`034de93...e7cddcc` 技能增量的独立 Standards/Spec 审查共同发现一项 P2：旧报告重试依赖当前技能文件。`2ce0588` 在客户端 ID 事务锁内先读取历史、仅首次写入验证当前包，并补充真实 HTTP 回归；修复合入 `8039cb6` 后在 Linux 再次通过。Spec 复核确认该问题已解决，16 包分类矩阵已同步，#7 的原始四项验收满足。Standards 未发现硬性规则违反；多处固定目录是低优先级维护建议，当前保留运行器、服务端的独立边界及测试的独立预期。

本轮 `66ba72c...8c41006` 再次进行两轴独立审查，修复于 `6c4aa76`：Standards 的类型化拓扑节点建议消除了 bigint 经 float64 舍入；Spec 的两项问题分别修复了密钥迁移中断后旧副本清理，以及详情心跳/断开状态未随轮询刷新。独立 PostgreSQL 的 8 项顶层回归及 5 个启动子场景通过，TypeScript/Biome 通过。Linux 内容证据对应 `8c41006`，未将后续修复冒充已在 Linux 重跑。

Standards：未发现明确仓库规则硬性违反；已修复测试初始化错误被跳过、缓存无限积累、YAML锚点丢失及候选证据保留问题。后续修复模板输出上限被继承方法绕过、代理租约变化后旧连接存活及切换请求取消误暂停任务；实际子进程与公开 HTTP 回归通过。

Spec：已修复缺增量包时游标提前推进、坏缓存阻止重试、CVE技能丢失受影响条件、同步状态快照竞态，并补齐候选来源闭环。后续修复关联任务停止后模板仍执行、代理监控总超时误暂停其他任务；复核未发现新的可操作问题。上表列明的范围缺口仍存在，父 issue 必须保持开启。

## Linux 交付边界

新增 `Dockerfile.source` 和 `compose.source.yml` 从本分支源码构建，步骤见根目录 `DEPLOYMENT.md`。Ubuntu 服务器已用于独立 CVE、模板、技能、代理及实际 Chromium、密钥回归与 Linux 指标口径验收，见[Linux记录](screenshot-parity-linux-validation.md)。整套应用镜像冷启动/升级仍未验收。源码 Compose override 已新增私有 JWT/config 持久卷；首次升级旧容器必须先按文档保存并恢复原密钥。整套平台部署曾被自动审批拒绝（`blocked by policy`），未替换服务器原 ARTEX；数据及受限工作流验收不能代表平台发布完成。
