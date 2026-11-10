# 内容交付与来源核验

本文记录“CVE 语料、扫描模板、技能和武器库内容都要实际具备”的来源方案。只记录可核验的内容格式、更新和许可事实，不复制第三方利用代码、payload 或攻击链。内容必须在自有/明确授权资产或隔离靶场中验证。

## 已核验的一手来源

### CVE 全量语料：CVEProject/cvelistV5

来源：<https://github.com/CVEProject/cvelistV5>（官方仓库 README，已于本轮读取）。

已核验事实：

- 这是 CVE Program 的官方 CVE List 仓库，提供 CVE Record Format JSON 记录。
- 仓库约每 7 分钟通过官方 CVE Services API 更新；可用 Git 获取，也提供 Releases ZIP。
- 每日 baseline ZIP 和按小时发布的 delta ZIP 是官方列出的两类分发方式；delta 只包含自 baseline 以来的变化。
- 2024-07-31 之后的记录可能同时包含 CNA container 和 CVE Program container；下游处理器至少要检查这两个容器，不能只读取一个 `references` 数组。
- README 记录了 CVE Record Format 5.0/5.1/5.2 的演进，记录本身通过 `dataversion` 反映格式；导入器不能只按发布日期猜 schema。
- 官方仓库明确旧 CSV、HTML、XML、CVRF 下载格式已停止支持，新的实现应以 JSON Record 为基线。
- 仓库内容按 CVE Program Terms of Use 使用；具体部署时要保留来源、快照/提交号和更新时间。

实现要求：

1. 首次导入选择一个明确的官方 baseline（Git commit 或 release ZIP），保存 `source_version`、下载时间和内容哈希。
2. 后续任务按官方 delta 或 Git 更新；批次必须可重跑，失败不清空旧数据。
3. 解析 CNA、CVE Program 和可选 ADP 容器，规范化搜索字段，同时保留原始 JSON 以便回溯。
4. 记录 schema/dataversion、CVE ID、描述、产品/版本原结构、日期和所有参考链接。参考链接去重时不能覆盖来源容器信息。
5. 页面显示实际导入数量、基线、最后成功更新、失败批次和年份统计；不能硬编码宣传图的 197,720 条。
6. 提供完成导入后的离线检索；同步工作在后台作业中运行，不阻塞任务执行。

限制：官方仓库 README 不保证某个时点的固定总数，也不提供利用代码。图片中的数量是快照，不是验收数据。

### 检测/扫描模板：ProjectDiscovery/nuclei-templates

来源：<https://github.com/projectdiscovery/nuclei-templates>（官方仓库 README，已于本轮读取）；引擎来源：<https://github.com/projectdiscovery/nuclei>（官方 README，已于本轮读取）；模板文档入口：<https://docs.projectdiscovery.io/templates/introduction>。

已核验事实：

- 官方称该仓库是 Nuclei 的社区维护模板集合，模板是 YAML，供 Nuclei 扫描引擎执行。
- README 给出按标签、作者、目录、严重性和协议类型统计的矩阵，并明确统计会随仓库变化；网页当前数量不能当作项目固定目标。
- Nuclei 官方 README 说明可用模板路径/目录、标签和严重性过滤，支持模板校验；模板支持 HTTP、DNS、TCP、SSL、WHOIS、JavaScript、代码等协议，具体模板必须按类型和权限审查。
- Nuclei 引擎仓库 README 说明项目在持续开发、版本可能有 breaking changes；模板和引擎应锁定兼容版本并查看 changelog。
- 引擎 README 将 Nuclei 项目标为 MIT；模板仓库的 README 未在本次读取中给出可直接套用于每个模板的统一许可结论，分发前必须检查仓库许可文件、模板头部元数据和第三方作者要求。

实现要求：

1. 采用版本锁定的模板快照，保存仓库 commit/release、引擎版本和导入时间；不直接在生产容器启动时拉取 `latest`。
2. 导入前运行模板 schema/语法校验，建立模板 ID、作者、标签、严重性、协议类型、CVE/产品引用和许可证/来源字段。
3. 默认模板集合只启用经过审核且适合当前授权范围的检测；高影响或可能产生副作用的模板必须由任务策略和审批控制。
4. 将模板运行结果作为候选发现和证据引用，不能仅凭模板命中或版本匹配把漏洞标成已确认；确认仍要有独立复现或明确证据。
5. 导入更新保留旧版本和失败日志；模板删除/撤销不能删除历史发现使用过的模板版本。
6. 模板页面显示真实数量、版本、严重性和协议筛选；宣传图中的数量不是交付阈值。

本项目的“扫描模板”交付包括：锁定并导入可分发的公开模板、为项目工作流编写缺失的安全检测模板、模板元数据和验证记录。它不包括复制利用链、绕过检测或未经授权的攻击内容。

### 可运行技能：本项目格式与 Agent Skills 规范

本地事实：当前仓库仅带 `skills/api-recon`、`skills/playwright-cli`、`skills/scopesentry` 三个目录，三者均有 `SKILL.md`，并包含边界、工具和调用说明。

规范来源：<https://github.com/agentskills/agentskills>（官方 README，已于本轮读取）。

已核验事实：

- Agent Skills 是一个开放格式；技能目录至少有带 `name` 和 `description` 元数据的 `SKILL.md`。
- 目录可以附带 `scripts/`、`references/`、`templates/`、`assets/` 等资源。
- 规范采用 progressive disclosure：启动时发现名称/描述，匹配任务后读取完整说明，再执行附带资源。
- 规范仓库 README 说明代码 Apache-2.0、文档 CC-BY-4.0；具体技能目录仍需检查各自许可证和第三方资源许可。

实现要求：

1. 先把截图中需要的技能按真实工作流建成可运行包：目标/范围校验、资产整理、HTTP/API 证据收集、流量/报告整理、CVE 元数据关联、知识条目导入等。
2. 每个技能必须含清晰触发条件、输入/输出、失败处理、授权边界和依赖；脚本应可在 Linux Compose 镜像中复现。
3. 技能资源与 Agent 绑定使用当前项目的技能管理和调用账本；页面统计真实调用次数，不用目录数量代替能力数量。
4. 第三方工具只作为依赖或适配器，许可证、版本和安装方式单独记录；没有来源正文的截图目录先建立内容缺口，不伪造说明。
5. 把现有三个技能作为 M1/M2 的回归样本，再按来源和验收用例逐步增加技能包。用户要求“缺少的技能也要有”意味着需要为目标工作流补齐内容清单和可运行实现，不意味着可以从截图推导私有项目的原文。

### 武器库/知识条目：公开方法、检测和修复资料

可核验来源一：OWASP Web Security Testing Guide，<https://github.com/OWASP/wstg>（官方 README，已于本轮读取）。

- WSTG 是 OWASP 的综合 Web 应用和 Web 服务测试指南；场景使用 `WSTG-<version>-<category>-<number>` 标识。
- README 建议使用带版本的引用，例如 `WSTG-v42-INFO-02`，因为无版本的标识会随内容演进而产生歧义。
- 当前主分支面向 5.0，README 同时给出稳定版 4.2；导入时应保存版本和固定链接。
- 仓库 README 标示 CC BY-SA 4.0；入库时保留作者、版本和来源，按许可要求署名并处理相同方式共享义务。

可核验来源二：OWASP Cheat Sheet Series，<https://github.com/OWASP/CheatSheetSeries>（官方 README，已于本轮读取）。

- 该项目提供面向构建者的安全实践；官方建议通过项目网站阅读和引用。
- README 标示 CC BY-SA 4.0，并提供可下载的离线网站 bundle；Markdown 是工作源，不应直接当作外部引用页面。
- 这些内容适合形成“检测依据、修复建议、配置检查”的知识条目，不等于可执行利用代码。

武器库条目模型建议：

- `code`：稳定短标识；标题、分类、类型、分档、适用产品/版本。
- `summary`：检索摘要；`body`：验证步骤、检测依据、修复建议和参考链接。默认不放目标专属凭据或可直接危害第三方的利用内容。
- `source_refs`：CVE、WSTG/OWASP 版本化链接、模板 ID/版本、任务发现和证据引用。
- `verification_status` 与 `publication_status` 分离；只有具备可追溯证据的条目才能标记已验证，人工审核只记录审核结论，不替代技术证据。
- `reuse_count` 仅计真实 `kb_get(code)` 取用；搜索、浏览和重复请求不重复计数。条目版本变化后重新验证。

用户要求的“武器”应理解为可审计的检测/验证模板、知识条目、修复和授权靶场复现记录。截图中的私有条目数量或 `EXP` 数字无法从图片还原，不能伪造为已导入数据；可用公开来源和本项目在隔离靶场产生的证据逐步填充。

## 关于截图中的会话类型

图 8 的表格示例显示 `http_phpcmd` 模型和一个 `.php` URL，这只能说明目标版本有基于 HTTP 的 PHP 命令会话类型；它不是 SSH 的证据，也不能推导完整 WebShell/C2 协议或其操作实现。用户已明确按截图落实 C2/WebShell 管理，因此图中 `http_phpcmd` 对应的 HTTP/PHP WebShell 适配器属于本期必做验收项；至少需要验证接入、心跳、断开、任务关联、拓扑、凭据引用和受控操作。实现应把 SSH、HTTP/PHP 会话、C2/WebShell 分成独立适配器和能力声明，SSH 只能作为可选补充，不能冒充截图中的 WebShell/C2 能力。其他 C2 协议必须按真实适配器能力逐项展示，不能通过静态页面声称完成。

## 来源与内容验收

每个导入批次都记录来源 URL、版本/commit、许可证、获取时间、内容哈希、解析器版本、成功/失败数量。每个模板、技能和武器条目都能追溯到批次和独立验证记录。离线模式必须在断网时完成检索和查看；更新失败保留上一份可用快照。

不承诺：从截图还原目标项目私有知识库正文、私有 payload、私有脚本、固定条数或宣传中的成功率。缺失内容必须以待补清单、来源或实现状态显示，而不是空目录、重复条目或硬编码数字。

