## Problem Statement

当前 ARTEX 已提供任务、资产、探索图、发现、流量、Agent、工具、技能、审批及报告等能力，但与用户提供的魔改版本截图存在系统性差距：导航与仪表盘组织不同，缺少跨任务知识复用、离线 CVE 语料及自动更新、实际扫描模板及技能内容、代理池，以及真实 C2/WebShell 管理和内网作战视图。

用户只有八张截图，无法提供目标版本源码、私有数据、协议文档或完整交互。用户希望基于当前项目反推并实现截图体现的功能与设计，保留当前配色。仅增加菜单、静态展示、导入接口或空目录无法满足需求；实际语料、模板、技能与武器库内容也必须交付。

项目运行在 Linux 服务器。改造需要保留现有任务、资产、发现、证据、流量、报告、复测、审批及用户配置，避免为了界面和角色名称调整破坏历史数据。

## Solution

在现有 Go 后端、Next.js 前端与 PostgreSQL 架构上扩展，按截图重组工作台、作战、情报、执行、知识库、智能、安全和运维入口。用真实后端支持快速开始、资源监控、知识检索复用、CVE 全量导入及自动增量更新、模板和技能内容、代理租约、C2/WebShell 会话及内网拓扑。

以可验证的页面结构、字段、交互、数据和运行结果定义一致性。截图没有揭示的后台行为采用明确的产品合同设计，不宣称与目标项目私有实现相同。所有统计来自真实数据。

Linux Docker Compose 是标准部署与验收方式，同时保留 Linux 二进制启动。自定义 Agent 保持现状；内置 Agent 在保留既有运行时标识的基础上对齐显示与职责，并支持 worker 的内网上下文变体。

## User Stories

1. As an ARTEX operator, I want navigation grouped like the reference screenshots, so that I can find workbench, operations, intelligence, execution, knowledge, configuration, safety, and maintenance functions consistently.
2. As an existing ARTEX user, I want existing links and saved task references to remain usable, so that navigation changes do not interrupt my work.
3. As an ARTEX operator, I want the existing color theme retained, so that the upgrade preserves the project's visual identity.
4. As an ARTEX operator, I want to enter a target and start a real task from the dashboard, so that I can begin work without manually assembling routine settings.
5. As an ARTEX operator, I want stage-specific shortcuts to create tasks with limited objectives, so that I can run only the part of the workflow I need.
6. As an ARTEX operator, I want quick start to inherit existing model, concurrency, timeout, Token, and rule settings, so that shortcuts respect my configuration.
7. As an ARTEX operator, I want the effective task limits visible and overridable where supported, so that I can understand why execution pauses or ends.
8. As an ARTEX operator, I want repeated submission of the same start request to avoid duplicate tasks, so that retries do not multiply work.
9. As an ARTEX operator, I want real task, finding, asset, and Token summaries on the dashboard, so that I can assess current activity accurately.
10. As a Linux administrator, I want CPU and memory metrics labeled with their collection scope and limits, so that I do not mistake container usage for whole-server usage.
11. As an ARTEX operator, I want severity filters, search, summaries, and expandable finding rows, so that I can review findings in the screenshot's information structure.
12. As an existing ARTEX user, I want reports, evidence, disposition, and retest actions preserved in finding details, so that the simpler list does not remove capabilities.
13. As a knowledge maintainer, I want actual knowledge entries with stable codes, summaries, bodies, product applicability, sources, and versions, so that the weapon library contains usable material.
14. As an ARTEX operator, I want knowledge search by category, type, tier, verification status, and optional body matching, so that I can locate relevant entries precisely.
15. As a knowledge maintainer, I want task findings and evidence saved as traceable candidate sources, so that useful experience is not lost after a task ends.
16. As a knowledge maintainer, I want to import, edit, deduplicate, review, publish, revoke, and revalidate entries without creating a custom Agent, so that the knowledge workflow works independently.
17. As an ARTEX operator, I want publication and verification states shown separately, so that a published entry is not incorrectly presented as technically verified.
18. As a knowledge maintainer, I want substantive body changes to require a new verification decision, so that outdated evidence does not certify a new version.
19. As an operator of a built-in Agent, I want the Agent to search and retrieve eligible knowledge through kb_search and kb_get, so that previous work can support a new task.
20. As an ARTEX operator, I want revoked, invalid, unpublished, or unverified entries excluded from default execution retrieval, so that execution uses eligible material.
21. As a knowledge maintainer, I want retrieval counts to record actual body retrieval with retry deduplication, so that browsing and repeated transport requests do not inflate reuse.
22. As an ARTEX operator, I want retrieval counts distinguished from successful validation outcomes, so that usage does not imply effectiveness.
23. As a knowledge maintainer, I want reusable knowledge separated from target-specific secrets and evidence, so that cross-task reuse does not expose unrelated credentials.
24. As an ARTEX operator, I want a real full public CVE metadata corpus available locally, so that the CVE page is useful beyond a demonstration dataset.
25. As an ARTEX operator, I want to search CVE identifiers, products, components, descriptions, and vulnerability terms without network access, so that local research remains available during outages.
26. As an ARTEX operator, I want automatic background synchronization of new CVEs, revisions, references, and source status changes, so that I do not need to update the corpus manually.
27. As an ARTEX operator, I want an automatic-update switch and an immediate-update action, so that I can control synchronization when needed.
28. As an ARTEX operator, I want the last check, last successful update, source version, change counts, failures, and next check time displayed, so that I can judge corpus freshness.
29. As a Linux administrator, I want interrupted CVE updates to resume safely after restart and reconnect, so that outages do not require clearing and rebuilding the database.
30. As an ARTEX operator, I want real CVE totals, year counts, source states, and references, so that the page reflects the actual imported corpus.
31. As an ARTEX operator, I want actual Nuclei templates with versioned metadata and a compatible engine, so that templates can be loaded and used rather than merely listed.
32. As a content maintainer, I want template source, license, compatibility, validation, and execution records, so that content releases can be audited and reproduced.
33. As an ARTEX operator, I want template matches retained as candidate findings with supporting evidence, so that a match alone does not become an unsupported confirmed finding.
34. As an ARTEX operator, I want actual runnable skills with instructions, inputs, outputs, dependencies, and required resources, so that skill directories represent usable workflows.
35. As a skill maintainer, I want categories, tree navigation, import, editing, bindings, and true usage statistics, so that I can maintain the expanded skill collection.
36. As a content maintainer, I want missing screenshot categories populated from sourced or newly authored material, so that missing content is not indefinitely delegated back to the user.
37. As an ARTEX operator, I want weapon-library entries with substantive testing or validation material, tool or template references, applicability, and verification records, so that the library is more than relabeled CVE descriptions.
38. As a content maintainer, I want reproducible content batches with source versions and hashes, so that indexes can be rebuilt offline and prior releases remain traceable.
39. As an ARTEX operator, I want built-in Agent cards to display real bindings and retain existing runtime keys, so that visual alignment does not break tasks or configuration.
40. As an ARTEX operator, I want the worker's intranet context variant selected only from valid task-related sessions or credentials, so that it uses available context rather than assumed access.
41. As an ARTEX operator, I want proxy import, editing, health checks, task leases, and real exit status, so that each task's outbound path is understandable.
42. As an ARTEX operator, I want concurrent tasks to retain their own proxy leases, so that one task does not silently use another task's exit.
43. As an ARTEX operator, I want proxy failure to pause affected work by default and direct fallback to require an explicit setting, so that failures have predictable behavior.
44. As an ARTEX operator, I want target traffic, model traffic, and web-search proxy configuration kept distinct, so that enabling the pool does not unexpectedly reroute other traffic.
45. As an ARTEX operator, I want real C2 and WebShell management rather than an SSH substitute, so that the delivered capability matches the screenshot's session model.
46. As an ARTEX operator, I want an actual HTTP/PHP session integration corresponding to the visible http_phpcmd type, so that session records are connected to a working backend.
47. As an ARTEX operator, I want session state, heartbeat, host, task, URL, and supported operations visible, so that I can understand and manage connected sessions.
48. As an ARTEX operator, I want session operations to produce traceable requests, results, timeouts, and errors, so that operation status reflects the backend's outcome.
49. As an ARTEX operator, I want host topology, subnet grouping, sessions, tunnels, and credential references linked to actual relationships, so that the intranet view does not invent connectivity.
50. As an ARTEX operator, I want session, tunnel, credential, and task filters to update consistently after disconnection or invalidation, so that the intranet view remains current.
51. As an ARTEX operator, I want unavailable protocol operations identified by adapter capabilities, so that unsupported actions are not presented as completed functionality.
52. As an existing ARTEX user, I want my custom Agents, prompts, bindings, triggers, and historical records preserved unchanged, so that this upgrade does not reconfigure my automation.
53. As a Linux administrator, I want reproducible Compose deployment and continued binary startup support, so that I can choose a supported operating model.
54. As a Linux administrator, I want data, skills, content versions, and synchronization state to survive restart and backup restoration, so that upgrades do not lose operational history.
55. As an ARTEX operator, I want meaningful loading, empty, unconfigured, no-match, partial-failure, and expired-credential states, so that incomplete setup and failures are understandable.
56. As an existing ARTEX user, I want task lifecycle, traffic recording, reports, retests, approvals, rules, and logs to keep working, so that new functionality does not regress existing workflows.

## Implementation Decisions

1. Extend the current Go, Next.js, and PostgreSQL architecture. Do not replace the Agent runtime, rebuild the asset model, or introduce another search infrastructure before existing database indexing is measured against real data.
2. Preserve the existing distinction between assets, per-task exploration graphs, intents, findings, evidence, traffic, and conversations. Session and knowledge relationships must reference existing domain identifiers rather than duplicate their identities.
3. Match screenshot-visible navigation, information structure, fields, cards, filters, and entry points while retaining current colors. Hidden dialogs and behaviors follow existing component conventions and explicit acceptance scenarios.
4. Retain old navigation compatibility. Keep existing detailed report, evidence, disposition, and retest functions reachable through detail or advanced views.
5. Reuse task templates and task lifecycle for quick start. Inherit effective model, concurrency, timeout, Token, and interception settings, support applicable task overrides, and make task creation idempotent. Do not impose the previously proposed two-worker, fifteen-minute, or two-hour defaults.
6. Preserve built-in runtime keys including goals and mainagent. Align displayed names and responsibilities without migrating historical references to poets or manager. The worker_intranet behavior is a worker context variant sharing worker resources, not a separately provisioned custom Agent.
7. Select intranet context using task ownership, session or credential validity, and adapter capabilities. Continue to use the existing atomic-intent execution, fact recording, and settlement lifecycle.
8. Add a knowledge service with entries, immutable content versions, candidate sources, verification records, publication state, and usage records. Candidate-source identity plus version and retrieval-call identity provide deduplication.
9. Keep publication and technical verification independent. Default execution retrieval includes only published, valid, verified material. Revocation takes effect immediately; substantive content changes cannot inherit prior verification automatically.
10. Provide manual editing, import, deduplication, review, publication, revocation, and evidence-backed verification management. Collect candidate sources without requiring any new custom Agent.
11. Expose kb_search for summaries and stable codes and kb_get for eligible body retrieval. Count real body retrievals once per logical call. Store outcomes separately from usage counts; do not count list views or searches as reuse.
12. Keep target-specific credentials and raw evidence in controlled task storage; reusable entries contain appropriate redacted material and traceable references. Secrets are not copied from screenshot examples.
13. Import actual full public CVE JSON metadata, retaining source identity, schema version, original record, source state, descriptions, affected-product structures, dates, references, source version, and content hash. Handle relevant CNA and additional containers rather than assuming a single flat record.
14. First import establishes a full baseline. Background incremental synchronization then applies new records, revisions, references, and status changes, including rejected records. A baseline snapshot is a recovery and traceability mechanism, not a frozen corpus.
15. Persist CVE synchronization runs and cursors. Enforce update mutual exclusion, idempotent batch application, commit-safe cursor advancement, restart recovery, backoff, and reconciliation when an incremental window is missed. Keep the last usable corpus available after failures.
16. Expose manual update, automatic-update settings, progress, last check, last success, next check, source version, and separate added/modified/failed counts. Existing settings take precedence; polling cadence and retry parameters remain configurable. Do not characterize periodic polling as real-time push.
17. Use PostgreSQL indexing and structured filters for initial knowledge and CVE search. Validate mixed Chinese/English, aliases, body matching, totals, and pagination against actual content before choosing additional indexing mechanisms.
18. Deliver real Nuclei templates and a compatible, versioned engine. Record template identity, severity, tags, protocol, references, source, license, compatibility, and validation results. Preserve historical template versions referenced by findings.
19. Deliver runnable skill packages, retaining the existing three skills and adding sourced or newly authored content for the screenshot's workflow categories. Each skill includes triggers, inputs, outputs, dependencies, failure behavior, and resources needed for Linux execution. Empty directories and duplicate placeholders do not satisfy delivery.
20. Populate the weapon library with substantive applicability, test or validation material, tool/template references where relevant, provenance, detection/remediation guidance, and verification records. Do not treat a CVE description as an automatically verified weapon or invent the target project's private EXP corpus.
21. Generate reproducible content manifests with source URLs, release or commit versions, hashes, acquisition times, license information, tool/parser versions, and actual availability and validation counts. Keep original material separate from derived indexes and preserve usable prior content after failed updates.
22. Add skill categories and filters without overwriting existing skill bodies or user bindings. Missing categories display as unclassified. Report actual invocation statistics.
23. Add proxy endpoints, health observations, and per-task leases for HTTP, HTTPS, and SOCKS5. Preserve the existing single global proxy behavior until the pool is explicitly enabled.
24. Keep target egress separate from model and web-search proxies. Route recorded and unrecorded target traffic through the same task exit policy; distinguish the system default exit from the active task's exit in the UI.
25. Proxy failure pauses affected work by default; switching and explicit direct fallback are configured and recorded. Never promise unlimited IP supply.
26. Implement native C2/WebShell management and intranet relationships with replaceable protocol integrations. An actual HTTP/PHP session backend corresponding to the screenshot's visible type is mandatory; SSH does not satisfy this acceptance requirement.
27. Track integration capabilities, connection state, session source identifiers, task and host association, heartbeat, disconnection reason, tunnels, scoped credential references, and operation records. Distinguish disconnected sessions, invalid credentials, and unreachable integrations.
28. Session operations expose explicit supported capabilities and traceable request, completion, failure, and timeout states. Do not infer an undocumented private request format from the http_phpcmd label or invent topology edges from subnet membership alone.
29. Docker metrics report container CPU/memory usage and effective limits with scope, units, and sampling time. Binary deployments report corresponding Linux process metrics. Whole-host metrics require explicit integration rather than relabeling container values.
30. Use compatible additive database migrations under the current startup migration mechanism. Do not rename existing runtime identifiers, overwrite prompts, reconfigure custom Agents, or delete new data to perform an application rollback.
31. Paginate lists, bound import and search requests, and run long imports as observable background jobs that survive page navigation. Separate import capacity from business-task concurrency to avoid starving active work.
32. Preserve existing authentication, task ownership, interception, and approval contracts. Store credential references consistently with controlled configuration and exclude secret values from normal logs and list responses.
33. Package for Linux Compose and binary startup, including persistence and content preparation. Backups cover PostgreSQL, runtime data, skills, and versioned content. Application rollback leaves compatible additive structures intact; database recovery uses a tested backup.
34. Implement in four milestones: existing UI/workflow alignment; knowledge/CVE and actual content; proxies plus C2/WebShell and intranet integration; Linux end-to-end delivery and regression. Milestones establish order and do not remove later requirements.

## Testing Decisions

The primary testing seam is the existing authenticated HTTP application boundary backed by real PostgreSQL and the real task lifecycle. Exercise public requests and observe responses, state transitions, retrieval eligibility, visible counts, operation records, and restart persistence. Focused browser acceptance and actual protocol integration acceptance complement this application boundary. This testing approach was presented during specification preparation and retained when the user requested continuation of the to-spec publication workflow.

- Reuse the repository's HTTP Handler integration-test approach demonstrated by TestCoreTaskLifecyclePG, TestTaskTemplateHTTPCRUD, and TestWorkerControlRoutes. Extend observable feature behavior rather than asserting private helper calls, exact SQL, or internal storage layout.
- Run against an available test PostgreSQL service. A skipped database test is not evidence of a passing integration acceptance check.
- Exercise quick-start inheritance and idempotency, finding filters, knowledge publication/version invalidation/revocation, retrieval retry deduplication, authorization failures, pagination, and custom-configuration preservation through the same primary boundary.
- Exercise CVE full import, new records, revisions, rejected-state changes, interrupted batches, duplicate batches, missing incremental windows, restart recovery, and offline queries using controlled source responses. Assert public corpus results, update status, and continued availability of prior data.
- Exercise template import, source and compatibility metadata, failed validation, prior-version retention, and actual engine loading. Validate runnable skill inputs, outputs, required dependencies, and failure reporting. Inspect content coverage by category rather than treating a global count as sufficient.
- Exercise concurrent proxy leases, recorded and unrecorded traffic paths, distinct task exits, unhealthy endpoints, configured switching, default pause, and explicit direct fallback through observable task and egress behavior.
- Exercise session connection, heartbeat, operation completion, timeout, disconnection, task ownership, credential invalidation, capability errors, topology changes, and intranet context selection through public management behavior. Use controlled backend fixtures for repeatability and at least one actual HTTP/PHP integration for release acceptance; a stub alone cannot certify the real integration.
- Add focused browser acceptance for navigation, screenshot-visible structure, filters, row expansion, quick start, update status, errors, and empty/unconfigured states. Browser checks complement the primary application seam; they do not require a second new internal testing abstraction.
- Validate Linux Compose cold start, upgrade with existing data, restart, backup restoration, content-index rebuild, and application rollback. Compare CPU/memory readings with measurements using the same scope and denominator.
- Regress existing task lifecycle, traffic recording, reports, retests, interception rules, approvals, and logs. Preserve task/exploration/asset distinctions and existing custom Agent records.
- Record application revision, content manifests, source and engine versions, adapter versions, environment, hardware scope, results, and unresolved failures. Passing page rendering, source research, or mocked integration alone is not complete acceptance.

## Out of Scope

- Adding or modifying custom Agent prompts, bindings, resources, role counts, specialist triggers, or their orchestration. Existing custom Agent behavior remains available and unchanged.
- Forcing fourteen cards or the screenshot's exact MCP, Skill, or tool counts through placeholders or duplicate resources.
- Copying the target project's unavailable private prompts, private protocol implementation, private knowledge corpus, or private EXP collection; claiming identical hidden behavior without evidence.
- Hardcoding screenshot totals, historical target data, credentials, success rates, zero-incident claims, or unlimited IP availability.
- Replacing C2/WebShell delivery with SSH-only access or static management pages.
- Model training or fine-tuning, and presenting experience storage as model training.
- A standalone search platform, vector database, or broader architecture rewrite without demonstrated need.
- Detection-bypass implementation, real fund transfers, or added functionality inferred solely from names of excluded custom Agents.
- Guaranteed performance thresholds before measuring the actual corpus and deployment environment.

## Further Notes

The eight images are the complete target-project evidence available to the user. The dashboard chat-window overlay is not an ARTEX component. Screenshot dates and counts are historical visual evidence rather than authoritative source data or dataset requirements.

Primary content sources already investigated include CVEProject/cvelistV5, ProjectDiscovery/nuclei and nuclei-templates, the Agent Skills specification, OWASP WSTG, and OWASP Cheat Sheet Series. Their content has not yet been downloaded or delivered. Verify exact release licenses and compatibility during content preparation, retain attribution, and do not assume the engine's license automatically covers every template or third-party resource.

Adapter selection, upstream version selection, source-format verification, deployment capacity measurements, and concrete skill/content inventories are implementation investigations, not missing information the user must supply. Material changes to accepted scope must be made explicit; missing private source material is not permission to ship empty modules.

Current deliverables are repository investigation, the confirmed requirements, a technical implementation plan, source research, and an acceptance matrix. No product implementation or dataset import is represented as completed by this spec.

The configured publication target is the GitHub Issues tracker for 1807142316-cmyk/ARTEX with the ready-for-agent label. The repository's engineering-skill configuration is authoritative for future tracker or label changes.
