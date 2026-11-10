# Issue tracker：GitHub

Issues 和 specs 存放在 `1807142316-cmyk/ARTEX` 的 GitHub Issues。使用 `gh` CLI，并显式指定 `--repo 1807142316-cmyk/ARTEX`，避免 fork 或上游默认值改变发布目标。

## 操作约定

- 发布前核对目标：`gh repo view 1807142316-cmyk/ARTEX --json nameWithOwner,url,hasIssuesEnabled`。
- 创建：`gh issue create --repo 1807142316-cmyk/ARTEX --title "..." --body-file <body-file>`。多行正文写入 UTF-8 文件，使用 `--body-file` 保留格式。
- 读取：`gh issue view <number> --repo 1807142316-cmyk/ARTEX --json number,title,body,labels,comments`。
- 列出：`gh issue list --repo 1807142316-cmyk/ARTEX --state open --json number,title,body,labels,comments`，按需使用 `--label` 和 `--state`。
- 修改正文：`gh issue edit <number> --repo 1807142316-cmyk/ARTEX --body-file <body-file>`。
- 标签：`gh issue edit <number> --repo 1807142316-cmyk/ARTEX --add-label "..."` 或 `--remove-label "..."`。角色映射见 `triage-labels.md`。
- 评论：`gh issue comment <number> --repo 1807142316-cmyk/ARTEX --body-file <body-file>`。
- 关闭：先发布说明，再运行 `gh issue close <number> --repo 1807142316-cmyk/ARTEX`；说明发布成功后才关闭。

Skill 要求“publish to the issue tracker”时，创建 GitHub issue；要求“fetch the relevant ticket”时，读取对应 issue。创建前检查是否已有同一任务的 issue，避免重试造成重复发布。

只向上述仓库发布；更换仓库需要用户明确指示。

## 子任务与依赖

优先使用 GitHub 原生 sub-issues 和 issue dependencies。先检查当前 CLI 是否支持相应选项；使用 API 时，sub-issue/dependency 参数需要 issue 的 database ID，而非展示编号或 node ID。

若当前服务或 CLI 不支持原生关系，在 child issue 正文标注 `Part of #<parent>` 和 `Blocked by: #<number>`，并在父 issue 维护子任务清单。只有未关闭的依赖会阻塞任务。

## PRs 作为 triage surface

**PRs as a request surface: no.**
