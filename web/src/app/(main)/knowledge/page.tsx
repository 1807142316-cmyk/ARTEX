"use client";

import * as React from "react";

import { BookOpen, Check, ChevronDown, Plus, Search, ShieldCheck, Upload } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { KnowledgeCandidate, KnowledgeEntry, KnowledgeHistory, KnowledgeInput } from "@/lib/types";

const emptyDraft = {
  code: "",
  category: "web",
  kind: "checklist",
  tier: "low",
  summary: "",
  body: "",
  source_url: "",
  source_version: "",
};

export default function KnowledgePage() {
  const [items, setItems] = React.useState<KnowledgeEntry[]>([]);
  const [query, setQuery] = React.useState("");
  const [matchBody, setMatchBody] = React.useState(true);
  const [filter, setFilter] = React.useState("all");
  const [loading, setLoading] = React.useState(true);
  const [selected, setSelected] = React.useState<KnowledgeEntry | null>(null);
  const [draft, setDraft] = React.useState(emptyDraft);
  const [showEditor, setShowEditor] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [history, setHistory] = React.useState<KnowledgeHistory | null>(null);
  const [showHistory, setShowHistory] = React.useState(false);
  const [operation, setOperation] = React.useState<"verify" | "review" | null>(null);
  const [notes, setNotes] = React.useState("");
  const [verificationResult, setVerificationResult] = React.useState<"passed" | "failed">("passed");
  const [approved, setApproved] = React.useState(true);
  const [redacted, setRedacted] = React.useState(false);
  const [category, setCategory] = React.useState("");
  const [kind, setKind] = React.useState("");
  const [tier, setTier] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [total, setTotal] = React.useState(0);
  const loadSequence = React.useRef(0);
  const importInput = React.useRef<HTMLInputElement>(null);
  const [editingID, setEditingID] = React.useState<number | null>(null);
  const [candidates, setCandidates] = React.useState<KnowledgeCandidate[]>([]);
  const [candidateID, setCandidateID] = React.useState<number | null>(null);
  const [candidateRedacted, setCandidateRedacted] = React.useState(false);
  const [showCandidates, setShowCandidates] = React.useState(false);

  const load = React.useCallback(async () => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    try {
      const result = await api.knowledge({
        q: query,
        match_body: matchBody,
        category,
        kind,
        tier,
        page,
        verified: filter === "verified" ? true : undefined,
        published: filter === "published" ? true : undefined,
        limit: 50,
      });
      if (sequence !== loadSequence.current) return;
      setTotal(result.total);
      setItems(result.items);
      setSelected((current) =>
        current ? (result.items.find((item) => item.id === current.id) ?? null) : (result.items[0] ?? null),
      );
    } catch (error) {
      toast.error(`知识库加载失败：${(error as Error).message}`);
    } finally {
      if (sequence === loadSequence.current) setLoading(false);
    }
  }, [query, matchBody, filter, category, kind, tier, page]);

  React.useEffect(() => {
    void load();
  }, [load]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset entry-specific panels when selection changes.
  React.useEffect(() => {
    setShowHistory(false);
    setHistory(null);
    setOperation(null);
  }, [selected?.id]);

  async function importEntries(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 240 * 1024) {
      toast.error("单次导入文件不能超过 240 KiB");
      return;
    }
    setSaving(true);
    try {
      const data: unknown = JSON.parse(await file.text());
      const entries = Array.isArray(data) ? data : (data as { items?: unknown })?.items;
      if (!Array.isArray(entries) || entries.length < 1 || entries.length > 100)
        throw new Error("需要包含 1–100 条记录的 JSON 数组或 items 数组");
      const result = await api.importKnowledge(entries as KnowledgeInput[]);
      toast.success(`已导入 ${result.created} 条，跳过 ${result.skipped} 条相同记录`);
      await load();
    } catch (error) {
      toast.error(`导入失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function loadHistory(entry: KnowledgeEntry) {
    try {
      setHistory(await api.knowledgeHistory(entry.id));
      setShowHistory(true);
    } catch (error) {
      toast.error(`历史记录加载失败：${(error as Error).message}`);
    }
  }

  async function createEntry(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      let saved: KnowledgeEntry;
      if (candidateID)
        saved = await api.promoteKnowledgeCandidate(candidateID, { ...draft, redacted: candidateRedacted });
      else if (editingID) saved = await api.updateKnowledge(editingID, draft);
      else saved = await api.createKnowledge(draft);
      setShowEditor(false);
      setDraft(emptyDraft);
      setEditingID(null);
      setCandidateID(null);
      setShowCandidates(false);
      setSelected(saved);
      toast.success(editingID ? "条目已更新，新版本需要重新验证" : "知识条目已创建，需完成验证后才能发布");
      await load();
    } catch (error) {
      toast.error(`创建失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function recordDecision(event: React.FormEvent) {
    event.preventDefault();
    if (!selected || !notes.trim()) return;
    setSaving(true);
    try {
      const updated =
        operation === "verify"
          ? await api.verifyKnowledge(selected.id, selected.content_version, verificationResult, notes.trim())
          : await api.reviewKnowledge(selected.id, selected.content_version, approved, redacted, notes.trim());
      setSelected(updated);
      setOperation(null);
      setNotes("");
      setShowHistory(false);
      await load();
    } catch (error) {
      toast.error(`保存记录失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function publish(entry: KnowledgeEntry) {
    try {
      const updated = await api.publishKnowledge(entry.id);
      setSelected(updated);
      toast.success("条目已发布");
      await load();
    } catch (error) {
      toast.error(`发布失败：${(error as Error).message}`);
    }
  }

  async function revoke(entry: KnowledgeEntry) {
    try {
      const updated = await api.revokeKnowledge(entry.id);
      setSelected(updated);
      toast.success("条目已撤销");
      await load();
    } catch (error) {
      toast.error(`撤销失败：${(error as Error).message}`);
    }
  }

  return (
    <main className="flex h-full min-h-0 flex-col gap-4 p-4 md:p-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-2xl">
            <BookOpen className="size-5" />
            武器库
          </h1>
          <p className="text-muted-foreground text-sm">
            可检索、验证并复用的知识条目。发布状态与技术验证状态分别记录。
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => {
              void api.knowledgeCandidates().then(
                (result) => {
                  setCandidates(result.items);
                  setShowCandidates((open) => !open);
                },
                (error: Error) => toast.error(`候选加载失败：${error.message}`),
              );
            }}
          >
            候选来源
          </Button>
          <input
            ref={importInput}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={(event) => void importEntries(event)}
          />
          <Button variant="outline" disabled={saving} onClick={() => importInput.current?.click()}>
            <Upload className="mr-2 size-4" />
            导入 JSON
          </Button>
          <Button
            onClick={() => {
              setEditingID(null);
              setCandidateID(null);
              setDraft(emptyDraft);
              setShowEditor((open) => !open);
            }}
          >
            <Plus className="mr-2 size-4" />
            新增条目
          </Button>
        </div>
      </header>

      {showCandidates && (
        <Card>
          <CardHeader>
            <CardTitle>知识候选来源</CardTitle>
          </CardHeader>
          <CardContent className="grid max-h-72 gap-3 overflow-auto">
            {candidates.length === 0 && (
              <p className="text-muted-foreground text-sm">从发现列表的“知识候选”操作收集来源。</p>
            )}
            {candidates.map((candidate) => (
              <div
                key={candidate.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3"
              >
                <div className="grid gap-1 text-sm">
                  <span>
                    来源 {candidate.source_identity} · 证据版本 {candidate.source_version} ·{" "}
                    {candidate.evidence_refs.length} 个证据引用
                  </span>
                  <span className="break-all font-mono text-muted-foreground text-xs">
                    SHA256 {candidate.source_hash}
                  </span>
                  {candidate.task_id && (
                    <a className="underline" href={`/function/tasks/detail?id=${candidate.task_id}`}>
                      任务 #{candidate.task_id}
                    </a>
                  )}
                  {candidate.finding_id && (
                    <a className="underline" href={`/function/findings/detail?id=${candidate.finding_id}`}>
                      发现 #{candidate.finding_id}
                    </a>
                  )}
                </div>
                <Button
                  size="sm"
                  disabled={candidate.entry_id !== null}
                  onClick={() => {
                    setCandidateID(candidate.id);
                    setCandidateRedacted(false);
                    setEditingID(null);
                    setDraft({
                      ...emptyDraft,
                      code: `KB-FINDING-${candidate.finding_id ?? candidate.id}-${candidate.id}`,
                    });
                    setShowEditor(true);
                  }}
                >
                  {candidate.entry_id ? `已整理为 #${candidate.entry_id}` : "整理为草稿"}
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {showEditor && (
        <Card>
          <CardHeader>
            <CardTitle>
              {candidateID ? `整理候选 #${candidateID}` : editingID ? "编辑知识条目" : "新建知识条目"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form className="grid gap-3 md:grid-cols-2" onSubmit={createEntry}>
              {candidateID && (
                <label className="flex items-center gap-2 text-sm md:col-span-2">
                  <input
                    type="checkbox"
                    required
                    checked={candidateRedacted}
                    onChange={(event) => setCandidateRedacted(event.target.checked)}
                  />
                  正文由人工整理，不包含原始目标证据、凭据和身份信息；来源引用会单独保留。
                </label>
              )}
              {(["code", "category", "kind", "tier", "source_url", "source_version"] as const).map((key) => (
                <div className="grid gap-1.5" key={key}>
                  <Label htmlFor={`knowledge-${key}`}>
                    {
                      {
                        code: "编码",
                        category: "分类",
                        kind: "类型",
                        tier: "等级",
                        source_url: "来源 URL",
                        source_version: "来源版本",
                      }[key]
                    }
                  </Label>
                  <Input
                    id={`knowledge-${key}`}
                    required={key === "code"}
                    value={draft[key]}
                    onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))}
                  />
                </div>
              ))}
              <div className="grid gap-1.5 md:col-span-2">
                <Label htmlFor="knowledge-summary">摘要</Label>
                <Input
                  id="knowledge-summary"
                  required
                  value={draft.summary}
                  onChange={(event) => setDraft((current) => ({ ...current, summary: event.target.value }))}
                />
              </div>
              <div className="grid gap-1.5 md:col-span-2">
                <Label htmlFor="knowledge-body">正文</Label>
                <Textarea
                  id="knowledge-body"
                  required
                  rows={7}
                  value={draft.body}
                  onChange={(event) => setDraft((current) => ({ ...current, body: event.target.value }))}
                />
              </div>
              <div className="flex justify-end gap-2 md:col-span-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowEditor(false);
                    setEditingID(null);
                  }}
                >
                  取消
                </Button>
                <Button disabled={saving}>{saving ? "保存中…" : editingID ? "保存新版本" : "保存草稿"}</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.9fr)]">
        <Card className="flex min-h-0 flex-col">
          <CardHeader className="gap-3">
            <div className="flex flex-wrap gap-2">
              {[
                { value: "all", label: "全部" },
                { value: "verified", label: "已验证" },
                { value: "published", label: "已发布" },
              ].map((option) => (
                <Button
                  key={option.value}
                  variant={filter === option.value ? "secondary" : "ghost"}
                  size="sm"
                  onClick={() => {
                    setFilter(option.value);
                    setPage(1);
                  }}
                >
                  {option.label}
                </Button>
              ))}
            </div>
            <div className="relative">
              <Search className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="搜索编码、摘要或正文"
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <Input
                aria-label="分类筛选"
                placeholder="分类"
                value={category}
                onChange={(event) => {
                  setCategory(event.target.value);
                  setPage(1);
                }}
              />
              <Input
                aria-label="类型筛选"
                placeholder="类型"
                value={kind}
                onChange={(event) => {
                  setKind(event.target.value);
                  setPage(1);
                }}
              />
              <Input
                aria-label="等级筛选"
                placeholder="等级"
                value={tier}
                onChange={(event) => {
                  setTier(event.target.value);
                  setPage(1);
                }}
              />
            </div>
          </CardHeader>
          <label className="flex items-center gap-2 px-6 pb-3 text-sm">
            <input
              type="checkbox"
              checked={matchBody}
              onChange={(event) => {
                setMatchBody(event.target.checked);
                setPage(1);
              }}
            />
            匹配正文
          </label>
          <CardContent className="min-h-0 flex-1 overflow-auto">
            {loading ? (
              <p className="py-8 text-center text-muted-foreground text-sm">正在加载知识条目…</p>
            ) : items.length === 0 ? (
              <p className="py-8 text-center text-muted-foreground text-sm">暂无匹配条目</p>
            ) : (
              <div className="divide-y">
                {items.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`w-full rounded-md px-3 py-3 text-left hover:bg-muted/60 ${selected?.id === item.id ? "bg-muted" : ""}`}
                    onClick={() => setSelected(item)}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-semibold text-sm">{item.code}</span>
                      <Badge variant="outline">{item.category || "未分类"}</Badge>
                      <Badge variant={item.verified ? "default" : "secondary"}>
                        {item.verified ? "已验证" : "待验证"}
                      </Badge>
                      {item.published && <Badge variant="outline">已发布</Badge>}
                    </div>
                    <p className="mt-1 line-clamp-2 text-muted-foreground text-sm">{item.summary}</p>
                    <div className="mt-2 flex gap-3 text-muted-foreground text-xs">
                      <span>版本 v{item.content_version}</span>
                      <span>复用 {item.use_count}</span>
                      <span>{item.kind || "未分类"}</span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </CardContent>
          <div className="flex items-center justify-between border-t px-5 py-3 text-sm">
            <span>
              共 {total} 条 · 第 {page} 页
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 1 || loading}
                onClick={() => setPage((current) => current - 1)}
              >
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page * 50 >= total || loading}
                onClick={() => setPage((current) => current + 1)}
              >
                下一页
              </Button>
            </div>
          </div>
        </Card>

        <Card className="min-h-0 overflow-auto">
          {selected ? (
            <>
              <CardHeader className="border-b">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <CardTitle className="font-mono">{selected.code}</CardTitle>
                    <p className="mt-1 text-muted-foreground text-sm">{selected.summary}</p>
                  </div>
                  <ChevronDown className="size-4 text-muted-foreground" />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">{selected.category || "未分类"}</Badge>
                  <Badge variant="outline">{selected.kind || "未分类"}</Badge>
                  <Badge variant="outline">{selected.tier || "未分档"}</Badge>
                  <Badge variant={selected.verified ? "default" : "secondary"}>
                    {selected.verified ? "已验证" : "未验证"}
                  </Badge>
                  <Badge variant={selected.reviewed ? "default" : "secondary"}>
                    {selected.reviewed ? "审核通过" : "待审核"}
                  </Badge>
                  {selected.revoked && <Badge variant="destructive">已撤销</Badge>}
                  <Badge variant={selected.published ? "default" : "outline"}>
                    {selected.published ? "已发布" : "未发布"}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="grid gap-4 py-4">
                <article className="whitespace-pre-wrap text-sm leading-6">
                  {selected.body || "此条目没有正文。"}
                </article>
                <div className="grid gap-1 border-t pt-3 text-muted-foreground text-xs">
                  <span>来源：{selected.source_url || "未提供"}</span>
                  <span>
                    来源版本：{selected.source_version || "未指定"} · 当前内容版本：v{selected.content_version}
                  </span>
                  <span>验证：{selected.verification_result || "尚无当前版本验证记录"}</span>
                </div>
                <div className="flex flex-wrap gap-2 border-t pt-3">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setOperation("verify");
                      setNotes("");
                      setVerificationResult("passed");
                    }}
                  >
                    <ShieldCheck className="mr-1 size-4" />
                    {selected.verified ? "重新验证" : "记录验证"}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setOperation("review");
                      setNotes("");
                      setApproved(true);
                      setRedacted(false);
                    }}
                  >
                    审核内容
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => void loadHistory(selected)}>
                    版本及审核记录
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setEditingID(selected.id);
                      setCandidateID(null);
                      setDraft({
                        code: selected.code,
                        category: selected.category,
                        kind: selected.kind,
                        tier: selected.tier,
                        summary: selected.summary,
                        body: selected.body ?? "",
                        source_url: selected.source_url,
                        source_version: selected.source_version,
                      });
                      setShowEditor(true);
                    }}
                  >
                    编辑
                  </Button>
                  {selected.verified && selected.reviewed && !selected.revoked && !selected.published && (
                    <Button size="sm" onClick={() => void publish(selected)}>
                      <Check className="mr-1 size-4" />
                      发布
                    </Button>
                  )}
                  {selected.published && !selected.revoked && (
                    <Button size="sm" variant="destructive" onClick={() => void revoke(selected)}>
                      撤销发布
                    </Button>
                  )}
                </div>
                {operation && (
                  <form onSubmit={recordDecision} className="grid gap-3 rounded-md border p-3">
                    <h3 className="font-medium text-sm">
                      {operation === "verify"
                        ? `验证 v${selected.content_version}`
                        : `审核 v${selected.content_version}`}
                    </h3>
                    {operation === "verify" ? (
                      <select
                        aria-label="验证结论"
                        className="rounded-md border bg-background p-2 text-sm"
                        value={verificationResult}
                        onChange={(event) => setVerificationResult(event.target.value as "passed" | "failed")}
                      >
                        <option value="passed">通过</option>
                        <option value="failed">失败</option>
                      </select>
                    ) : (
                      <>
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={approved}
                            onChange={(event) => setApproved(event.target.checked)}
                          />
                          审核通过
                        </label>
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={redacted}
                            onChange={(event) => setRedacted(event.target.checked)}
                          />
                          已检查正文和来源，不包含目标凭据、令牌或敏感证据
                        </label>
                      </>
                    )}
                    <Label htmlFor="knowledge-decision-notes">
                      {operation === "verify" ? "验证依据（单独保存，不进入 Agent 复用正文）" : "审核说明"}
                    </Label>
                    <Textarea
                      id="knowledge-decision-notes"
                      required
                      maxLength={20000}
                      rows={4}
                      value={notes}
                      onChange={(event) => setNotes(event.target.value)}
                    />
                    <div className="flex justify-end gap-2">
                      <Button type="button" variant="outline" size="sm" onClick={() => setOperation(null)}>
                        取消
                      </Button>
                      <Button size="sm" disabled={saving || (operation === "review" && approved && !redacted)}>
                        保存记录
                      </Button>
                    </div>
                  </form>
                )}
                {showHistory && history && (
                  <div className="grid gap-3 border-t pt-3">
                    {history.candidate_sources.map((source) => (
                      <div key={source.id} className="rounded-md border p-2 text-sm">
                        <strong>候选来源 {source.source_identity}</strong> · 证据版本 {source.source_version}
                        <p className="break-all font-mono text-xs">SHA256 {source.source_hash}</p>
                        <p>
                          {source.evidence_refs.map((ref) => `证据 #${ref.binding_id} / ${ref.snapshot_id}`).join("；")}
                        </p>
                      </div>
                    ))}
                    <h3 className="font-medium text-sm">最近 100 条版本及决策记录</h3>
                    {history.versions.map((version) => (
                      <details key={version.version} className="rounded-md border p-2 text-sm">
                        <summary>
                          v{version.version} · {version.code} · {new Date(version.created_at).toLocaleString()}
                        </summary>
                        <p className="mt-2 whitespace-pre-wrap">{version.body}</p>
                        <p className="mt-2 break-all text-muted-foreground text-xs">SHA256 {version.content_hash}</p>
                      </details>
                    ))}
                    {history.verifications.map((item, index) => (
                      <div key={`verification-${index}`} className="rounded-md border p-2 text-sm">
                        <strong>
                          v{item.version} 验证{item.result === "passed" ? "通过" : "失败"}
                        </strong>{" "}
                        · {item.verified_by}
                        <p className="whitespace-pre-wrap">{item.evidence}</p>
                      </div>
                    ))}
                    {history.reviews.map((item, index) => (
                      <div key={`review-${index}`} className="rounded-md border p-2 text-sm">
                        <strong>
                          v{item.version} 审核{item.approved && item.redacted ? "通过" : "未通过"}
                        </strong>{" "}
                        · {item.reviewed_by}
                        <p className="whitespace-pre-wrap">{item.notes}</p>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </>
          ) : (
            <CardContent className="py-10 text-center text-muted-foreground text-sm">
              选择一条知识记录以查看详情。
            </CardContent>
          )}
        </Card>
      </div>
    </main>
  );
}
