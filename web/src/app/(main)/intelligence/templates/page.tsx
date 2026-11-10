"use client";

import * as React from "react";

import { SearchIcon, ShieldCheckIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ScanTemplate, ScanTemplateEngine, ScanTemplateRun } from "@/lib/types";

export default function ScanTemplatesPage() {
  const [items, setItems] = React.useState<ScanTemplate[]>([]);
  const [total, setTotal] = React.useState(0);
  const [query, setQuery] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [page, setPage] = React.useState(1);
  const [refresh, setRefresh] = React.useState(0);
  const [content, setContent] = React.useState("");
  const [sourceURL, setSourceURL] = React.useState("");
  const [sourceVersion, setSourceVersion] = React.useState("");
  const [license, setLicense] = React.useState("");
  const [importing, setImporting] = React.useState(false);
  const [importResult, setImportResult] = React.useState("");
  const [importError, setImportError] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [taskID, setTaskID] = React.useState("");
  const [engine, setEngine] = React.useState<ScanTemplateEngine | null>(null);
  const [runError, setRunError] = React.useState("");
  const [starting, setStarting] = React.useState(false);
  const [runs, setRuns] = React.useState<ScanTemplateRun[]>([]);
  const [runTotal, setRunTotal] = React.useState(0);
  const [runPage, setRunPage] = React.useState(1);
  const [selectedRun, setSelectedRun] = React.useState<ScanTemplateRun | null>(null);

  React.useEffect(() => {
    let disposed = false;
    api
      .scanTemplateEngine()
      .then((value) => {
        if (!disposed) setEngine(value);
      })
      .catch((reason: unknown) => {
        if (!disposed) setRunError(reason instanceof Error ? reason.message : "引擎状态读取失败");
      });
    const load = () =>
      api
        .scanTemplateRuns(runPage)
        .then((value) => {
          if (!disposed) {
            setRuns(value.items);
            setRunTotal(value.total);
          }
        })
        .catch((reason: unknown) => {
          if (!disposed) setRunError(reason instanceof Error ? reason.message : "执行历史读取失败");
        });
    void load();
    const timer = setInterval(load, 2500);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [runPage]);

  async function runTemplate(template: ScanTemplate) {
    setStarting(true);
    setRunError("");
    try {
      const run = await api.startScanTemplateRun(template.id, template.content_hash, target, taskID);
      setSelectedRun(run);
      setRunPage(1);
      const result = await api.scanTemplateRuns();
      setRuns(result.items);
      setRunTotal(result.total);
    } catch (reason: unknown) {
      setRunError(reason instanceof Error ? reason.message : "执行启动失败");
    } finally {
      setStarting(false);
    }
  }

  async function viewRun(id: number) {
    try {
      setSelectedRun(await api.scanTemplateRun(id));
      setRunError("");
    } catch (reason: unknown) {
      setRunError(reason instanceof Error ? reason.message : "执行记录读取失败");
    }
  }

  async function importTemplate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setImporting(true);
    setImportError("");
    setImportResult("");
    try {
      const template = await api.importScanTemplate({
        content,
        source_url: sourceURL,
        source_version: sourceVersion,
        license,
      });
      setImportResult(`${template.id} 已通过结构校验并导入。`);
      setContent("");
      setPage(1);
      setRefresh((value) => value + 1);
    } catch (reason: unknown) {
      setImportError(reason instanceof Error ? reason.message : "模板导入失败");
    } finally {
      setImporting(false);
    }
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: successful imports invalidate the current catalog page.
  React.useEffect(() => {
    let disposed = false;
    const timer = setTimeout(() => {
      setLoading(true);
      api
        .scanTemplates(query.trim(), severity === "all" ? "" : severity, page)
        .then((result) => {
          if (disposed) return;
          setItems(result.items);
          setTotal(result.total);
          setError("");
        })
        .catch((reason: unknown) => {
          if (disposed) return;
          setError(reason instanceof Error ? reason.message : "模板目录暂不可用");
        })
        .finally(() => {
          if (!disposed) setLoading(false);
        });
    }, 180);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [query, severity, page, refresh]);

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">扫描模板</h1>
        <p className="text-muted-foreground text-sm">
          静态 HTTP GET 与状态码检查，由固定版本 Nuclei 执行。命中会进入待审发现，并保留执行版本与请求响应。
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>模板目录</CardTitle>
          <CardDescription>{loading ? "正在读取目录…" : `共 ${total} 个模板`}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2 rounded-md border p-3">
            <p className="text-sm">
              Nuclei {engine?.version ?? "…"} · {engine?.available ? "可用" : (engine?.error ?? "正在检查引擎")}
            </p>
            <Input
              type="url"
              aria-label="模板运行目标"
              placeholder="HTTP(S) 目标 URL"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
            />
            <Input
              aria-label="模板运行关联任务"
              placeholder="关联任务 ID（可选）"
              value={taskID}
              onChange={(event) => setTaskID(event.target.value)}
            />
            <p className="text-muted-foreground text-xs">
              每次执行最多 16 个静态路径；不跟随重定向。支持范围以导入校验结果为准。
            </p>
            {runError && (
              <p role="alert" className="text-destructive text-sm">
                {runError}
              </p>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <div className="relative min-w-52 flex-1">
              <SearchIcon className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                className="pl-8"
                aria-label="搜索扫描模板"
                placeholder="搜索名称、标签或描述"
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
              />
            </div>
            <Select
              value={severity}
              onValueChange={(value) => {
                setSeverity(value ?? "all");
                setPage(1);
              }}
            >
              <SelectTrigger className="w-40" aria-label="按严重性筛选">
                <SelectValue placeholder="全部严重性" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部严重性</SelectItem>
                <SelectItem value="info">信息</SelectItem>
                <SelectItem value="low">低</SelectItem>
                <SelectItem value="medium">中</SelectItem>
                <SelectItem value="high">高</SelectItem>
                <SelectItem value="critical">严重</SelectItem>
                <SelectItem value="unknown">未知</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}
          {!loading && !error && items.length === 0 && (
            <p className="py-8 text-center text-muted-foreground text-sm">当前目录没有匹配的模板。</p>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            {items.map((template) => (
              <Card key={`${template.id}:${template.content_hash}`}>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <CardTitle className="text-base">{template.name}</CardTitle>
                      <CardDescription className="font-mono">{template.id}</CardDescription>
                    </div>
                    <Badge variant="outline">{template.severity}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <p className="text-muted-foreground">{template.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {template.tags.map((tag) => (
                      <Badge key={tag} variant="secondary">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                  <div className="flex items-center gap-1 text-muted-foreground text-xs">
                    <ShieldCheckIcon className="size-3.5" /> 被动 HTTP GET · {template.license} ·{" "}
                    {template.source_version || "项目内容"}
                  </div>
                  <p className="break-all font-mono text-[11px] text-muted-foreground">
                    SHA-256 {template.content_hash}
                  </p>
                  {template.source_url && (
                    <a
                      className="block truncate text-xs underline"
                      href={template.source_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      来源：{template.source_url}
                    </a>
                  )}
                  {template.references.map((reference) => (
                    <a
                      key={reference}
                      className="block truncate text-xs underline"
                      href={reference}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {reference}
                    </a>
                  ))}
                  <details className="rounded-md border p-2">
                    <summary className="cursor-pointer text-xs">查看模板内容</summary>
                    <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap text-xs">{template.content}</pre>
                  </details>
                  <Button
                    type="button"
                    disabled={starting || !engine?.available || !target.trim()}
                    onClick={() => void runTemplate(template)}
                  >
                    运行此版本
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
          <div className="flex items-center justify-end gap-2">
            <Button variant="outline" disabled={loading || page <= 1} onClick={() => setPage(page - 1)}>
              上一页
            </Button>
            <span className="text-muted-foreground text-xs">第 {page} 页</span>
            <Button variant="outline" disabled={loading || page * 20 >= total} onClick={() => setPage(page + 1)}>
              下一页
            </Button>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>执行历史</CardTitle>
          <CardDescription>共 {runTotal} 条。列表不包含请求响应；展开记录后读取证据。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {runs.length === 0 && <p className="text-muted-foreground text-sm">尚无执行记录。</p>}
          {runs.map((run) => (
            <div
              key={run.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm"
            >
              <div>
                <p>
                  #{run.id} · {run.template_id} · <Badge variant="outline">{run.status}</Badge>
                </p>
                <p className="break-all text-muted-foreground text-xs">
                  {run.target} · {new Date(run.created_at).toLocaleString()}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => void viewRun(run.id)}>
                查看结果与证据
              </Button>
            </div>
          ))}
          <div className="flex items-center justify-end gap-2">
            <Button variant="outline" disabled={runPage <= 1} onClick={() => setRunPage(runPage - 1)}>
              上一页
            </Button>
            <span className="text-xs">第 {runPage} 页</span>
            <Button variant="outline" disabled={runPage * 20 >= runTotal} onClick={() => setRunPage(runPage + 1)}>
              下一页
            </Button>
          </div>
          {selectedRun && (
            <div className="space-y-2 rounded-md border p-3 text-sm">
              <div className="flex justify-between gap-2">
                <p>
                  #{selectedRun.id} · {selectedRun.status} · Nuclei {selectedRun.engine_version}
                </p>
                <Button size="sm" variant="outline" onClick={() => void viewRun(selectedRun.id)}>
                  刷新
                </Button>
              </div>
              <p className="break-all font-mono text-xs">SHA-256 {selectedRun.template_hash}</p>
              <p className="text-muted-foreground text-xs">
                {selectedRun.source_version} · {selectedRun.license}
              </p>
              {selectedRun.error && (
                <p role="alert" className="text-destructive">
                  {selectedRun.error}
                </p>
              )}
              {selectedRun.status === "completed" && selectedRun.matches.length === 0 && (
                <p>执行完成，没有结果事件。</p>
              )}
              {selectedRun.matches.map((match) => (
                <div key={`${match.url}:${match.request}:${match.matched}`} className="space-y-2 border-t pt-2">
                  <p className="break-all">
                    {match.matched ? "命中，需独立核验" : "未命中"} · {match.url}
                  </p>
                  {match.finding_id && (
                    <a className="underline" href={`/function/findings/detail?id=${match.finding_id}`}>
                      候选发现 #{match.finding_id}（待审）
                    </a>
                  )}
                  <details>
                    <summary className="cursor-pointer">请求与响应证据</summary>
                    <pre className="max-h-96 overflow-auto whitespace-pre-wrap text-xs">
                      {match.request}
                      {"\n"}
                      {match.response}
                    </pre>
                  </details>
                </div>
              ))}
              <details>
                <summary className="cursor-pointer">执行时模板</summary>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{selectedRun.template_content}</pre>
              </details>
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>导入模板</CardTitle>
          <CardDescription>支持静态路径的 HTTP GET 与状态码匹配；更新同一模板时保留旧内容版本。</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-3" onSubmit={importTemplate}>
            <Textarea
              aria-label="模板 YAML 内容"
              placeholder="粘贴模板 YAML 内容"
              value={content}
              onChange={(event) => setContent(event.target.value)}
              required
              rows={8}
              className="font-mono"
            />
            <div className="grid gap-3 md:grid-cols-3">
              <Input
                aria-label="模板来源地址"
                type="url"
                placeholder="来源 URL"
                value={sourceURL}
                onChange={(event) => setSourceURL(event.target.value)}
              />
              <Input
                aria-label="模板来源版本"
                placeholder="来源版本或提交"
                value={sourceVersion}
                onChange={(event) => setSourceVersion(event.target.value)}
              />
              <Input
                aria-label="模板许可证"
                placeholder="许可证（必填）"
                value={license}
                onChange={(event) => setLicense(event.target.value)}
                required
              />
            </div>
            {importError && (
              <p role="alert" className="text-destructive text-sm">
                {importError}
              </p>
            )}
            {importResult && (
              <p role="status" className="text-muted-foreground text-sm">
                {importResult}
              </p>
            )}
            <Button type="submit" disabled={importing || !content.trim() || !license.trim()}>
              {importing ? "校验并导入中…" : "校验并导入"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
