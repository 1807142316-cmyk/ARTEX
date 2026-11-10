"use client";

import * as React from "react";

import { RefreshCwIcon, SearchIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { http } from "@/lib/api";

type CVERecord = {
  cve_id: string;
  state: string;
  data_version: string;
  description: string;
  products: string[];
  references: string[];
  date_published: string;
  date_updated: string;
  source_version: string;
  content_hash: string;
  raw: unknown;
};
type CVEPage = { items: CVERecord[]; total: number; page: number; limit: number };
type CVEStats = { total: number; states: Record<string, number>; years: Record<string, number> };
type SyncStatus = {
  enabled: boolean;
  interval_minutes: number;
  next_check: string;
  last_check: string | null;
  last_success: string | null;
  source_version: string;
  status: string;
  added: number;
  modified: number;
  failed: number;
  last_error: string;
  run: { run_id: number; checkpoint: number; assets: { name: string }[] } | null;
};
const statusText: Record<string, string> = {
  idle: "尚未同步",
  queued: "排队中",
  running: "同步中",
  succeeded: "已完成",
  failed: "更新失败",
};
function time(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString("zh-CN") : "暂无";
}

export default function CVEPageView() {
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [records, setRecords] = React.useState<CVEPage | null>(null);
  const [stats, setStats] = React.useState<CVEStats | null>(null);
  const [sync, setSync] = React.useState<SyncStatus | null>(null);
  const [error, setError] = React.useState("");
  const [controlError, setControlError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [interval, setIntervalMinutes] = React.useState("60");
  const [expanded, setExpanded] = React.useState("");
  const [refresh, setRefresh] = React.useState(0);
  const initialInterval = React.useRef(true);
  const lastSuccess = React.useRef<string | null>(null);

  React.useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setError("");
      try {
        const result = await http<CVEPage>(
          `/cve?q=${encodeURIComponent(query)}&page=${page}&limit=20&refresh=${refresh}`,
          {
            signal: controller.signal,
          },
        );
        if (!controller.signal.aborted) setRecords(result);
      } catch (e) {
        if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "检索失败");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 250);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [query, page, refresh]);

  React.useEffect(() => {
    let disposed = false;
    async function poll() {
      try {
        const [state, counts] = await Promise.all([http<SyncStatus>("/cve/sync"), http<CVEStats>("/cve/stats")]);
        if (disposed) return;
        setSync(state);
        setStats(counts);
        if (initialInterval.current) {
          setIntervalMinutes(String(state.interval_minutes));
          initialInterval.current = false;
        }
        if (state.last_success !== lastSuccess.current) {
          lastSuccess.current = state.last_success;
          setRefresh((value) => value + 1);
        }
      } catch (e) {
        if (!disposed) setControlError(e instanceof Error ? e.message : "读取更新状态失败");
      }
    }
    void poll();
    const timer = window.setInterval(poll, 5000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, []);

  async function configure(enabled: boolean) {
    setBusy(true);
    setControlError("");
    try {
      const minutes = Number(interval);
      if (!Number.isInteger(minutes) || minutes < 5 || minutes > 10080) throw new Error("检查间隔须为 5 至 10080 分钟");
      const updated = await http<SyncStatus>("/cve/sync", {
        method: "PUT",
        body: JSON.stringify({ enabled, interval_minutes: minutes }),
      });
      setSync(updated);
    } catch (e) {
      setControlError(e instanceof Error ? e.message : "保存失败");
    } finally {
      setBusy(false);
    }
  }
  async function update() {
    setBusy(true);
    setControlError("");
    try {
      await http("/cve/sync", { method: "POST" });
      setSync(await http<SyncStatus>("/cve/sync"));
    } catch (e) {
      setControlError(e instanceof Error ? e.message : "启动失败");
    } finally {
      setBusy(false);
    }
  }

  const active = sync?.status === "queued" || sync?.status === "running";
  return (
    <div className="space-y-6 p-4 md:p-6">
      <div>
        <h1 className="font-semibold text-2xl">离线 CVE 库</h1>
        <p className="text-muted-foreground text-sm">官方 CVE Program 元数据，支持本地检索、全量基线与后台增量更新。</p>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">本地记录</CardTitle>
          </CardHeader>
          <CardContent className="font-semibold text-2xl">{stats?.total.toLocaleString() ?? "—"}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">已发布</CardTitle>
          </CardHeader>
          <CardContent className="font-semibold text-2xl">
            {(stats?.states.PUBLISHED ?? 0).toLocaleString()}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">已撤回</CardTitle>
          </CardHeader>
          <CardContent className="font-semibold text-2xl">{(stats?.states.REJECTED ?? 0).toLocaleString()}</CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            语料更新<Badge variant="outline">{statusText[sync?.status ?? "idle"] ?? sync?.status}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <Label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={sync?.enabled ?? false}
                disabled={!sync || busy}
                onChange={(event) => void configure(event.target.checked)}
              />
              自动更新
            </Label>
            <Label htmlFor="cve-interval">检查间隔（分钟）</Label>
            <Input
              id="cve-interval"
              className="w-28"
              type="number"
              min={5}
              max={10080}
              value={interval}
              onChange={(event) => setIntervalMinutes(event.target.value)}
            />
            <Button variant="outline" disabled={!sync || busy} onClick={() => void configure(sync?.enabled ?? false)}>
              保存间隔
            </Button>
            <Button disabled={busy || active || !sync} onClick={() => void update()}>
              <RefreshCwIcon className="mr-2 size-4" />
              立即更新
            </Button>
          </div>
          <dl className="grid gap-2 text-sm md:grid-cols-2">
            <div>来源版本：{sync?.source_version || "尚未建立基线"}</div>
            <div>最近检查：{time(sync?.last_check)}</div>
            <div>最近成功：{time(sync?.last_success)}</div>
            <div>下次检查：{sync?.enabled ? time(sync.next_check) : "自动更新已关闭"}</div>
            <div>
              本次新增 {sync?.added ?? 0} · 修改 {sync?.modified ?? 0} · 失败 {sync?.failed ?? 0}
            </div>
            <div>已处理：{sync?.run?.checkpoint.toLocaleString() ?? 0} 条</div>
          </dl>
          {active && (
            <p className="text-muted-foreground text-sm">
              后台任务持续运行，关闭页面后仍会继续。中断后从已提交的批次恢复。
            </p>
          )}
          {(controlError || sync?.last_error) && (
            <p role="alert" className="text-destructive text-sm">
              {controlError || sync?.last_error}。已有本地语料仍可检索。
            </p>
          )}
        </CardContent>
      </Card>
      {stats && (
        <div className="flex max-h-28 flex-wrap gap-2 overflow-auto">
          {Object.entries(stats.years)
            .sort(([a], [b]) => b.localeCompare(a))
            .map(([year, count]) => (
              <Badge key={year} variant="secondary">
                {year} · {count.toLocaleString()}
              </Badge>
            ))}
        </div>
      )}
      <div className="relative">
        <SearchIcon className="absolute top-3 left-3 size-4 text-muted-foreground" />
        <Input
          aria-label="搜索 CVE"
          className="pl-9"
          placeholder="CVE 编号、产品、组件或漏洞描述"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPage(1);
          }}
        />
      </div>
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      {loading && <p className="text-muted-foreground text-sm">正在检索本地数据库…</p>}
      {!loading && records?.items.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            {query ? "没有匹配的 CVE，尝试其他编号或关键词。" : "尚无本地语料。点击「立即更新」获取官方全量记录。"}
          </CardContent>
        </Card>
      )}
      {records?.items.map((record) => (
        <Card key={record.cve_id}>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-3">
              <Button
                variant="link"
                className="h-auto p-0 font-semibold"
                onClick={() => setExpanded(expanded === record.cve_id ? "" : record.cve_id)}
              >
                {record.cve_id}
              </Button>
              <Badge variant={record.state === "REJECTED" ? "secondary" : "outline"}>{record.state}</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>{record.description || "来源未提供描述"}</p>
            <div className="flex flex-wrap gap-1">
              {record.products?.map((product) => (
                <Badge key={product} variant="secondary">
                  {product}
                </Badge>
              ))}
            </div>
            {expanded === record.cve_id && (
              <div className="space-y-2 border-t pt-3">
                <p>
                  发布时间：{time(record.date_published)} · 修订时间：{time(record.date_updated)}
                </p>
                <p>
                  来源版本：{record.source_version} · JSON 格式：{record.data_version || "未声明"}
                </p>
                <p className="break-all text-muted-foreground">SHA-256：{record.content_hash}</p>
                <ul className="list-inside list-disc">
                  {record.references
                    ?.filter((reference) => /^https?:\/\//i.test(reference))
                    .map((reference) => (
                      <li key={reference} className="break-all">
                        <a
                          href={reference}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary underline"
                        >
                          {reference}
                        </a>
                      </li>
                    ))}
                </ul>
                <details>
                  <summary className="cursor-pointer">原始记录（含受影响版本及来源容器）</summary>
                  <pre className="max-h-96 overflow-auto rounded bg-muted p-3 text-xs">
                    {JSON.stringify(record.raw, null, 2)}
                  </pre>
                </details>
              </div>
            )}
          </CardContent>
        </Card>
      ))}
      {records && (
        <div className="flex items-center justify-between">
          <p className="text-muted-foreground text-sm">
            共 {records.total.toLocaleString()} 条 · 第 {page} 页
          </p>
          <div className="flex gap-2">
            <Button variant="outline" disabled={page <= 1 || loading} onClick={() => setPage(page - 1)}>
              上一页
            </Button>
            <Button
              variant="outline"
              disabled={page * records.limit >= records.total || loading}
              onClick={() => setPage(page + 1)}
            >
              下一页
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
