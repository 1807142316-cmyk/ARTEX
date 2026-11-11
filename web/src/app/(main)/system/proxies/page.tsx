"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { http } from "@/lib/api";

type Endpoint = {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  check_url: string;
  health: string;
  exit_ip: string;
  last_error: string;
  checked_at: string | null;
};
type Pool = { items: Endpoint[]; enabled: boolean; system_default_proxy: string };
type Lease = {
  task_id?: number;
  proxy_id?: number;
  policy?: string;
  state?: string;
  exit_ip?: string;
  proxy_url?: string;
  events: { id: number; kind: string; message: string; created_at: string }[];
  system_default_proxy: string;
};
const health: Record<string, string> = { healthy: "可用", unhealthy: "不可用", unchecked: "未检查" };
const states: Record<string, string> = { active: "代理出口", paused: "出口暂停", direct: "显式直连" };

export default function ProxiesPage() {
  const [pool, setPool] = React.useState<Pool | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [edit, setEdit] = React.useState<number | null>(null);
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [checkURL, setCheckURL] = React.useState("https://api.ipify.org?format=json");
  const [enabled, setEnabled] = React.useState(true);
  const [taskID, setTaskID] = React.useState("");
  const [proxyID, setProxyID] = React.useState("");
  const [policy, setPolicy] = React.useState("pause");
  const [lease, setLease] = React.useState<Lease | null>(null);
  const refresh = React.useCallback(async () => {
    setPool(await http<Pool>("/proxies"));
  }, []);
  React.useEffect(() => {
    refresh().catch((e) => setError(String(e)));
  }, [refresh]);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  function reset() {
    setEdit(null);
    setName("");
    setUrl("");
    setEnabled(true);
  }
  const taskValid = /^[1-9]\d*$/.test(taskID);
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-2xl">代理池</h1>
          <p className="text-muted-foreground text-sm">任务固定出口、健康观测与故障策略</p>
        </div>
        <Button disabled={busy} variant="outline" onClick={() => run(refresh)}>
          刷新
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>目标流量出口</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <Badge variant={pool?.enabled ? "default" : "secondary"}>{pool?.enabled ? "已启用" : "未启用"}</Badge>
            <Button
              disabled={busy || !pool}
              onClick={() =>
                run(async () => {
                  await http("/proxies/settings", { method: "PUT", body: JSON.stringify({ enabled: !pool?.enabled }) });
                  await refresh();
                })
              }
            >
              {pool?.enabled ? "停用代理池" : "启用代理池"}
            </Button>
          </div>
          <p className="text-sm">系统默认出口：{pool?.system_default_proxy || "直连"}</p>
          <p className="text-muted-foreground text-sm">
            透明网络沙箱（Linux，可选）开启后，任务 Bash 的连接、DNS 与忽略代理设置的流量都强制经过本任务租约；需要
            NET_ADMIN / SYS_ADMIN 及 iproute2、nftables、util-linux。未开启时仅处理遵循代理设置的 HTTP 流量。
          </p>
          <p className="text-muted-foreground text-sm">
            模型和联网搜索沿用各自的代理配置。任务出口以租约为准；健康检查每分钟执行，也可手动检查。启停代理池后，正在运行的任务需暂停并继续以重建工具环境。只处理遵循代理设置的
            HTTP 流量。
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{edit ? "编辑代理" : "添加代理"}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="proxy-name">名称</Label>
              <Input id="proxy-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="proxy-url">HTTP / HTTPS / SOCKS5 地址</Label>
              <Input
                id="proxy-url"
                type="password"
                autoComplete="off"
                value={url}
                placeholder={edit ? "留空保留原地址与凭据" : "http://host:port"}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="proxy-check">出口检测 URL（返回 IP 或含 ip 的 JSON）</Label>
              <Input id="proxy-check" value={checkURL} onChange={(e) => setCheckURL(e.target.value)} />
            </div>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              允许分配
            </label>
          </div>
          <div className="flex gap-2">
            <Button
              disabled={busy || !name || (!edit && !url)}
              onClick={() =>
                run(async () => {
                  await http(edit ? `/proxies/${edit}` : "/proxies", {
                    method: edit ? "PUT" : "POST",
                    body: JSON.stringify({ name, url, enabled, check_url: checkURL }),
                  });
                  reset();
                  await refresh();
                })
              }
            >
              保存
            </Button>
            {edit && (
              <Button variant="outline" disabled={busy} onClick={reset}>
                取消
              </Button>
            )}
          </div>
          <p className="text-muted-foreground text-xs">
            凭据加密保存；列表只显示不含凭据的地址。活跃租约引用的代理需先调整任务出口后才能编辑。
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>代理与健康状态（{pool?.items.length ?? 0}）</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {!pool && <p>加载中…</p>}
          {pool?.items.length === 0 && <p className="text-muted-foreground">尚未添加代理</p>}
          {pool?.items.map((item) => (
            <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3">
              <div className="space-y-1">
                <p className="font-medium">
                  {item.name} <Badge variant="outline">{health[item.health] || item.health}</Badge>
                  {!item.enabled && <Badge variant="secondary">禁用</Badge>}
                </p>
                <p className="text-muted-foreground text-sm">
                  {item.url} · 出口 {item.exit_ip || "未知"}
                </p>
                <p className="text-muted-foreground text-xs">
                  {item.checked_at ? new Date(item.checked_at).toLocaleString() : "尚未检查"}
                  {item.last_error ? ` · ${item.last_error}` : ""}
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() =>
                    run(async () => {
                      await http(`/proxies/${item.id}/check`, { method: "POST" });
                      await refresh();
                    })
                  }
                >
                  检查
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => {
                    setEdit(item.id);
                    setName(item.name);
                    setUrl("");
                    setCheckURL(item.check_url);
                    setEnabled(item.enabled);
                  }}
                >
                  编辑
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>任务出口租约</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="proxy-task">任务 ID</Label>
              <Input
                id="proxy-task"
                value={taskID}
                onChange={(e) => {
                  setTaskID(e.target.value);
                  setLease(null);
                }}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="proxy-choice">代理</Label>
              <select
                id="proxy-choice"
                className="h-9 w-full rounded-md border bg-background px-3 text-sm"
                value={proxyID}
                onChange={(e) => setProxyID(e.target.value)}
              >
                <option value="">自动选取健康且空闲的代理</option>
                {pool?.items.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}（{health[p.health]}）
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="proxy-policy">故障策略</Label>
              <select
                id="proxy-policy"
                className="h-9 w-full rounded-md border bg-background px-3 text-sm"
                value={policy}
                onChange={(e) => setPolicy(e.target.value)}
              >
                <option value="pause">暂停任务（默认）</option>
                <option value="failover">切换到健康空闲代理</option>
                <option value="direct">允许直连回退</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              disabled={busy || !taskValid}
              variant="outline"
              onClick={() => run(async () => setLease(await http<Lease>(`/tasks/${taskID}/egress`)))}
            >
              查看
            </Button>
            <Button
              disabled={busy || !taskValid || !pool?.enabled}
              onClick={() =>
                run(async () =>
                  setLease(
                    await http<Lease>(`/tasks/${taskID}/egress`, {
                      method: "POST",
                      body: JSON.stringify({ proxy_id: Number(proxyID), policy }),
                    }),
                  ),
                )
              }
            >
              分配 / 更新租约
            </Button>
          </div>
          {lease && (
            <div className="space-y-2 text-sm">
              <p>
                任务出口：{lease.state ? states[lease.state] : "尚未分配"} · 代理 #{lease.proxy_id ?? "无"} · 观测出口{" "}
                {lease.exit_ip || "未知"}
              </p>
              {lease.proxy_url && <p>本地任务网关：{lease.proxy_url}</p>}
              <p className="text-muted-foreground">
                系统默认出口：{lease.system_default_proxy || "直连"}。分配不会自动恢复已暂停任务；请在任务页继续。
              </p>
              {lease.events.map((event) => (
                <p key={event.id} className="text-muted-foreground text-xs">
                  {new Date(event.created_at).toLocaleString()} · {event.kind} · {event.message}
                </p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
