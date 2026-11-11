"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  type AdapterInput,
  type ConnectionAdapter,
  type ConnectionOperation,
  type ConnectionSession,
  connectionOperationStatusLabel,
  connectionSessionStateLabel,
  connectionStateLabel,
  connectionsAPI,
} from "@/lib/connections";

const selectClass = "border-input bg-background h-9 rounded-md border px-3 text-sm";
const formatTime = (value?: string | null) => (value ? new Date(value).toLocaleString() : "—");
const errorText = (error: unknown) => (error instanceof Error ? error.message : "操作失败");

const operationBadge: Record<string, "default" | "destructive" | "outline"> = {
  succeeded: "default",
  failed: "destructive",
  timeout: "destructive",
};

const emptyForm = {
  name: "",
  base_url: "",
  secret: "",
  secret_ref: "",
  timeout_seconds: "10",
  heartbeat_ttl_seconds: "120",
  enabled: true,
  task_id: "",
  asset_id: "",
};

type AdapterForm = typeof emptyForm;

export default function C2WebShellPage() {
  const [adapters, setAdapters] = useState<ConnectionAdapter[]>([]);
  const [kinds, setKinds] = useState<string[]>(["http_phpcmd"]);
  const [sessions, setSessions] = useState<ConnectionSession[]>([]);
  const [selected, setSelected] = useState<ConnectionSession | null>(null);
  const [operations, setOperations] = useState<ConnectionOperation[]>([]);
  const [form, setForm] = useState<AdapterForm>(emptyForm);
  const [editing, setEditing] = useState<number | null>(null);
  const [action, setAction] = useState("exec");
  const [cmd, setCmd] = useState("id");
  const [operationError, setOperationError] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refreshSeconds, setRefreshSeconds] = useState(15);
  const requestSeq = useRef(0);
  const selectedID = useRef<number | null>(null);

  const refreshOperations = useCallback(async (id: number) => {
    try {
      const result = await connectionsAPI.operations(id);
      if (selectedID.current !== id) return;
      setOperations(result.items);
    } catch (err) {
      if (selectedID.current === id) setOperationError(errorText(err));
    }
  }, []);

  const load = useCallback(async () => {
    const seq = ++requestSeq.current;
    setLoading(true);
    setError("");
    try {
      const [adapterList, sessionList] = await Promise.all([connectionsAPI.adapters(), connectionsAPI.sessions()]);
      if (seq !== requestSeq.current) return;
      setAdapters(adapterList.items);
      setKinds(adapterList.kinds.length ? adapterList.kinds : ["http_phpcmd"]);
      setSessions(sessionList.items);
      const current = selectedID.current;
      if (current !== null) {
        const latest = sessionList.items.find((item) => item.id === current) ?? null;
        setSelected(latest);
        if (latest) void refreshOperations(latest.id);
        else selectedID.current = null;
      }
    } catch (err) {
      if (seq === requestSeq.current) setError(errorText(err));
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [refreshOperations]);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), refreshSeconds * 1000);
    return () => {
      clearInterval(timer);
      requestSeq.current++;
      selectedID.current = null;
    };
  }, [load, refreshSeconds]);

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      const input: AdapterInput = {
        name: form.name.trim(),
        kind: "http_phpcmd",
        base_url: form.base_url.trim(),
        secret_ref: form.secret_ref.trim(),
        timeout_seconds: Number(form.timeout_seconds) || 10,
        heartbeat_ttl_seconds: Number(form.heartbeat_ttl_seconds) || 120,
        enabled: form.enabled,
        ...(form.task_id ? { task_id: Number(form.task_id) } : {}),
        ...(form.asset_id ? { asset_id: Number(form.asset_id) } : {}),
      };
      if (form.secret) input.secret = form.secret;
      if (editing === null) await connectionsAPI.createAdapter(input);
      else await connectionsAPI.updateAdapter(editing, input);
      toast.success(editing === null ? "适配器已创建" : "适配器已更新");
      setEditing(null);
      setForm(emptyForm);
      await load();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const startEdit = (adapter: ConnectionAdapter) => {
    setEditing(adapter.id);
    setForm({
      name: adapter.name,
      base_url: adapter.base_url,
      secret: "",
      secret_ref: adapter.secret_ref,
      timeout_seconds: String(adapter.timeout_seconds),
      heartbeat_ttl_seconds: String(adapter.heartbeat_ttl_seconds),
      enabled: adapter.enabled,
      task_id: adapter.task_id ? String(adapter.task_id) : "",
      asset_id: adapter.asset_id ? String(adapter.asset_id) : "",
    });
  };

  const runAction = async (actionRun: () => Promise<unknown>, message: string) => {
    setBusy(true);
    setError("");
    try {
      await actionRun();
      toast.success(message);
      await load();
      if (selectedID.current !== null) await refreshOperations(selectedID.current);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const openSession = (session: ConnectionSession) => {
    selectedID.current = session.id;
    setSelected(session);
    setOperations([]);
    setOperationError("");
    void refreshOperations(session.id);
  };

  const execute = async () => {
    if (!selected) return;
    setBusy(true);
    setOperationError("");
    try {
      const requestId = `ui-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const result = await connectionsAPI.run(selected.id, {
        action,
        request_id: requestId,
        ...(action === "exec" ? { cmd } : {}),
      });
      if (result.status === "timeout") setOperationError("操作超时，已记录请求与超时状态");
      else if (result.status === "failed") setOperationError(result.error || "操作失败");
    } catch (err) {
      setOperationError(errorText(err));
    } finally {
      // A rejected capability or a refused session still produces a record, so
      // refresh regardless of whether the request itself threw.
      await refreshOperations(selected.id);
      setBusy(false);
    }
  };

  const capabilities = selected?.adapter.capabilities ?? ["ping", "info", "exec"];
  const unsupportedAction = !capabilities.includes(action);
  const sessionExecutable = selected?.effective_state === "connected" && selected.adapter.enabled;

  return (
    <div className="flex flex-col gap-5 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-2xl">C2 / WebShell</h1>
          <p className="mt-1 text-muted-foreground text-sm">HTTP/PHP 会话适配器 · 真实操作记录 · 能力约束</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            aria-label="自动刷新间隔"
            className={selectClass}
            value={refreshSeconds}
            onChange={(event) => setRefreshSeconds(Number(event.target.value))}
          >
            <option value={15}>每 15 秒刷新</option>
            <option value={30}>每 30 秒刷新</option>
            <option value={60}>每 60 秒刷新</option>
          </select>
          <Button variant="outline" disabled={loading} onClick={() => void load()}>
            刷新
          </Button>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border p-3 text-destructive">
          {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{editing === null ? "新增适配器" : `编辑适配器 #${editing}`}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="adapter-name">名称</Label>
              <Input
                id="adapter-name"
                value={form.name}
                placeholder="webshell-lab-01"
                onChange={(event) => setForm({ ...form, name: event.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-url">Base URL</Label>
              <Input
                id="adapter-url"
                value={form.base_url}
                placeholder="http://127.0.0.1:18080/index.php"
                onChange={(event) => setForm({ ...form, base_url: event.target.value })}
              />
              <p className="text-muted-foreground text-xs">必须是绝对 HTTP(S) 地址，不能含查询串或内嵌凭据。</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-secret">凭据（只写，不回显）</Label>
              <Input
                id="adapter-secret"
                type="password"
                autoComplete="new-password"
                value={form.secret}
                placeholder={editing === null ? "至少 32 字节" : "留空表示沿用原凭据"}
                onChange={(event) => setForm({ ...form, secret: event.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-ref">凭据引用标签</Label>
              <Input
                id="adapter-ref"
                value={form.secret_ref}
                placeholder="ops-rotated-2026-11"
                onChange={(event) => setForm({ ...form, secret_ref: event.target.value })}
              />
              <p className="text-muted-foreground text-xs">列表和详情只显示该标签，真实凭据不会返回。</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-timeout">超时（秒）</Label>
              <Input
                id="adapter-timeout"
                type="number"
                min="1"
                max="120"
                value={form.timeout_seconds}
                onChange={(event) => setForm({ ...form, timeout_seconds: event.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-ttl">心跳有效期（秒）</Label>
              <Input
                id="adapter-ttl"
                type="number"
                min="1"
                max="86400"
                value={form.heartbeat_ttl_seconds}
                onChange={(event) => setForm({ ...form, heartbeat_ttl_seconds: event.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-task">关联任务 ID</Label>
              <Input
                id="adapter-task"
                type="number"
                min="1"
                value={form.task_id}
                placeholder="可选"
                onChange={(event) => setForm({ ...form, task_id: event.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="adapter-asset">关联资产 ID</Label>
              <Input
                id="adapter-asset"
                type="number"
                min="1"
                value={form.asset_id}
                placeholder="可选，必须属于该任务"
                onChange={(event) => setForm({ ...form, asset_id: event.target.value })}
              />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
              />
              启用适配器
            </label>
            <Badge variant="outline">kind: {kinds.join(" / ")}</Badge>
            <Button disabled={busy || !form.name || !form.base_url || !form.secret_ref} onClick={() => void submit()}>
              {editing === null ? "保存适配器" : "更新适配器"}
            </Button>
            {editing !== null && (
              <Button
                variant="ghost"
                onClick={() => {
                  setEditing(null);
                  setForm(emptyForm);
                }}
              >
                取消编辑
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>适配器</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/40">
              <tr>
                {["名称", "Base URL", "凭据引用", "状态", "检查时间", "关联", "能力", "操作"].map((label) => (
                  <th key={label} className="p-3 font-medium">
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {adapters.map((adapter) => (
                <tr key={adapter.id} className="border-t align-top">
                  <td className="p-3">
                    {adapter.name}
                    <div className="text-muted-foreground text-xs">
                      {adapter.kind} · {adapter.enabled ? "已启用" : "已停用"}
                    </div>
                  </td>
                  <td className="max-w-[18rem] break-all p-3 text-xs">{adapter.base_url}</td>
                  <td className="p-3 text-xs">{adapter.secret_ref}</td>
                  <td className="p-3">
                    <Badge variant={adapter.state === "reachable" ? "default" : "outline"}>
                      {connectionStateLabel[adapter.state] ?? adapter.state}
                    </Badge>
                    {adapter.last_error && (
                      <div className="mt-1 max-w-[16rem] text-destructive text-xs">{adapter.last_error}</div>
                    )}
                  </td>
                  <td className="p-3 text-xs">{formatTime(adapter.checked_at)}</td>
                  <td className="p-3 text-xs">
                    任务 {adapter.task_id ?? "—"}
                    <br />
                    资产 {adapter.asset_id ?? "—"}
                  </td>
                  <td className="p-3 text-xs">{adapter.capabilities.join(", ")}</td>
                  <td className="p-3">
                    <div className="flex flex-wrap gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy || !adapter.enabled}
                        onClick={() =>
                          void runAction(() => connectionsAPI.checkAdapter(adapter.id), "已执行真实连通检查")
                        }
                      >
                        检查
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy || !adapter.enabled}
                        onClick={() => void runAction(() => connectionsAPI.syncAdapter(adapter.id), "会话已同步")}
                      >
                        同步会话
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => startEdit(adapter)}>
                        编辑
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() =>
                          void runAction(async () => {
                            if (!window.confirm(`删除适配器 ${adapter.name}？其操作记录会一并删除。`)) return;
                            await connectionsAPI.deleteAdapter(adapter.id);
                          }, "适配器已删除")
                        }
                      >
                        删除
                      </Button>
                    </div>
                    {!adapter.enabled && (
                      <div className="mt-1 text-muted-foreground text-xs">适配器已停用，检查与同步不可用。</div>
                    )}
                  </td>
                </tr>
              ))}
              {!adapters.length && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-muted-foreground">
                    尚无适配器。填写上方表单并保存后，检查按钮会对真实 Base URL 发起 ping。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>会话</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/40">
              <tr>
                {["主机", "URL", "状态", "协议", "任务 / 资产", "心跳", "能力", "操作"].map((label) => (
                  <th key={label} className="p-3 font-medium">
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id} className="border-t align-top">
                  <td className="p-3">
                    {session.host || "—"}
                    <div className="text-muted-foreground text-xs">{session.adapter.name}</div>
                  </td>
                  <td className="max-w-[18rem] break-all p-3 text-xs">{session.url}</td>
                  <td className="p-3">
                    <Badge variant={session.effective_state === "connected" ? "default" : "outline"}>
                      {connectionSessionStateLabel[session.effective_state] ?? session.effective_state}
                    </Badge>
                    {session.disconnect_reason && (
                      <div className="mt-1 max-w-[16rem] text-muted-foreground text-xs">
                        断开原因：{session.disconnect_reason}
                      </div>
                    )}
                  </td>
                  <td className="p-3 text-xs">{session.protocol_label}</td>
                  <td className="p-3 text-xs">
                    任务 {session.task_id ?? "—"}
                    <br />
                    资产 {session.asset_id ?? "—"}
                  </td>
                  <td className="p-3 text-xs">
                    {formatTime(session.heartbeat_at)}
                    <div className="text-muted-foreground">{session.heartbeat_ttl_seconds}s 有效期</div>
                  </td>
                  <td className="p-3 text-xs">{session.adapter.capabilities.join(", ")}</td>
                  <td className="p-3">
                    <Button size="sm" variant="outline" onClick={() => openSession(session)}>
                      打开控制台
                    </Button>
                  </td>
                </tr>
              ))}
              {!sessions.length && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-muted-foreground">
                    尚无适配器会话。对已启用的适配器执行「同步会话」后，这里会出现真实心跳的会话。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>操作控制台</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {!selected && (
            <p className="text-muted-foreground text-sm">
              选择一个会话后可以执行参数化命令。未声明的能力会被明确拒绝，不会发送请求。
            </p>
          )}
          {selected && (
            <>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <Badge variant="outline">会话 #{selected.id}</Badge>
                <span>{selected.host}</span>
                <span className="text-muted-foreground">{selected.url}</span>
                <Badge variant={selected.effective_state === "connected" ? "default" : "outline"}>
                  {connectionSessionStateLabel[selected.effective_state] ?? selected.effective_state}
                </Badge>
                <Badge variant="secondary">凭据引用 {selected.adapter.secret_ref}</Badge>
              </div>
              {!sessionExecutable && (
                <p className="rounded-lg border p-3 text-destructive text-sm">
                  {selected.adapter.enabled
                    ? `会话当前为 ${connectionSessionStateLabel[selected.effective_state] ?? selected.effective_state}，请先同步会话再执行。`
                    : "适配器已停用，操作不可用。"}
                </p>
              )}
              <div className="grid gap-3 md:grid-cols-[10rem_1fr]">
                <select
                  aria-label="操作"
                  className={selectClass}
                  value={action}
                  onChange={(event) => setAction(event.target.value)}
                >
                  {["exec", "ping", "info", "upload", "tunnel"].map((capability) => (
                    <option key={capability} value={capability}>
                      {capability}
                      {capabilities.includes(capability) ? "" : "（不支持）"}
                    </option>
                  ))}
                </select>
                <Textarea
                  aria-label="命令"
                  value={cmd}
                  disabled={action !== "exec"}
                  placeholder="id"
                  onChange={(event) => setCmd(event.target.value)}
                />
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  disabled={busy || !sessionExecutable || unsupportedAction || (action === "exec" && !cmd.trim())}
                  onClick={() => void execute()}
                >
                  执行并记录
                </Button>
                <Button variant="outline" disabled={busy} onClick={() => void refreshOperations(selected.id)}>
                  刷新记录
                </Button>
                {unsupportedAction && (
                  <span className="text-destructive text-sm">该操作未在适配器能力中声明，执行将被拒绝。</span>
                )}
                {action !== "exec" && capabilities.includes(action) && (
                  <span className="text-muted-foreground text-sm">该操作不接收命令参数。</span>
                )}
              </div>
              {operationError && (
                <p role="alert" className="rounded-lg border p-3 text-destructive text-sm">
                  {operationError}
                </p>
              )}
              <div className="overflow-x-auto rounded-lg border">
                <table className="w-full text-left text-sm">
                  <thead className="bg-muted/40">
                    <tr>
                      {["请求 ID", "操作", "状态", "退出码", "耗时窗口", "输出 / 错误"].map((label) => (
                        <th key={label} className="p-3 font-medium">
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {operations.map((operation) => (
                      <tr key={operation.id} className="border-t align-top">
                        <td className="max-w-[10rem] break-all p-3 text-xs">{operation.request_id}</td>
                        <td className="p-3">
                          {operation.action}
                          <div className="text-muted-foreground text-xs">{operation.args_summary || "—"}</div>
                        </td>
                        <td className="p-3">
                          <Badge variant={operationBadge[operation.status] ?? "outline"}>
                            {connectionOperationStatusLabel[operation.status] ?? operation.status}
                          </Badge>
                        </td>
                        <td className="p-3 text-xs">{operation.exit_code ?? "—"}</td>
                        <td className="p-3 text-xs">
                          {formatTime(operation.started_at)}
                          <br />
                          {formatTime(operation.finished_at)}
                        </td>
                        <td className="max-w-[26rem] p-3">
                          {operation.output && (
                            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-muted/40 p-2 text-xs">
                              {operation.output}
                            </pre>
                          )}
                          {operation.error && <div className="mt-1 text-destructive text-xs">{operation.error}</div>}
                          {!operation.output && !operation.error && (
                            <span className="text-muted-foreground text-xs">无输出</span>
                          )}
                        </td>
                      </tr>
                    ))}
                    {!operations.length && (
                      <tr>
                        <td colSpan={6} className="p-6 text-center text-muted-foreground">
                          该会话还没有操作记录。
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
