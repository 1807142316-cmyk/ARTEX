"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  type IntranetContext,
  type InventoryDetail,
  type InventoryGraph,
  type InventoryNode,
  type InventorySession,
  type InventorySummary,
  inventoryAPI,
} from "@/lib/session-inventory";

const stateNames: Record<string, string> = {
  connected: "在线观察",
  disconnected: "已断开",
  stale: "心跳失联",
  unknown: "未知",
  active: "有效",
  inactive: "无效关系",
  invalid: "已失效",
  expired: "已过期",
};
const relationNames: Record<string, string> = {
  hosted_on: "所在主机",
  member_of: "所属网段",
  tunnel_metadata: "隧道元数据",
  credential_reference: "凭据引用",
};
// Derived edge reasons. An empty reason means the edge is active, or that an
// operator deactivated it explicitly — neither is a state to explain.
const reasonNames: Record<string, string> = {
  session_stale: "会话心跳失联",
  session_disconnected: "会话已断开",
  node_invalid: "节点已失效",
  credential_expired: "凭据已过期",
  tunnel_inactive: "隧道不可用",
  task_mismatch: "跨任务归属",
};
// Intranet unavailability reasons, in the same vocabulary the API uses.
const intranetReasonNames: Record<string, string> = {
  no_session: "本任务尚无可用会话",
  session_stale: "会话心跳失联，通道已不可用",
  no_credential: "尚无可用凭据引用",
  credential_expired: "凭据已过期",
  integration_unreachable: "会话适配器不可达",
};
const summaryFields: { key: keyof InventorySummary; label: string }[] = [
  { key: "hosts", label: "主机" },
  { key: "subnets", label: "网段" },
  { key: "sessions", label: "会话" },
  { key: "tunnels", label: "隧道" },
  { key: "credentials", label: "凭据" },
  { key: "active_edges", label: "有效关系" },
  { key: "inactive_edges", label: "无效关系" },
];
const heartbeatAge = (value?: string) => {
  if (!value) return "—";
  const age = Date.now() - new Date(value).getTime();
  if (Number.isNaN(age) || age < 0) return "刚刚";
  const minutes = Math.floor(age / 60000);
  if (minutes < 1) return "不到 1 分钟";
  if (minutes < 60) return `${minutes} 分钟前`;
  return `${Math.floor(minutes / 60)} 小时前`;
};
const selectClass = "border-input bg-background h-9 rounded-md border px-3 text-sm";
const formatTime = (value?: string) => (value ? new Date(value).toLocaleString() : "—");
const errorText = (error: unknown) => (error instanceof Error ? error.message : "操作失败");

export default function SessionInventoryPage() {
  const [items, setItems] = useState<InventorySession[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [source, setSource] = useState("");
  const [kind, setKind] = useState("");
  const [state, setState] = useState("");
  const [query, setQuery] = useState("");
  const [task, setTask] = useState("");
  const [detail, setDetail] = useState<InventoryDetail | null>(null);
  const [graph, setGraph] = useState<InventoryGraph | null>(null);
  const [intranet, setIntranet] = useState<IntranetContext | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [observation, setObservation] = useState("");
  const [nodeForm, setNodeForm] = useState({
    kind: "host",
    external_ref: "",
    label: "",
    address: "",
    state: "active",
    scope: "",
    expires_at: "",
    task_id: "",
    asset_id: "",
  });
  const [edgeForm, setEdgeForm] = useState({
    source_ref: "",
    target_ref: "",
    relation: "hosted_on",
    state: "active",
    note: "",
  });
  const [nodeAudit, setNodeAudit] = useState<{
    node: InventoryNode;
    audit: { id: number; state: string; label: string; created_at: string }[];
  } | null>(null);
  const [edgeAudit, setEdgeAudit] = useState<{ id: number; state: string; note: string; created_at: string }[] | null>(
    null,
  );
  const listRequest = useRef(0);
  const detailRequest = useRef(0);
  const selectedDetail = useRef<number | null>(null);
  const refreshDetail = useCallback(async (id: number, clearNote = false) => {
    const request = ++detailRequest.current;
    try {
      const latest = await inventoryAPI.detail(id);
      if (request !== detailRequest.current || selectedDetail.current !== id) return;
      setDetail(latest);
      if (clearNote) setNote("");
    } catch (err) {
      if (request === detailRequest.current && selectedDetail.current === id) toast.error(errorText(err));
    }
  }, []);
  const load = useCallback(async () => {
    const request = ++listRequest.current;
    setLoading(true);
    setError("");
    const params = new URLSearchParams({ page: String(page), limit: "20", source, kind, state, q: query });
    if (task) params.set("task_id", task);
    const topologyParams = new URLSearchParams();
    if (task) topologyParams.set("task_id", task);
    const id = selectedDetail.current;
    if (id !== null) void refreshDetail(id);
    try {
      const [list, topology, context] = await Promise.all([
        inventoryAPI.sessions(params),
        inventoryAPI.graph(topologyParams),
        // The panel only exists for a concrete task: an unfiltered view has no
        // single context to report.
        task ? inventoryAPI.intranet(task) : Promise.resolve(null),
      ]);
      if (request !== listRequest.current) return;
      setItems(list.items);
      setTotal(list.total);
      setGraph(topology);
      setIntranet(context);
    } catch (err) {
      if (request === listRequest.current) setError(errorText(err));
    } finally {
      if (request === listRequest.current) setLoading(false);
    }
  }, [page, source, kind, state, query, task, refreshDetail]);
  const latestLoad = useRef(load);
  useEffect(() => {
    latestLoad.current = load;
    void load();
    const interval = setInterval(() => void load(), 15000);
    return () => {
      clearInterval(interval);
      listRequest.current++;
      detailRequest.current++;
    };
  }, [load]);
  const open = async (id: number) => {
    if (selectedDetail.current !== id) setDetail(null);
    selectedDetail.current = id;
    await refreshDetail(id, true);
  };
  const closeDetail = () => {
    selectedDetail.current = null;
    detailRequest.current++;
    setDetail(null);
  };
  const run = async (action: () => Promise<unknown>, message: string) => {
    setBusy(true);
    try {
      await action();
      toast.success(message);
      await latestLoad.current();
    } catch (err) {
      toast.error(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  const numericRefs = (value: { task_id: string; asset_id: string }) => ({
    ...(value.task_id ? { task_id: Number(value.task_id) } : {}),
    ...(value.asset_id ? { asset_id: Number(value.asset_id) } : {}),
  });
  // expires_at / scope describe a credential reference only; sending them for a
  // host or tunnel is refused by the API, so they are stripped before submit.
  const nodePayload = () => {
    const { expires_at, scope, ...rest } = nodeForm;
    const credential = nodeForm.kind === "credential_ref";
    return {
      ...rest,
      task_id: undefined,
      asset_id: undefined,
      ...numericRefs(nodeForm),
      ...(credential && scope.trim() ? { scope: scope.trim() } : {}),
      ...(credential && expires_at ? { expires_at: new Date(expires_at).toISOString() } : {}),
    };
  };
  const openNode = async (id: number) => {
    try {
      setNodeAudit(await inventoryAPI.nodeDetail(id));
    } catch (err) {
      toast.error(errorText(err));
    }
  };
  const openEdgeAudit = async (id: number) => {
    try {
      setEdgeAudit((await inventoryAPI.edgeAudit(id)).items);
    } catch (err) {
      toast.error(errorText(err));
    }
  };
  let emptyMessage = "尚无来源提交观察记录，可通过来源登记或健康观察脚本接入。";
  if (query || source || kind || state || task) emptyMessage = "没有匹配的观察记录";
  if (loading) emptyMessage = "正在读取观察记录…";
  return (
    <div className="flex flex-col gap-5 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-2xl">会话与拓扑观察</h1>
          <p className="mt-1 text-muted-foreground text-sm">外部来源状态登记 · inventory / observer</p>
        </div>
        <Button variant="outline" onClick={() => void load()} disabled={loading}>
          刷新状态
        </Button>
      </div>
      <div className="rounded-lg border p-4 text-sm">
        <strong>观察能力</strong>
        <p className="mt-1 text-muted-foreground">
          C2 / WebShell
          是来源标签。本页接收状态、心跳和关系元数据；支持读取、注释与断开库存记录。断开记录不操作远端服务。协议名称仅为来源描述。
        </p>
      </div>
      {error && (
        <div role="alert" className="rounded-lg border p-3 text-destructive">
          {error}
          <Button variant="link" onClick={() => void load()}>
            重试
          </Button>
        </div>
      )}
      <Tabs defaultValue="sessions">
        <TabsList>
          <TabsTrigger value="sessions">会话 ({total})</TabsTrigger>
          <TabsTrigger value="topology">拓扑与关联</TabsTrigger>
          <TabsTrigger value="ingest">来源登记</TabsTrigger>
        </TabsList>
        <TabsContent value="sessions" className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Input
              aria-label="搜索观察记录"
              className="w-56"
              placeholder="搜索来源、主机、注释"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(1);
              }}
            />
            <Input
              aria-label="来源筛选"
              className="w-44"
              placeholder="精确来源名称"
              value={source}
              onChange={(e) => {
                setSource(e.target.value);
                setPage(1);
              }}
            />
            <Input
              aria-label="任务筛选"
              type="number"
              min="1"
              className="w-36"
              placeholder="任务 ID"
              value={task}
              onChange={(e) => {
                setTask(e.target.value);
                setPage(1);
              }}
            />
            <select
              aria-label="来源类型"
              className={selectClass}
              value={kind}
              onChange={(e) => {
                setKind(e.target.value);
                setPage(1);
              }}
            >
              <option value="">全部来源类型</option>
              <option value="c2">C2</option>
              <option value="webshell">WebShell</option>
            </select>
            <select
              aria-label="会话状态"
              className={selectClass}
              value={state}
              onChange={(e) => {
                setState(e.target.value);
                setPage(1);
              }}
            >
              <option value="">全部状态</option>
              {["connected", "stale", "disconnected", "unknown"].map((value) => (
                <option key={value} value={value}>
                  {stateNames[value]}
                </option>
              ))}
            </select>
          </div>
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/40">
                <tr>
                  {["来源 / 外部标识", "类型 / 协议标签", "主机", "状态", "关联", "心跳", "操作"].map((label) => (
                    <th key={label} className="p-3 font-medium">
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} className="border-t">
                    <td className="p-3">
                      {item.source}
                      <div className="text-muted-foreground text-xs">{item.source_id}</div>
                    </td>
                    <td className="p-3">
                      {item.kind}
                      <div className="text-muted-foreground text-xs">{item.protocol_label || "未提供"}</div>
                    </td>
                    <td className="p-3">{item.host || "—"}</td>
                    <td className="p-3">
                      <Badge variant={item.effective_state === "connected" ? "default" : "outline"}>
                        {stateNames[item.effective_state] ?? item.effective_state}
                      </Badge>
                    </td>
                    <td className="p-3">
                      任务 {item.task_id ?? "—"}
                      <br />
                      资产 {item.asset_id ?? "—"}
                    </td>
                    <td className="p-3">
                      {formatTime(item.heartbeat_at)}
                      <div className="text-muted-foreground text-xs">{item.heartbeat_ttl_seconds}s 有效期</div>
                    </td>
                    <td className="p-3">
                      <Button variant="outline" size="sm" onClick={() => void open(item.id)}>
                        详情与审计
                      </Button>
                    </td>
                  </tr>
                ))}
                {!items.length && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-muted-foreground">
                      {emptyMessage}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span>
              共 {total} 条 · 第 {page} 页
            </span>
            <div className="flex gap-2">
              <Button variant="outline" disabled={page <= 1 || loading} onClick={() => setPage(page - 1)}>
                上一页
              </Button>
              <Button variant="outline" disabled={page * 20 >= total || loading} onClick={() => setPage(page + 1)}>
                下一页
              </Button>
            </div>
          </div>
          {detail && (
            <section className="space-y-3 rounded-lg border p-4">
              <div className="flex justify-between">
                <h2 className="font-semibold">
                  观察 #{detail.session.id} · {detail.session.source_id}
                </h2>
                <Button variant="ghost" onClick={closeDetail}>
                  关闭详情
                </Button>
              </div>
              <dl className="grid gap-2 text-sm md:grid-cols-2">
                <div>模式：{detail.session.mode}</div>
                <div>状态：{stateNames[detail.session.effective_state]}</div>
                <div className="break-all">URL：{detail.session.url || "—"}</div>
                <div>最近更新：{formatTime(detail.session.updated_at)}</div>
                <div>断开原因：{detail.session.disconnect_reason || "—"}</div>
                <div>注释：{detail.session.annotation || "—"}</div>
                <div>
                  任务：{detail.session.task_id ?? "—"} · 资产：{detail.session.asset_id ?? "—"}
                </div>
                <div>支持操作：{detail.capabilities.join(" / ")}</div>
              </dl>
              <Textarea
                aria-label="操作说明"
                value={note}
                maxLength={2000}
                onChange={(e) => setNote(e.target.value)}
                placeholder="填写注释或库存断开原因"
              />
              <div className="flex gap-2">
                <Button
                  disabled={busy || !note.trim()}
                  onClick={() => void run(() => inventoryAPI.action(detail.session.id, "annotate", note), "注释已保存")}
                >
                  保存注释
                </Button>
                <Button
                  variant="outline"
                  disabled={busy || !note.trim()}
                  onClick={() =>
                    void run(() => inventoryAPI.action(detail.session.id, "disconnect", note), "库存记录已断开")
                  }
                >
                  断开库存记录
                </Button>
                <Button variant="outline" onClick={() => void open(detail.session.id)}>
                  读取最新状态
                </Button>
              </div>
              <h3 className="font-medium">最近 100 条审计</h3>
              <div className="max-h-60 overflow-auto text-sm">
                {detail.audit.map((entry) => (
                  <div key={entry.id} className="border-t py-2">
                    <span className="text-muted-foreground">{formatTime(entry.created_at)}</span> · {entry.action} ·{" "}
                    {entry.state} · 序号 {entry.sequence}
                    <p>{entry.detail}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </TabsContent>
        <TabsContent value="topology" className="space-y-4">
          <p className="text-muted-foreground text-sm">
            只显示显式提交的节点与关系。网段成员关系不表示网络连通；隧道仅记录元数据，凭据仅保存引用标识。当前任务筛选：
            {task || "全部"}。
          </p>
          {graph && (
            <section aria-label="拓扑汇总" className="rounded-lg border p-4">
              <h2 className="font-semibold">汇总 · {task ? `任务 ${task}` : "全部任务"}</h2>
              <dl className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4 lg:grid-cols-7">
                {summaryFields.map((field) => (
                  <div key={field.key}>
                    <dt className="text-muted-foreground text-xs">{field.label}</dt>
                    <dd className="font-semibold text-lg tabular-nums">{graph.summary[field.key]}</dd>
                  </div>
                ))}
              </dl>
              {graph.empty.nodes && task && (
                <p role="status" className="mt-3 rounded border p-3 text-muted-foreground">
                  该任务尚无拓扑节点：未登记主机、网段、隧道或凭据引用。节点只能由显式登记或来源观察写入，不会由同网段推断产生。
                </p>
              )}
              {!graph.empty.edges && graph.summary.active_edges === 0 && (
                <p role="status" className="mt-3 rounded border p-3 text-muted-foreground">
                  已登记的关系当前全部无效，原因见下方每条关系的标记。
                </p>
              )}
            </section>
          )}
          <IntranetPanel task={task} context={intranet} />
          {graph?.truncated && <p role="status">图已达到 500 节点 / 1000 关系上限，请按任务筛选。</p>}
          <div className="grid gap-4 lg:grid-cols-2">
            <section className="rounded-lg border p-4">
              <h2 className="mb-3 font-semibold">节点</h2>
              <div className="max-h-96 space-y-2 overflow-auto">
                {graph?.nodes.map((node) => (
                  <div className="flex items-center justify-between gap-3 rounded border p-2 text-sm" key={node.ref}>
                    <div>
                      <strong>{node.label}</strong>
                      <div className="break-all text-muted-foreground">
                        {node.ref} · {node.kind} · {node.address || ""}
                      </div>
                    </div>
                    <Badge variant={node.effective_state === "active" ? "default" : "outline"}>
                      {stateNames[node.effective_state] ?? node.effective_state}
                    </Badge>
                    {node.expires_at && (
                      <span className="text-muted-foreground text-xs">到期 {formatTime(node.expires_at)}</span>
                    )}
                    {node.kind !== "session" && (
                      <Button size="sm" variant="ghost" onClick={() => void openNode(node.id)}>
                        审计
                      </Button>
                    )}
                  </div>
                ))}
                {!graph?.nodes.length && (
                  <p className="text-muted-foreground text-sm">
                    {task ? "该任务尚无节点。" : "尚无节点。先在上方选择任务，或在下方登记节点。"}
                  </p>
                )}
              </div>
            </section>
            <section className="rounded-lg border p-4">
              <h2 className="mb-3 font-semibold">显式关系</h2>
              <div className="max-h-96 space-y-2 overflow-auto">
                {graph?.edges.map((edge) => (
                  <div key={edge.id} className="rounded border p-2 text-sm">
                    <div className="break-all">
                      {edge.source_ref} → {edge.target_ref}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span>
                        {relationNames[edge.relation] ?? edge.relation} ·{" "}
                        {stateNames[edge.effective_state] ?? edge.effective_state}
                      </span>
                      {edge.reason && (
                        <Badge variant="outline" title={edge.reason}>
                          {reasonNames[edge.reason] ?? edge.reason}
                        </Badge>
                      )}
                    </div>
                    <p className="text-muted-foreground">{edge.note}</p>
                    <Button size="sm" variant="ghost" onClick={() => void openEdgeAudit(edge.id)}>
                      关系审计
                    </Button>
                  </div>
                ))}
                {!graph?.edges.length && (
                  <p className="text-muted-foreground text-sm">
                    {task ? "该任务尚未提交显式关系。" : "尚未提交显式关系。"}
                  </p>
                )}
              </div>
            </section>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <section className="space-y-3 rounded-lg border p-4">
              <h2 className="font-semibold">登记 / 更新节点</h2>
              <div className="flex flex-wrap gap-2">
                <select
                  aria-label="节点类型"
                  className={selectClass}
                  value={nodeForm.kind}
                  onChange={(e) => setNodeForm({ ...nodeForm, kind: e.target.value, address: "" })}
                >
                  {["host", "subnet", "tunnel", "credential_ref"].map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
                <select
                  aria-label="节点状态"
                  className={selectClass}
                  value={nodeForm.state}
                  onChange={(e) => setNodeForm({ ...nodeForm, state: e.target.value })}
                >
                  {["active", "invalid", "expired"].map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </div>
              {nodeForm.kind === "credential_ref" && (
                <>
                  <Input
                    aria-label="节点 scope"
                    placeholder="凭据适用范围（如 host / domain，仅描述）"
                    value={nodeForm.scope}
                    onChange={(e) => setNodeForm({ ...nodeForm, scope: e.target.value })}
                  />
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">过期时间（留空为不过期）</span>
                    <Input
                      aria-label="节点过期时间"
                      type="datetime-local"
                      value={nodeForm.expires_at}
                      onChange={(e) => setNodeForm({ ...nodeForm, expires_at: e.target.value })}
                    />
                  </div>
                </>
              )}
              {(["external_ref", "label", "address", "task_id", "asset_id"] as const).map((field) => (
                <Input
                  key={field}
                  aria-label={`节点 ${field}`}
                  placeholder={
                    {
                      external_ref: "稳定来源引用（更新时沿用）",
                      label: "节点名称",
                      address: "主机 IP / 网段 CIDR；引用类型留空",
                      task_id: "任务 ID（可选）",
                      asset_id: "资产 ID（可选）",
                    }[field]
                  }
                  value={nodeForm[field]}
                  onChange={(e) => setNodeForm({ ...nodeForm, [field]: e.target.value })}
                />
              ))}
              <Button
                disabled={busy || !nodeForm.external_ref || !nodeForm.label}
                onClick={() => void run(() => inventoryAPI.node(nodePayload()), "节点已保存")}
              >
                保存节点
              </Button>
            </section>
            <section className="space-y-3 rounded-lg border p-4">
              <h2 className="font-semibold">登记 / 更新关系</h2>
              <select
                aria-label="关系类型"
                className={selectClass}
                value={edgeForm.relation}
                onChange={(e) => setEdgeForm({ ...edgeForm, relation: e.target.value })}
              >
                {Object.entries(relationNames).map(([key, label]) => (
                  <option value={key} key={key}>
                    {label}
                  </option>
                ))}
              </select>
              <Input
                aria-label="关系起点"
                placeholder="session:ID 或 node:ID"
                value={edgeForm.source_ref}
                onChange={(e) => setEdgeForm({ ...edgeForm, source_ref: e.target.value })}
              />
              <Input
                aria-label="关系终点"
                placeholder="node:ID"
                value={edgeForm.target_ref}
                onChange={(e) => setEdgeForm({ ...edgeForm, target_ref: e.target.value })}
              />
              <select
                aria-label="关系状态"
                className={selectClass}
                value={edgeForm.state}
                onChange={(e) => setEdgeForm({ ...edgeForm, state: e.target.value })}
              >
                <option value="active">有效</option>
                <option value="inactive">无效</option>
              </select>
              <Textarea
                aria-label="关系说明"
                value={edgeForm.note}
                onChange={(e) => setEdgeForm({ ...edgeForm, note: e.target.value })}
              />
              <Button
                disabled={busy || !edgeForm.source_ref || !edgeForm.target_ref}
                onClick={() => void run(() => inventoryAPI.edge(edgeForm), "显式关系已保存")}
              >
                保存关系
              </Button>
            </section>
          </div>
          {edgeAudit && (
            <section className="space-y-2 rounded-lg border p-4">
              <div className="flex justify-between">
                <h2 className="font-semibold">关系审计</h2>
                <Button variant="ghost" onClick={() => setEdgeAudit(null)}>
                  关闭
                </Button>
              </div>
              {edgeAudit.map((entry) => (
                <p key={entry.id} className="border-t py-2 text-sm">
                  {formatTime(entry.created_at)} · {entry.state} · {entry.note}
                </p>
              ))}
            </section>
          )}
          {nodeAudit && (
            <section className="space-y-2 rounded-lg border p-4">
              <div className="flex justify-between">
                <h2 className="font-semibold">{nodeAudit.node.label} · 节点审计</h2>
                <Button variant="ghost" onClick={() => setNodeAudit(null)}>
                  关闭
                </Button>
              </div>
              {nodeAudit.audit.map((entry) => (
                <p key={entry.id} className="border-t py-2 text-sm">
                  {formatTime(entry.created_at)} · {entry.state} · {entry.label}
                </p>
              ))}
            </section>
          )}
        </TabsContent>
        <TabsContent value="ingest" className="space-y-4">
          <section className="space-y-3 rounded-lg border p-4">
            <h2 className="font-semibold">提交来源观察 JSON</h2>
            <p className="text-muted-foreground text-sm">
              必填 source、source_id、递增 sequence、kind、state。可关联现有 task_id / asset_id。心跳有效期默认 120
              秒；重复序号必须保持原始内容一致。
            </p>
            <Textarea
              aria-label="来源观察 JSON"
              rows={12}
              value={observation}
              onChange={(e) => setObservation(e.target.value)}
              placeholder={
                '{"source":"my-observer","source_id":"service-1","sequence":1,"kind":"c2","state":"connected","protocol_label":"http-health-observer","host":"service.internal","heartbeat_ttl_seconds":120}'
              }
            />
            <Button
              disabled={busy || !observation.trim()}
              onClick={() => void run(() => inventoryAPI.observe(JSON.parse(observation)), "观察已接收")}
            >
              提交观察
            </Button>
          </section>
          <section className="rounded-lg border p-4 text-sm">
            <h2 className="font-semibold">只读健康来源</h2>
            <p className="mt-2">
              仓库提供 scripts/session-inventory/observe_health.py，通过 GET 读取普通服务健康端点，使用
              ARTEX_OBSERVER_TOKEN 向本平台提交状态。令牌只发送到 ARTEX 地址；支持按计划重复执行。
            </p>
          </section>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// IntranetPanel shows the task-scoped context the worker would receive: the
// worker_intranet variant when a valid session and credential exist, and the
// explicit reason it does not otherwise. This mirrors what the model sees, so an
// operator can tell "the worker has no route" apart from "the worker is ignoring
// the route it has".
function IntranetPanel({ task, context }: { task: string; context: IntranetContext | null }) {
  if (!task) {
    return (
      <section aria-label="内网上下文" className="rounded-lg border p-4 text-sm">
        <h2 className="font-semibold">内网上下文</h2>
        <p className="mt-1 text-muted-foreground">
          按任务查看。选择任务后显示该任务的 worker 内网变体与可用性原因；未选任务时不提供跨任务视图。
        </p>
      </section>
    );
  }
  if (!context) {
    return (
      <section aria-label="内网上下文" className="rounded-lg border p-4 text-sm">
        <h2 className="font-semibold">内网上下文</h2>
        <p className="mt-1 text-muted-foreground">正在读取任务 {task} 的内网上下文…</p>
      </section>
    );
  }
  return (
    <section aria-label="内网上下文" className="space-y-3 rounded-lg border p-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-semibold">内网上下文 · 任务 {task}</h2>
        <Badge variant={context.available ? "default" : "outline"}>{context.variant}</Badge>
      </div>
      {context.available ? (
        <>
          <p className="text-muted-foreground">
            该任务的 worker 会收到以下会话与凭据，并只能用于本任务。会话失效或凭据过期后，下一次工具调用即被拒绝。
          </p>
          <div className="grid gap-4 lg:grid-cols-2">
            <div>
              <h3 className="mb-2 font-medium">可用会话 ({context.sessions.length})</h3>
              {context.sessions.length ? (
                context.sessions.map((session) => (
                  <div key={session.id} className="rounded border p-2">
                    <div className="break-all">
                      会话 #{session.id} · {session.host || "未提供主机"}
                    </div>
                    <div className="text-muted-foreground text-xs">
                      {session.protocol || "未提供协议"} · 心跳 {heartbeatAge(session.heartbeat_at)} ·{" "}
                      {session.state}
                    </div>
                    <div className="break-all text-muted-foreground text-xs">{session.url || "—"}</div>
                  </div>
                ))
              ) : (
                <p className="text-muted-foreground">无可用会话。</p>
              )}
            </div>
            <div>
              <h3 className="mb-2 font-medium">可用凭据引用 ({context.credentials.length})</h3>
              {context.credentials.length ? (
                context.credentials.map((credential) => (
                  <div key={credential.ref} className="rounded border p-2">
                    <div className="break-all">
                      {credential.label} · {credential.ref}
                    </div>
                    <div className="text-muted-foreground text-xs">
                      范围 {credential.scope || "未标注"} · {credential.state} · 到期{" "}
                      {credential.expires_at ? formatTime(credential.expires_at) : "不过期"}
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-muted-foreground">无可用凭据引用。</p>
              )}
            </div>
          </div>
        </>
      ) : (
        <div role="status" className="rounded border p-3">
          <p className="font-medium">本任务暂无内网上下文</p>
          <p className="mt-1 text-muted-foreground">
            {intranetReasonNames[context.reason] ?? context.reason}
            {context.reason ? <span className="ml-1 text-xs">({context.reason})</span> : null}
          </p>
          <p className="mt-1 text-muted-foreground text-xs">
            worker 在不可用时不会收到任何内网提示；此处仅供运维定位原因。
          </p>
        </div>
      )}
    </section>
  );
}
