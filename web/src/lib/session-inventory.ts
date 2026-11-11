import { http } from "./api";

export interface InventorySession {
  id: number;
  source: string;
  source_id: string;
  sequence: number;
  kind: "c2" | "webshell";
  protocol_label: string;
  state: string;
  effective_state: string;
  host: string;
  url: string;
  mode: "observer";
  task_id?: number;
  asset_id?: number;
  heartbeat_at: string;
  heartbeat_ttl_seconds: number;
  disconnect_reason: string;
  annotation: string;
  updated_at: string;
}
export interface InventoryAudit {
  id: number;
  action: string;
  sequence: number;
  state: string;
  detail: string;
  created_at: string;
}
export interface InventoryDetail {
  session: InventorySession;
  audit: InventoryAudit[];
  capabilities: string[];
}
export interface InventoryNode {
  ref: string;
  id: number;
  kind: string;
  external_ref?: string;
  label: string;
  address?: string;
  state: string;
  effective_state: string;
  expires_at?: string;
  task_id?: number;
  asset_id?: number;
}
export interface InventoryEdge {
  id: number;
  source_ref: string;
  target_ref: string;
  relation: string;
  state: string;
  effective_state: string;
  /** Machine-readable reason an edge is inactive; empty when active. */
  reason: string;
  note: string;
}
export interface InventorySummary {
  hosts: number;
  subnets: number;
  sessions: number;
  tunnels: number;
  credentials: number;
  active_edges: number;
  inactive_edges: number;
}
/** true means the collection is empty for the current task filter. */
export interface InventoryEmpty {
  nodes: boolean;
  edges: boolean;
  sessions: boolean;
  tunnels: boolean;
  credentials: boolean;
}
export interface InventoryGraph {
  nodes: InventoryNode[];
  edges: InventoryEdge[];
  truncated: boolean;
  mode: string;
  summary: InventorySummary;
  empty: InventoryEmpty;
}
export interface IntranetContextSession {
  id: number;
  host: string;
  url: string;
  protocol: string;
  state: string;
  heartbeat_at: string;
}
export interface IntranetContextCredential {
  ref: string;
  label: string;
  scope: string;
  state: string;
  expires_at?: string;
}
export interface IntranetContext {
  variant: "worker_intranet" | "worker";
  available: boolean;
  reason: string;
  sessions: IntranetContextSession[];
  credentials: IntranetContextCredential[];
}
const post = <T>(path: string, value: unknown) =>
  http<T>(`/session-inventory${path}`, { method: "POST", body: JSON.stringify(value) });
export const inventoryAPI = {
  sessions: (params: URLSearchParams) =>
    http<{ items: InventorySession[]; total: number; page: number; limit: number }>(
      `/session-inventory/sessions?${params}`,
    ),
  detail: (id: number) => http<InventoryDetail>(`/session-inventory/sessions/${id}`),
  observe: (input: unknown) => post<{ session: InventorySession; replayed: boolean }>("/observations", input),
  action: (id: number, action: "annotate" | "disconnect", detail: string) =>
    post<InventorySession>(`/sessions/${id}/${action}`, { detail }),
  graph: (params: URLSearchParams) => http<InventoryGraph>(`/session-inventory/topology?${params}`),
  node: (input: unknown) => post<InventoryNode>("/nodes", input),
  edge: (input: unknown) => post<InventoryEdge>("/edges", input),
  nodeDetail: (id: number) =>
    http<{ node: InventoryNode; audit: { id: number; state: string; label: string; created_at: string }[] }>(
      `/session-inventory/nodes/${id}`,
    ),
  intranet: (taskID: string) => http<IntranetContext>(`/tasks/${taskID}/intranet-context`),
  edgeAudit: (id: number) =>
    http<{ items: { id: number; state: string; note: string; created_at: string }[] }>(
      `/session-inventory/edges/${id}/audit`,
    ),
};
