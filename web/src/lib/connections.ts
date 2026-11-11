import { http } from "./api";

// C2/WebShell adapter client. The backend never returns the sealed or plaintext
// credential: secret_ref is the only secret-shaped field in these responses.

export interface ConnectionAdapter {
  id: number;
  name: string;
  kind: string;
  base_url: string;
  secret_ref: string;
  timeout_seconds: number;
  heartbeat_ttl_seconds: number;
  enabled: boolean;
  state: "unconfigured" | "reachable" | "unreachable" | "auth_failed";
  last_error: string;
  checked_at: string | null;
  task_id?: number | null;
  asset_id?: number | null;
  session_id?: number | null;
  created_at: string;
  updated_at: string;
  capabilities: string[];
}

export interface ConnectionSession {
  id: number;
  source: string;
  source_id: string;
  kind: string;
  protocol_label: string;
  effective_state: string;
  host: string;
  url: string;
  task_id?: number | null;
  asset_id?: number | null;
  heartbeat_at: string | null;
  heartbeat_ttl_seconds: number;
  disconnect_reason: string;
  annotation: string;
  updated_at: string;
  adapter: {
    id: number;
    name: string;
    kind: string;
    secret_ref: string;
    state: ConnectionAdapter["state"];
    enabled: boolean;
    capabilities: string[];
    last_error: string;
    checked_at: string | null;
    base_url: string;
    timeout_seconds: number;
  };
}

export interface ConnectionOperation {
  id: number;
  adapter_id: number;
  session_id: number;
  request_id: string;
  action: string;
  args_summary: string;
  status: "running" | "succeeded" | "failed" | "timeout" | "unsupported";
  exit_code: number | null;
  output: string;
  error: string;
  started_at: string;
  finished_at: string | null;
  /** Inventory sequence the operation ran against. */
  session_sequence: number | null;
  /** "sha256:<hex>" over the stored output; empty when there is no output. */
  output_ref: string;
}

/** Shape every paginated list endpoint returns. */
export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  truncated: boolean;
}

export interface AdapterList extends PageMeta {
  items: ConnectionAdapter[];
  capabilities: string[];
  kinds: string[];
}

export interface SessionList extends PageMeta {
  items: ConnectionSession[];
  capabilities: string[];
}

export interface OperationList extends PageMeta {
  items: ConnectionOperation[];
  session: ConnectionSession;
  capabilities: string[];
}

export interface AdapterInput {
  name: string;
  kind: string;
  base_url: string;
  secret?: string;
  secret_ref: string;
  timeout_seconds: number;
  heartbeat_ttl_seconds: number;
  enabled: boolean;
  task_id?: number | null;
  asset_id?: number | null;
}

export interface OperationInput {
  action: string;
  cmd?: string;
  argv?: string[];
  timeout_ms?: number;
  request_id: string;
}

const post = <T>(path: string, value?: unknown) =>
  http<T>(`/connections${path}`, {
    method: "POST",
    ...(value === undefined ? {} : { body: JSON.stringify(value) }),
  });

export const connectionsAPI = {
  adapters: () => http<AdapterList>("/connections/adapters"),
  adapter: (id: number) => http<ConnectionAdapter>(`/connections/adapters/${id}`),
  createAdapter: (input: AdapterInput) => post<ConnectionAdapter>("/adapters", input),
  updateAdapter: (id: number, input: AdapterInput) =>
    http<ConnectionAdapter>(`/connections/adapters/${id}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteAdapter: (id: number) => http<null>(`/connections/adapters/${id}`, { method: "DELETE" }),
  checkAdapter: (id: number) => post<ConnectionAdapter>(`/adapters/${id}/check`),
  syncAdapter: (id: number) =>
    post<{ adapter: ConnectionAdapter; session: ConnectionSession; state: string; replayed: boolean }>(
      `/adapters/${id}/sync`,
    ),
  sessions: (page = 1, limit = 20) =>
    http<SessionList>(`/connections/sessions?page=${page}&limit=${limit}`),
  operations: (sessionId: number, page = 1, limit = 20) =>
    http<OperationList>(`/connections/sessions/${sessionId}/operations?page=${page}&limit=${limit}`),
  run: (sessionId: number, input: OperationInput) =>
    post<ConnectionOperation>(`/sessions/${sessionId}/operations`, input),
};

export const connectionStateLabel: Record<string, string> = {
  unconfigured: "未检查",
  reachable: "可达",
  unreachable: "不可达",
  auth_failed: "凭据被拒绝",
};

export const connectionSessionStateLabel: Record<string, string> = {
  connected: "在线",
  stale: "心跳失联",
  disconnected: "已断开",
  unknown: "未知",
};

export const connectionOperationStatusLabel: Record<string, string> = {
  running: "执行中",
  succeeded: "已完成",
  failed: "失败",
  timeout: "超时",
  unsupported: "不支持",
};
