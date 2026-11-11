# Session observation inventory

This module records external session observations. The `c2` and `webshell`
values classify the reporting source; `protocol_label` is descriptive metadata.
The implemented adapter is `http-health-observer`: a regular HTTP GET health
check followed by an authenticated JSON observation submission. It is not an
`http_phpcmd` execution adapter. No command, shell, tunnel activation, credential
read, worker context change or remote disconnect is implemented here. Issues
#9 and #10 remain incomplete against their original execution requirements.

The UI is **作战 → 会话与拓扑观察** (`/operations/sessions`). It includes paginated
session filters, status/details, the latest 100 audit entries, annotations,
inventory-only disconnect, explicit node/edge management, node audit, and JSON
observation submission. Connected observations become `stale` when their last
heartbeat plus TTL expires; status is computed when queried, without requiring
an always-open page. The page refreshes every 15 seconds.

## Authenticated observation API

Use the application's normal Bearer JWT for all endpoints. Send one JSON object
(no secret fields) to `POST /api/session-inventory/observations`:

```json
{
  "source": "service-health-monitor",
  "source_id": "service-one",
  "sequence": 1,
  "kind": "c2",
  "protocol_label": "http-health-observer",
  "state": "connected",
  "host": "service.internal",
  "url": "https://service.internal/health",
  "heartbeat_ttl_seconds": 120
}
```

`task_id` and `asset_id` are optional numeric references to existing records. If
both are supplied, the asset must belong to the task. URLs cannot include user
credentials, query strings or fragments. Bodies are limited to 32 KiB. A supplied
`heartbeat_at` uses RFC3339; omit it to use server receipt time. Future timestamps
more than 30 seconds ahead are rejected. TTL is 1–86400 seconds, default 120.

The identity is `(source, source_id)`. Increasing sequences record a new
observation and audit entry. An identical retry returns the current record with
`replayed=true`, without extending its heartbeat or adding duplicate audit.
Reusing a sequence with different content or sending an older sequence returns
409. Changing associations requires a new sequence and valid references.
An inventory disconnect does not change the remote source. A later genuinely new
observation can report that source connected again.

- `GET /api/session-inventory/sessions`: `q`, exact `source`, `kind`, effective
  `state`, `task_id`, `page`, `limit` (max 100).
- `GET /api/session-inventory/sessions/{id}`: session, capabilities and audit.
- `POST /api/session-inventory/sessions/{id}/annotate`: `{"detail":"..."}`.
- `POST /api/session-inventory/sessions/{id}/disconnect`: same shape, changes only
  the inventory record and records the supplied reason.

## Explicit topology metadata

`POST /api/session-inventory/nodes` upserts a stable `external_ref` with `kind`,
`label`, `address`, `state` and optional task/asset references. Supported kinds:

- `host`: optional IP address.
- `subnet`: required CIDR, normalized to its network.
- `tunnel`: metadata reference only, empty address.
- `credential_ref`: external reference only, empty address; no secret value.

Node state is `active`, `invalid` or `expired`. The kind of an existing stable
reference cannot change. Each update retains node audit. Use
`GET /api/session-inventory/nodes/{id}` to read it.

`POST /api/session-inventory/edges` upserts `source_ref`, `target_ref`, `relation`,
`state` (`active`/`inactive`) and optional `note`. Node references use `node:ID`;
session references use `session:ID`. Permitted directions are session→host
`hosted_on`, host→subnet `member_of`, session→tunnel `tunnel_metadata`, and
session→credential_ref `credential_reference`. Missing endpoints, invalid kind
pairs and endpoints belonging to different tasks are rejected. Edges also retain
an immutable state/note audit in PostgreSQL.

`GET /api/session-inventory/topology` supports `q` and `task_id`. It reads one
repeatable database snapshot and returns explicit nodes and edges only. It never
creates connectivity from IP/subnet membership. Invalid nodes, stale/disconnected
sessions or mismatched task ownership make an existing relationship effectively
inactive. The result is bounded at 500 nodes and 1000 edges and signals
`truncated=true` if filtering is required. Database foreign keys detach deleted
task/asset references rather than point at nonexistent records.

## Runnable read-only observer

Requires Python 3.9+ standard library. Export a JWT in `ARTEX_OBSERVER_TOKEN` using
your normal credential storage; the script never prints it. Then run:

```sh
python3 scripts/session-inventory/observe_health.py \
  --artex-url https://artex.internal \
  --health-url https://service.internal/health \
  --source service-health-monitor --source-id service-one --kind c2
```

The script runs once and can be scheduled externally. It performs GET without
following redirects, discards response bodies, and reports connected only for
HTTP 2xx. It sends the JWT only to the ARTEX API. The ARTEX origin must use HTTPS
or loopback HTTP; both URLs reject embedded credentials, queries and fragments.
Optional flags: `--task-id`, `--asset-id`, `--ttl`, `--timeout` (1–30 seconds).
It prints only observation ID, state and mode. Clock-derived microsecond
sequences fit JSON's exact integer range at current dates; use one reporter per
source identity and keep its clock synchronized. Distributed writers should
provide their own monotonic sequence through the API.

## Verification

`TestSessionInventory*` exercises the authenticated HTTP handler with real
PostgreSQL: idempotency/conflicts/history, invalid foreign keys, actual task/asset
association, stale/disconnect/reconnect, explicit graph and invalidation,
cross-task rejection, immutable node kinds, and the actual Python observer
against an ordinary local health service. Set `ARTEX_TEST_PYTHON` when `python3`
is not on PATH. These checks do not certify C2/WebShell command protocol support.
