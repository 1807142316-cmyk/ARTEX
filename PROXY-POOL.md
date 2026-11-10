# Proxy pool runtime

The proxy pool is opt-in at `/system/proxies`. Existing global target proxy,
per-profile model proxy, and web-search proxy remain separate. With the pool
switched off, existing routing is retained. Add an HTTP, HTTPS or SOCKS5 endpoint
and a check URL that returns an IP address (plain text or a JSON `ip` field), then
check it before assignment. Health requests actually traverse that endpoint.
Unverified or unhealthy endpoints are excluded from assignment.

Each task receives an exclusive persisted endpoint lease. A local HTTP gateway
keeps its task's route stable across concurrent requests, capture toggles and
fallback policy changes. The gateway is bound only to `127.0.0.1`; like the
existing local recording proxy, it trusts processes running on the same host.
Do not expose its ports externally. Task recording authentication tokens are
removed before target forwarding and evidence capture. Upstream proxy URLs are
AES-GCM encrypted using a key derived from the installation JWT key; include
that key with database backups. Lists, errors and audit events omit credentials.

Task WebFetch and proxy-aware Bash/script HTTP clients receive the task gateway.
The seeded stdio browser MCP receives a task-local copy of its arguments rather
than changing its persisted configuration. Native custom HTTP requests and
worker-originated asynchronous HTTP asset enrichment use the same gateway.
Recorded traffic passes through the existing recorder and then returns to the
same task gateway for upstream selection. Direct and transparent recording
paths retain the lease. Model and search clients are not changed.

The default failure policy pauses the task and lease, with an audit event. The
operator can explicitly select failover to a healthy unused endpoint or allow
direct fallback. Failed requests are not automatically replayed, to avoid
repeating writes; the next request uses the chosen route. A healthy proxy's
ordinary target error does not automatically mark the proxy unhealthy. Health
checks run every minute and are available manually. A failed lease must be
reassigned before the operator resumes the task.

This is HTTP proxy routing, not a network namespace or firewall. Raw TCP/UDP,
DNS resolver traffic, programs that ignore proxy variables, custom remote MCP
services, and browser services hosted outside the application process are not
transparently redirected. The UI explicitly states this scope. Changing pool
settings while tools are already running requires pausing and continuing tasks
to rebuild their process and browser environments. Shell clients may have their
own `NO_PROXY` rules; those remain a limitation until process-level enforcement
is added. No unrestricted-network isolation claim is made.

Standalone scanning must either supply an associated task gateway or be rejected
when the pool is enabled. Linux runtime and real-browser execution still need
end-to-end deployment acceptance. Current actual-PostgreSQL HTTP tests cover
parallel exit separation, stable retries, proxy failure/default pause, explicit
failover/direct fallback with recorded transitions, recording on/off parity,
SOCKS5 forwarding, authentication and credential redaction.
