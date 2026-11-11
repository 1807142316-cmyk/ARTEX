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

With the transparent sandbox off, this is HTTP proxy routing only: raw TCP/UDP,
DNS resolver traffic, programs that ignore proxy variables, custom remote MCP
services, and browser services hosted outside the application process are not
redirected. The UI states this scope. Changing pool settings while tools are
already running requires pausing and continuing tasks to rebuild their process
and browser environments. Pooled task Bash environments clear inherited
`NO_PROXY` and `no_proxy` bypasses. Programs can still explicitly override their
own proxy configuration. With the sandbox off no network isolation claim is
made.

With `egress_sandbox_enabled` on and the required capabilities present the scope
is different, and is stated once in the sandbox section below.

## Transparent task egress sandbox (Linux)

Setting `egress_sandbox_enabled` (default off, only meaningful with the pool on)
forces task tool traffic through the task lease instead of relying on proxy
environment variables. It lives in `egress/`, is Linux-only, and is rejected on
other platforms; the rest of the program is unaffected there.

Per task the server starts a relay child in its own network namespace
(`CLONE_NEWNET`). Inside that namespace nftables redirects every outbound TCP
connection to the relay and every DNS query (UDP and TCP port 53) to the relay's
resolver bridge, while all non-loopback output is dropped — plain UDP, ICMP and
raw sockets fail closed. The relay asks the server for each connection over a
0600 Unix socket in the data directory; the server resolves the destination with
the existing `proxyPool.route` lease/policy code plus `dialTaskProxy` and passes
the connected fd back with `SCM_RIGHTS`. The task's HTTP gateway address is
mirrored inside the namespace, so proxy-aware clients keep their unchanged proxy
URL and still land on the lease-recording gateway. DNS is forwarded over TCP
through the same route.

Bash runs as `nsenter --net=/proc/<relay>/ns/net -- /bin/sh -c '<command>'`, so
quoting, cwd, environment, pipes, heredocs, background jobs and exit codes are
preserved. Pooled sandboxed Bash also clears inherited `NO_PROXY`/`no_proxy`. If
the sandbox cannot be created, or the relay dies, the command does not run and
the task's existing policy applies (pause by default; failover or direct only
when the operator selected it) with a `sandbox_failed` audit event. Failed
requests are never replayed.

Requirements: Linux with `CAP_SYS_ADMIN` (CLONE_NEWNET) and `CAP_NET_ADMIN`
(nftables), plus `iproute2`, `nftables` and `util-linux` (nsenter). The
`Dockerfile.source` image installs those packages; `compose.source.yml` adds the
capabilities. Without them the sandbox cannot start and sandboxed tasks pause —
no isolation is claimed for such a deployment.

Scope after the sandbox, stated precisely:

- Forced through the task's netns and lease: Bash and scripts run by task tools
  that execute inside the task process tree, including raw TCP clients and DNS
  queries, whether or not the program honours proxy environment variables.
- Deliberately not covered, and still on the pre-sandbox behaviour: external MCP
  servers and browser services that run outside the task process tree, the
  application's own internal calls (model, search, enrichment, notifications),
  UDP other than DNS (so no QUIC, no custom UDP protocols), ICMP, and SOCKS5
  `UDP ASSOCIATE` — the relay only speaks TCP and DNS, so a UDP-over-SOCKS5
  client still fails closed rather than being tunnelled.

Standalone scanning must either supply an associated task gateway or be rejected
when the pool is enabled. The actual Agent-assembled Playwright MCP/Chromium
test passed on Windows with two tasks assigned two different proxies, including
an inherited `NO_PROXY=*`; both navigations returned their assigned exit marker
and left persisted browser arguments unchanged. Six HTTP/PostgreSQL proxy tests
also passed on Linux, covering the gateway behavior below. The same actual
Agent-assembled browser test subsequently passed on Ubuntu 22.04 with Node
24.22.1, Playwright MCP 0.0.85 and Chrome for Testing 158.0.8127.18 at source
`8039cb6`. It exercised two distinct task exits with inherited `NO_PROXY=*` and
preserved persisted MCP arguments. Tooling and shared libraries were extracted
only into the independent validation directory; no system packages or existing
service configuration were changed. Complete application deployment still needs
acceptance, and the raw/non-proxy-aware traffic exclusions above remain. These checks cover
parallel exit separation, stable retries, proxy failure/default pause, explicit
failover/direct fallback with recorded transitions, recording on/off parity,
SOCKS5 forwarding, authentication and credential redaction.

