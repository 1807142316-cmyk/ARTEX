# CVE corpus and background updates

The authenticated `/intelligence/cve` page searches the local PostgreSQL corpus.
Searching and viewing retained source records requires no upstream connection.
The search includes CNA/ADP product names, affected modules, program files, CPEs,
descriptions, identifiers and references. Original affected-version/container
structures remain in `raw`.

The updater starts with the server, independently of business tasks and browsers.
Automatic updates default to enabled, checked every 60 minutes after an initial
five-minute startup delay. The UI can disable automatic checks, change the
interval (5 minutes to 7 days), or queue an immediate update. Disabling automatic
checks does not cancel an already queued/running import.

Upstream is the CVE Program's official `CVEProject/cvelistV5` latest release API.
Each release carries a daily full baseline and a delta cumulative since that
baseline. The first run applies baseline then delta. Later runs within the same
baseline apply the latest cumulative delta; a changed baseline is fully reapplied
before its delta. This reconciles arbitrary missed release windows and REJECTED
state changes without inventing a delta history. Daily reconciliation consumes
more bandwidth than a Git mirror, but avoids gaps. Source versions advance only
after every asset in a run succeeds. A no-change check records a successful check
without reimporting unchanged assets.

Runs, settings, counts and checkpoints persist in PostgreSQL. A session advisory
lock and partial unique index prevent concurrent updaters, including multiple
application instances. Each 250-record batch commits its records and checkpoint
in the same transaction. Cancellation or a process restart leaves the active run
resumable: it reopens its immutable cached archive, skips committed records, and
continues. Network/format failures preserve already usable records and the last
successful source cursor; automatic checks retry after at most 15 minutes. The
next release reconciles from the last completed baseline. Batch retry uses the
record content hash and does not inflate added/modified totals.

Downloads use temporary files and atomic rename, bounded transfer size, request
timeouts, and no extraction of source-controlled paths. Archives and SHA-256
manifests are stored in `<data>/content/cve/`, under the existing persistent data
volume. After a run finishes, obsolete hashed ZIPs are removed while archives referenced by queued/running runs and the latest successful content run remain. Historical manifests and database run metadata are retained. Non-cache files and links are left untouched. Manifests record source URL/name/version, acquired time, SHA-256, parser
version and CVE Program terms URL. A resumed run checks its stored checksum before
using an archive. Preserve this directory with PostgreSQL when backing up. Source
archives are metadata only; they contain no exploit-code corpus.

For an offline or predownloaded bootstrap, use the repository's `cmd/cve-import`
command with an official baseline ZIP and explicit source version; see its `-help`
and `DEPLOYMENT.md`. The initial automatic run still establishes the official
baseline/delta cursor, idempotently reconciling manually imported records.
`ARTEX_CVE_RELEASE_API` may point to an administrator-managed compatible mirror;
the default uses the official GitHub API. It is server configuration, not an API
request URL field.

HTTP controls, under the normal ARTEX authentication middleware:

- `GET /api/cve/sync`: settings, committed source cursor, latest run/progress,
  last check/success, next check and errors.
- `PUT /api/cve/sync`: `{ "enabled": true, "interval_minutes": 60 }`.
- `POST /api/cve/sync`: durable queue, HTTP 202; duplicate active queue is HTTP 409.
- `GET /api/cve` and `/api/cve/stats`: local search and actual counts.

Verification: with `ARTEX_PG_DSN` pointing to a dedicated PostgreSQL database, run
`go test -v ./server -run '^TestCVESync' -count=1`. Controlled HTTP upstreams and
real PostgreSQL cover first baseline, cumulative changes/new records/rejection,
component search, changed-baseline reconciliation, failure/offline availability,
concurrent request rejection, committed checkpoint restart and retry counts.
These tests clear CVE feature tables in the dedicated test database. Linux Compose
cold-start/restart/backup acceptance remains a separate deployment check and is
not certified by Windows-hosted tests or cross-compilation.