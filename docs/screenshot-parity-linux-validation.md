# Linux CVE and authored workflow acceptance

Date: 2026-11-11. Product revision: `ee74ee7` / `bcaee3b`; the additional
full-corpus HTTP acceptance test is at `832d658`. Later commits in this round
record tests and deployment instructions; they do not deploy the platform.

## Isolation and environment

The user supplied a Linux host with an existing ARTEX service and other running
applications. Validation uses `/opt/artex-cve-validation`, Compose project
`artex-cve-validation`, an independent PostgreSQL volume, separate full-corpus,
HTTP-test and restored databases, and an `internal: true` Docker network.
No validation database or application port is published. The existing ARTEX
binary, configuration, database, service and reverse proxy were not replaced.

- Ubuntu 22.04.5 LTS, x86-64, kernel `5.15.0-30-generic`.
- Two logical CPUs, approximately 1.93 GiB RAM, no swap.
- Docker `29.9.2`, Docker Compose `v5.6.1`.
- PostgreSQL `18.6`, image digest
  `postgres@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395`.
- Python `3.10.12` on the host.
- Go tools cross-compiled for Linux/amd64 with Go `1.27.3`, then actually run
  on Linux. PostgreSQL and import/test containers have 256 MiB memory limits;
  query containers have a 192 MiB limit. CPU limits are set separately.

SSH authentication material is not included in these files or in Git. Tool
hashes and source revisions are retained in the remote `tool-manifest.json`.

## Actual source content

The official CVE release `cve_2026-11-10_1900Z` was downloaded on the server,
not obtained by copying the production database. Its archive is 656,744,316
bytes; SHA-256 is
`8859cf40d4337e24bd2f258cc7778fbad01bb24c79d057aaf34cf1dfc6f8917d`.
The tracked source URL and terms are in
`content-manifests/cve-baseline.json`.

The real importer completed on an empty independent database:

```json
{"added":421793,"modified":0,"processed":421793,"source_version":"cve_2026-11-10_1900Z"}
```

The corpus contains 402,649 PUBLISHED and 19,144 REJECTED records. Real year
statistics were read from the database. Identifier, product and description
queries succeeded in the isolated network, including the exact
`CVE-2021-44228` record and its retained original JSON/source version.

## Completed runtime checks

- Five top-level CVE parser/archive tests passed, including nested official ZIP
  layout, cancellation, metadata across containers, rejected records and invalid
  input. No top-level tests skipped.
- Five authenticated HTTP/PostgreSQL CVE tests passed on the separate
  `cve_http_tests` database. These cover import/search, update failure preserving
  old data, cancellation recovery, concurrent start conflicts, incomplete
  releases, malformed cache retries and coherent status snapshots. The test
  sources are controlled HTTP servers; this does not assert that the production
  scheduler fetched a new upstream release.
- Nine authored workflow CLI tests passed on Linux Python; all seven authored
  package hashes matched `skills/content-manifest.json`. This does not fill the
  remaining screenshot-wide skill-content gap.
- `pg_dump -Fc` completed, and `pg_restore --exit-on-error` restored the whole
  database into `cve_restored`. Statistics and exact identifier/product/description
  query outputs matched the original database byte for byte.
- Restarting the independent PostgreSQL container retained matching statistics.
- Reimporting the unchanged official Log4Shell record reported one processed,
  zero added and zero modified. This is a record-level repeat check, not a
  second complete 421,793-record import.

The database backup `corpus.pgcustom` has SHA-256
`660f334b20c079fc7d3bf4513ca1107cb76ac390a54a5d498d91467d1ec009c1`.
Data-query/restore/restart checks finished at `2026-11-11T06:03:14Z`.

Full-corpus authenticated HTTP checks passed on the original database in 77.33
seconds and on the restored database in 66.54 seconds, with zero skips. These
checked unauthenticated rejection, exact total/state/year aggregates, retained
original JSON and source metadata, paginated exact identifier lookup, product,
component and description searches. `Apache Log4j` matched 21 records,
`log4j-core` matched one, and `cross-site scripting` matched 37,891. Both runs
reported 414,881 records with publication dates. The service context was
cancelled before constructing the HTTP server to prevent background tasks and
synchronization. The public authenticated handlers were exercised in-process
against the real Compose PostgreSQL instance; this was not a public deployment.

## Evidence and boundaries

Remote files include `manifest.json`, `tool-manifest.json`, `download.log`,
`import.log`, `cve-unit-tests.log`, `cve-http-tests.log`, `skill-tests.log`,
`skill-manifest.log`, `acceptance.log`, the original/restored/restarted query
JSON files, and `corpus.pgcustom` plus its checksum. These contain validation
material; `.env` is private and must not be copied into Git or public comments.

The collected `acceptance-evidence.tar.gz` is 16,556 bytes with SHA-256
`9e69eda864401521779c45052d26fcbb505711fc8548532a1ed8205de8ced85e`.
It was downloaded to the local validation directory and its hash checked again.
It excludes credentials and the large archive/database backup. After checks,
the independent PostgreSQL container was stopped; no validation container
remained running. Its volume, official archive, backup and evidence were kept.
The pre-existing ARTEX service remained active and its health endpoint returned
`ok: true` at the final check.

This round validates CVE storage/query/update behavior and the seven authored
workflows. It does not certify the complete ARTEX source image, Chromium/Agent
egress, metrics, platform upgrades, C2/WebShell or intranet features. The current
Compose JWT/config persistence gap is described in `DEPLOYMENT.md` and remains
relevant to whole-application recreation and upgrades.
