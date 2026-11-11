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
egress, metrics, platform upgrades, C2/WebShell or intranet features. The original
Compose JWT/config persistence gap was subsequently addressed in the source
override, with the regression evidence below. Whole-application container
recreation and upgrades still require their own acceptance.

## Additional content and gateway acceptance (source `8c41006`)

The same isolated validation project was used for these checks. It created
separate `templates_http_acceptance` and `workflows_acceptance` databases and
retained the existing CVE databases. No test port was published. The test image
was the already installed PostgreSQL Alpine image, with cross-compiled test
executables and explicitly selected local HTTP tests. This was not an application
deployment or upgrade.

- All 17 Python command tests passed on host Python 3.10.12; all 14 authored
  package hashes matched. The content archive SHA-256 is
  `ab32ed4ccfa359244d19821dc957341f6b982c86254398b1d6b8b1cd5136ac83`.
- Five top-level template syntax/bundle tests and eight authenticated HTTP tests
  passed with no skips. The actual Nuclei 3.4.10 engine checked local nginx,
  Apache, Angular and default-page responses; negative matches, extraction,
  immutable history, cancellation, proxy routing and failure behavior passed.
- Official Linux Nuclei archive SHA-256 matched
  `234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357`;
  the extracted executable hash was
  `794b5033f3e7b40b23bcf8a4e1c886d16275e0be2aaa19f0d8716a7bcb9e1489`.
  The test artifact archive hash was
  `9345926a9e5f78b5c9d52c996c5cdd28ce18b86c223df69a1d8d27afb72e231d`.
- The actual offline importer completed with `imported=11` and upstream commit
  `13f9bc679405927b7f78eb5dfd3e7260ed3d40f3`. The default catalog also retains
  three authored checks. This does not assert support for all community formats.
- Nine additional top-level tests passed: fourteen packages loaded through the
  actual Agent tool with resolved script paths and call counts; signing-key
  migration/recreation retained an existing token and authenticated proxy;
  invalid keys/browsable key paths rejected startup; and six proxy gateway tests
  covered concurrent exits, recording parity, failure pause/fallback, redaction,
  SOCKS5 and established-tunnel cancellation. No test skipped.

The extra evidence archive `content2-evidence.tar.gz` is 4,627 bytes with SHA-256
`6733b67bd75518535903af292554fe9e688fd96c7b9fdb352288c2394bc001f8`.
It contains test logs and hashes, excludes credentials, and was downloaded and
verified locally. After completion all validation containers were stopped;
volumes and evidence remain. The original `artex` service was active and its
health endpoint reported `ok: true`.

Windows acceptance at the same revision also passed actual Agent-assembled
Playwright MCP/Chromium navigations for two distinct task proxy exits. Linux
Chromium has not been run. The combined Windows suite initially had one failure
because the Windows `python3` app alias returned 9009; explicitly selecting the
installed Python 3.11 executable made that observer CLI test pass. The other
23 top-level tests had passed. TypeScript and the 36-page static production
build passed. The newly added session page has HTTP and build coverage;
interactive browser acceptance was rejected by automatic approval review before
startup, with reason `blocked by policy`, and remains unrun.

Subsequent review fixes at `6c4aa76` retain bigint task IDs without a float64
conversion, finish cleanup after an interrupted key migration, reject conflicting
legacy keys, and refresh open session details with polling. Eight focused HTTP
tests and five startup subcases passed against independent Windows PostgreSQL;
TypeScript and Biome passed. These fixes are later than the Linux artifacts
above and are not represented as part of their Linux evidence.

## Linux resource scope acceptance

The opt-in authenticated HTTP test `TestLinuxMetricsMatchRuntimeScope` ran as an
ordinary Linux process, then inside a container launched with `--network none
--memory 128m --cpus 0.5`. It uses no database or model. Both runs passed on
2026-11-11. The first response left CPU percent unset; a later response after a
bounded local CPU/memory workload reported a measured interval and positive CPU
usage. Process scope reported two cores and no host memory limit; container scope
reported cgroup v2, exactly 0.5 cores and 134,217,728 bytes, matching the separate
Docker limits. Actual later samples were:

| Scope | CPU percent | Window seconds | Memory bytes | Memory limit bytes |
| --- | --- | --- | --- | --- |
| process | 50.3864 | 0.6174 | 56,606,720 | null |
| container | 94.6867 | 0.6849 | 35,504,128 | 134,217,728 |

These are scope and configured-denominator checks under a local workload,
not precision benchmarking or the complete application-container acceptance.
Raw logs remain `metrics-process.log` and `metrics-container.log` in the isolated
validation directory. The disposable metrics container exited and was removed.

## Sixteen workflow packages and execution evidence

On 2026-11-11, content source `e7cddcc` passed all 31 actual Python CLI tests and
all 16 authored package manifests on Ubuntu 22.04/Python 3.10.12. The batch adds
Python AST review and ELF/PE structure inspection to the earlier fourteen
workflows. The installed `/bin/true` ELF file was parsed as saved bytes. Tests
also exercised malformed/truncated files, input limits, deterministic directory
identity, output limits, forged manifests and standard-library import shadowing.
The same 31 CLI tests passed with Windows Python 3.11.

The fixed runner verifies instructions and script hashes, executes a private copy
of the verified bytes with Python isolated mode, and emits explicit input and
execution evidence. It has no arbitrary command argument. Reports remain
`operator_reported`, separately from actual Agent Skill body-load statistics.
See `SKILL-RUN-EVIDENCE.md` and the category/limit matrix in `skills/CONTENT.md`.

After independent review, source `8039cb6` passed six top-level authenticated HTTP
tests against a new `skills_final_acceptance` database in the existing independent
Compose PostgreSQL project, with zero failures and zero skips:

- Category/body/binding preservation and actual load counters.
- All sixteen packages loaded through the assembled Agent Skill tool, with
  resolved resource paths and real usage increments.
- Recorded task/intent context and existing authenticated history details.
- Immutable execution reports, authentication, conflict handling, output omission
  from lists, and lossless roundtrip of two 64 KiB streams containing NUL/control
  characters.
- Historical reports retained after task deletion and HTTP application
  reconstruction; original requests remain retryable.
- Actual fixed workflow CLI execution and authenticated HTTP report submission.

The immutable-report test also covers package modification and manifest removal:
an identical accepted request still returns its historical record, changed
content under the same client ID conflicts, and a new ID must still pass current
package validation. This is the P2 review fix at `2ce0588`, merged into `8039cb6`.

The HTTP tests ran as a bounded test executable on the Linux host against the
independent Compose database; no application service or public port was deployed.
The content archive SHA-256 is
`9ef252564affa318816c555d4ed33d5a89732bde54feaa0314ed29864f49a478`.
The final Linux HTTP test executable SHA-256 is
`f0fde8286a9436db011957add8a469a0884b9c3d4b29fb8baf301ce11e99d114`.
The 2,926-byte collected log archive `skills-final-evidence.tar.gz` has SHA-256
`ab46e4e22bf230ba7d10a5b27c52c782883e9a43f427442c98d80ecfe346063e`;
it was downloaded and verified locally. Raw CLI, manifest and HTTP logs remain
in `/opt/artex-cve-validation`. The content manifest in the evidence records its
content revision separately from the later HTTP source revision.

The independent PostgreSQL container was stopped after testing. Its data and
evidence remain, and the pre-existing ARTEX service stayed active with health
`ok: true`. TypeScript and the 36-page static production build passed after the
skill evidence panel was integrated; no interactive browser acceptance of that
new panel is claimed. These results complete #7's original criteria for the
delivered catalog, while complete screenshot parity, Linux Chromium, whole-image
deployment, C2/WebShell control and the intranet worker remain parent-spec gaps.
The Linux Chromium gap was subsequently exercised as recorded below.

## Actual Linux Agent browser egress

`TestProxyPoolRealAgentBrowserKeepsTaskExitsSeparate` passed on Ubuntu 22.04 at
source `8039cb6` in 6.30 seconds, with no skip. It invoked the actual
Agent-assembled Playwright MCP `browser_navigate` tool for two tasks assigned
different proxies. Each navigation returned its assigned proxy's marker with
an observed upstream hit, despite inherited `NO_PROXY=*`; persisted browser
arguments were unchanged. Targets and proxies were local test HTTP servers.

The independently prepared runtime used Node 24.22.1, Playwright MCP 0.0.85,
Playwright Core 1.66.0-alpha-2026-11-09 and Chrome for Testing 158.0.8127.18.
Node's official SHASUMS256 entry verified its archive. Chrome came from the
Playwright CDN path selected by the pinned package. Hashes are:

| Artifact | SHA-256 |
| --- | --- |
| Node Linux x64 archive | `6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6` |
| Chrome Linux x64 ZIP | `c6cb06e1574ac2f6c5c38e31551157fbcaa67e6366c89974084553c5a5772592` |
| Locked MCP dependency archive | `1e1ed7fe7a071961d07e1bbe117ce673c8b30002d4115765e84607daea9fc36d` |
| Collected browser logs and manifest | `f2d5406038bfdb65976f737c8cc488c741be2abd502fc0118d127c2ed810ba49` |

The 6,346-byte evidence archive was downloaded and verified locally. Its manifest
also records the exact downloaded Ubuntu library packages. Missing libraries were
downloaded and extracted into the private validation directory, selected through
the test process's `LD_LIBRARY_PATH`; no packages were installed into the server
and no existing service configuration was modified.

The independent `browser_final_acceptance` PostgreSQL database was used, then its
Compose container was stopped. No validation browser or Node process remained;
the original ARTEX service was active and its health endpoint returned `ok: true`.
This completes Linux browser-path acceptance for #8, but does not supply
transparent raw TCP/UDP/DNS routing, constrain programs that ignore proxies, or
certify full application deployment. #8 remains open for that broader requirement.
