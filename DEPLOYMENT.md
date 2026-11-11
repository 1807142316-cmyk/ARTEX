# Screenshot parity integration deployment

Build the integration branch's source instead of using the published upstream image:

```sh
docker compose -f docker-compose.yml -f compose.source.yml build artex
docker compose -f docker-compose.yml -f compose.source.yml up -d
```

The existing `.env` supplies the PostgreSQL password and model configuration.
The source build compiles the static Next.js application, embeds it in the Go
binary, and includes the `cve-import` command. Node, Chromium, and the existing
tool dependencies are installed in the runtime image. PostgreSQL persists in
the existing named volume; application data and skills keep their existing
bind mounts. A local `content/` directory mounts read-only at `/app/content`.

## Offline CVE baseline

The local delivery content directory contains the official CVE release archive
and `content/cve/manifest.json`, which records its source URL, release and SHA-256.
The same manifest is tracked at `content-manifests/cve-baseline.json`, so a fresh
checkout retains the download and integrity information without the large ZIP.
It is a data artifact excluded from Git and the Docker build context. Preserve
this directory with the deployment or download the release URL recorded in the
manifest. CVE content follows the CVE Program terms linked in that manifest.

Import the archive into the deployed database:

```sh
docker compose -f docker-compose.yml -f compose.source.yml exec artex \
  /app/cve-import -archive /app/content/cve/baseline.zip \
  -version cve_2026-11-10_1900Z
```

For binary deployments, build and run the same importer with `ARTEX_PG_DSN`
pointing to the application's PostgreSQL database:

```sh
go build -o cve-import ./cmd/cve-import
./cve-import -archive content/cve/baseline.zip -version cve_2026-11-10_1900Z
```

Imports commit batches of 500 records. An interrupted import leaves committed
records queryable. Re-run the same archive to finish; repeated records are
deduplicated by CVE ID and hash. The CLI re-reads an interrupted archive rather
than maintaining a byte-offset cursor. Importing a baseline does not disable
the application's automatic update service.

Run the opt-in full-corpus HTTP acceptance check against a dedicated database
after the official import finishes, and again against its restored copy:

```sh
export ARTEX_PG_DSN='postgres://artex@127.0.0.1:5432/artex_cve_acceptance?sslmode=disable'
ARTEX_CVE_ACCEPTANCE_COUNT=421793 go test ./server \
  -run '^TestCVEFullCorpusAuthenticatedHTTPAcceptance$' -count=1 -v
```

Use the actual database DSN and the expected count of the verified source
snapshot. This check is skipped unless the count is positive. It uses the real
authenticated HTTP handler and PostgreSQL corpus, checks state/year aggregates,
the original Log4Shell record and source version, and product/component/description
queries. It does not import records, clear tables, or change synchronization
settings. Its canceled service context prevents background synchronization or
task execution; normal application schema/seed initialization still runs. Use an
isolated database without model configuration or active tasks. The command is a
CVE subset check; it does not certify Compose deployment or platform acceptance.
Execution results must be recorded separately after the check actually runs.

## Backup and recovery

Before upgrading, stop task admission and wait for in-flight work to settle.
Back up PostgreSQL using `pg_dump` from the PostgreSQL container, then preserve
the `data/`, `skills/` and `content/` directories together with `.env` and any
external configuration. The database includes synchronization state, knowledge
versions, task history and template metadata; the filesystem contains source
material, keys and task artifacts. Keep these backups together and restrict
access to configuration and keys.

Restore into a separate PostgreSQL database first with `pg_restore`, restore the
directories, then start the same application revision against that database.
Check local CVE search, knowledge state, task history and skill availability
before switching traffic. Application rollback retains additive database
structures. Restore a database backup if schema compatibility is uncertain.

## Verification status

The implementation has been tested on Windows with a real isolated PostgreSQL
17 instance and authenticated HTTP requests. Linux binaries can be cross-built.
The full 421,793-record database was dumped, restored into a separate database,
and reopened with this application; authenticated statistics and a retained CVE
search succeeded. The local backup is `content/cve/corpus.pgcustom`.
This workspace has no Docker daemon or configured WSL distribution; Compose
cold start, Linux metric comparison, and backup restoration on Linux still need
runtime verification. A successful cross-build does not certify those checks.

## Local Linux runtime probe (2026-11-11)

Actual Linux Compose acceptance could not run on this Windows host. Docker,
Podman, nerdctl, containerd and QEMU executables are absent; no container services,
container named pipes or configured remote runtime environment/context were
found. `wsl --list --verbose` reports WSL is not installed. Existing VMware
Workstation reports zero running guests and an empty guest inventory.

A disposable Alpine Linux 3.22.2 virtual ISO guest was then prepared under the
system temporary directory, limited to two virtual CPUs and 4 GiB memory, using
the installed VMware CLI and existing NAT network. `vmrun ... start ... nogui`
failed before guest boot with `VMware Workstation unrecoverable error (vmx)` and
`Exception 0xc0000005 (access violation)`. The local diagnostic log is
`%TEMP%/artex-parity-linux-vm/vmware.log`. No OS features, services or host network
configuration were installed or changed. No running guest remains; Workstation does not support the unregister CLI operation. The temporary guest files are outside the repository.

The pinned runtime npm releases `@playwright/mcp@0.0.85`,
`@playwright/cli@0.1.24` and `playwright@1.65.0` exist in the registry. This checks
package availability only; it does not certify Linux installation, Chromium
startup, Compose startup/upgrade/restore, Linux metrics or Linux skill execution.
Issue #5's Linux deployment acceptance therefore remains open. Run the documented
Compose flow on an existing Linux Docker host before closing that acceptance.
