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
This workspace has no Docker daemon or configured WSL distribution; Compose
cold start, Linux metric comparison, and backup restoration on Linux still need
runtime verification. A successful cross-build does not certify those checks.
