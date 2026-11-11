# Template execution

The template catalog runs the supported Nuclei HTTP subset using Nuclei 3.4.10.
`Dockerfile.source` installs its fixed Linux release with SHA-256 verification
and preserves the engine's MIT license. Binary installations may set
`ARTEX_NUCLEI_PATH` to the corresponding executable. The application checks the
exact engine version and reports an unavailable or incompatible installation.
Release URLs and hashes are in `content-manifests/nuclei-engine.json`.

The catalog includes three project-authored informational checks (robots.txt,
RFC 9116 security contact, and the conventional web manifest path) and eleven
unchanged official ProjectDiscovery HTTP technology/configuration templates.
The official snapshot identifies Apache, nginx, Angular, Amazon EC2 server headers,
HTTP Basic authentication and common default pages. Its exact source commit,
original upstream paths, MIT license, acquisition time and per-file SHA-256
hashes are recorded in `scantemplate/bundles/official/manifest.json`; the
original license is distributed beside the template files. Each catalog
entry retains its own source URL, version, license and content hash. The
upstream `metadata.verified` field describes upstream template metadata; it
does not mark a local finding as independently verified.

Imported templates must be one YAML document, use static GET paths at or below
BaseURL, and use status, word or regular-expression matchers. Body/header/all
parts, and/or conditions, negative matching, case-insensitive word matching,
regex extraction groups and key-value header extraction are accepted. The
application validates this syntax before invoking the real engine. This subset
does not accept raw requests, JavaScript, code, headless execution, fuzzing,
payloads, external callbacks, redirects or arbitrary CLI arguments. The full
community template collection is not part of this content bundle. A matching
server banner, default page or status alone does not establish a vulnerability.

Startup validates the embedded official bundle and seeds only missing template
IDs, preserving locally edited active revisions. The offline importer validates
all file hashes, the license hash and every template before opening the database,
then imports the entire batch in one transaction. An invalid bundle leaves the
existing usable catalog intact. To explicitly restore the embedded official
snapshot after setting the usual PostgreSQL connection variables, run:

```sh
go run ./cmd/template-import
# Source-built containers include the same command and embedded content.
docker compose exec artex /app/template-import
```

`template-import -bundle /path/to/bundle` imports an exported directory with the
same manifest schema. The explicit command activates that snapshot; previous
template versions and execution evidence remain in the database. No network is
needed for either import mode. The application's supported syntax and engine
version apply to external bundles as well.

The page supports target entry, execution of an exact content version,
paginated history, and authenticated detail views of request/response evidence.
Runs are limited to two concurrent operations per application process, two
minutes, sixteen paths and two requests per second. Responses are capped at
256 KiB. Automatic engine/template updates, external callbacks and redirect
following are disabled. Existing model/search proxy settings are not passed
to the scanner.

Execution continues independently of the browser request. Each run stores the
template body, content hash, provenance, engine version, target, timestamps,
optional existing task association, result and error in PostgreSQL. Matched
findings inherit the same task association. List responses omit raw request/response
content. Detail and finding views require application authentication and may
contain target-specific response data. A match creates a pending finding
with its request/response evidence and original template severity in the
summary. Informational/unknown observations use the existing finding model's
lowest `low` severity; they remain pending and require an independent review.
Template updates cannot overwrite execution snapshots. Uncompleted runs older
than five minutes are displayed as interrupted after application restart;
the scanner does not automatically repeat them.

Pausing, terminating or deleting an associated task cancels its active template
runs. Paused and terminal tasks cannot start a new run; canceled results do not
create candidate findings. Deleting a task preserves the execution snapshot with
an interrupted outcome. While the proxy pool is enabled, a task association is
required, and Nuclei uses that task's gateway rather than a separate direct exit.

Verification on Windows used the downloaded and SHA-256 verified real engine,
authenticated HTTP handlers and a real PostgreSQL database. It covered one
actual outgoing GET, status/header/body and regex/word matched and unmatched
responses, regex and header value extraction, connection failure,
pending findings, immutable history, restricted history-list evidence,
authentication, incompatible YAML, corrupt source/license checksums, failed
updates preserving the catalog, startup preserving local edits, and unavailable
engine states. Linux
container execution remains part of deployment acceptance.
