# Template execution

The template catalog runs the supported Nuclei HTTP subset using Nuclei 3.4.10.
`Dockerfile.source` installs its fixed Linux release with SHA-256 verification
and preserves the engine's MIT license. Binary installations may set
`ARTEX_NUCLEI_PATH` to the corresponding executable. The application checks the
exact engine version and reports an unavailable or incompatible installation.
Release URLs and hashes are in `content-manifests/nuclei-engine.json`.

Three project-authored informational checks are included: robots.txt,
RFC 9116 security contact, and the conventional web manifest path. Their
standards references, source version, license and content hashes are retained
in the catalog. An HTTP status observation alone does not establish resource
validity or a vulnerability. Imported templates must be one YAML document,
use static GET paths below BaseURL, and use status-code matchers. This subset
does not accept raw requests, JavaScript, code, headless execution, fuzzing,
payloads, external callbacks, redirects or arbitrary CLI arguments. The full
community template collection is not part of this content bundle.

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

Verification on Windows used the downloaded and SHA-256 verified real engine,
authenticated HTTP handlers and a real PostgreSQL database. It covered one
actual outgoing GET, matched and unmatched responses, connection failure,
pending findings, immutable history, restricted history-list evidence,
authentication, incompatible YAML, and unavailable engine states. Linux
container execution remains part of deployment acceptance.
