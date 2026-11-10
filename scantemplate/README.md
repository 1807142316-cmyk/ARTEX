# Scan-template catalog

The catalog accepts a restricted HTTP GET template format with static BaseURL paths
and status-code matchers. Imports retain the content, SHA-256 digest, source URL,
source version, license, metadata, and prior content versions. Only the current
version appears in catalog search. Validation checks structure and compatibility;
it does not establish whether an endpoint is vulnerable.

The project includes an authored `/robots.txt` availability check. It is embedded
from `db/scan-templates/artex-robots-index.yaml` and seeded only if its ID has never
been imported. Catalog endpoints require the normal application authentication.

This implements the catalog portion of issue #6. The following acceptance criteria
remain open: compatibility with the full Nuclei template format and engine, engine
execution, candidate findings and execution evidence, and retrieval of historical
versions and execution records. This package does not execute templates.

Run parser checks with `go test ./scantemplate`. Run the authenticated HTTP and
PostgreSQL check with `go test -v ./server -run ScanTemplate -count=1` after setting
`ARTEX_PG_DSN` to a dedicated test database. Without PostgreSQL configuration the
integration check is skipped; a configured connection failure is a test failure.
