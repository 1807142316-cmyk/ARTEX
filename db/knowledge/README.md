# Authored knowledge baseline

`baseline-v1.json` ships six original ARTEX entries for SQL parameterization,
object authorization, cookie controls, TLS certificates, CVE applicability and
evidence redaction. Each includes applicability, validation, remediation,
acceptance conditions, tool references and a public primary-source URL.

The text is authored for this repository and distributed under its license.
Linked documents inform the guidance; their full text is not redistributed.
`source_version` identifies this pack, not a claim that a mutable source page
was pinned or copied.

Startup adds missing entries as **unverified, unreviewed, unpublished drafts**.
It preserves existing codes and never manufactures validation records. To use an
entry in Agent retrieval, check applicability, record real verification evidence,
approve its redacted content and publish it from the knowledge page.

The page's **导入 JSON** action accepts this array. The HTTP equivalent is
`POST /api/knowledge/import` with `{"items":[...]}`. Batches accept 1–100 entries
and up to 256 KiB of request data. Identical codes/content are skipped; conflicting
content returns 409 and rolls back the batch. Edit an existing entry explicitly
to create a new immutable version.
