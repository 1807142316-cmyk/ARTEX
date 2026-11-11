# Authored workflow packages

This release adds sixteen original workflows. Each contains executable Python
standard-library code, input/output contracts, error handling, dependency notes,
and source references. `content-manifest.json` records exact SHA-256 digests and
the authored content version. It does not assert that an upstream document was
downloaded or copied.

| Package | Input and distinct result |
| --- | --- |
| `saved-header-review` | Saved response headers → applicability, missing controls and evidence hash |
| `evidence-inventory` | Evidence directory → file sizes and SHA-256 inventory without file contents |
| `cve-record-review` | CVE JSON → record state, affected conditions and source-container provenance |
| `scope-asset-inventory` | URL/IP/CIDR list → canonical, deduplicated scope without network probing or CIDR expansion |
| `har-api-inventory` | Saved HAR → method/path/status frequency without credentials, query values or bodies |
| `knowledge-package-check` | Knowledge import JSON → schema/provenance errors, normalized hashes and duplicate-body groups without importing |
| `report-evidence-index` | Task/finding/evidence export → recorded statuses, missing references and stale report versions without inferring confirmation |
| `tls-observation-review` | Saved TLS session and certificate metadata → protocol, expiry and supplied verification observations |
| `cors-policy-review` | Saved Origin/credential mode/response headers → per-response CORS origin policy, credential conflict and Vary observations |
| `cookie-attribute-review` | Individual saved Set-Cookie fields → flag/prefix/duplicate-attribute observations without names or values |
| `sshd-effective-config-review` | Saved `sshd -T` output → selected effective authentication, forwarding and logging controls, with missing fields unknown |
| `container-inspect-review` | Saved Docker container inspect → isolation, namespaces, added capabilities and engine-socket observations without environment or mount paths |
| `iam-policy-review` | Saved AWS IAM policy → Allow breadth, Deny/condition visibility and complement forms requiring manual analysis |
| `sbom-inventory-review` | CycloneDX/SPDX JSON → component/version/identifier/license/hash declaration quality without vulnerability matching |
| `python-source-review` | Saved Python source → AST definitions, imports, calls and literal review sites without executing the source |
| `binary-format-inspection` | Saved ELF/PE file → bounded headers and sections, architecture codes and declared entry metadata without loading the file |

The added commands have bounded file and item inputs, structured JSON CLI
errors, and no network or database writes. The knowledge precheck requires a
source URL and version even though the import API permits these to be empty;
passing this check does not attest to licensing, correctness or verification.
HAR and scope outputs retain URL paths, which can still contain business data.
Review those paths before sharing evidence. Each package documents its contract
and workflow in `SKILL.md`.

The implementation plan names the following broad categories. Each has substantive
content; the table describes the actual workflow and the boundary of its result.
These mappings do not recover the target project's private skill bodies or its
complete directory vocabulary.

| Planned category | Delivered packages and observable result | Coverage limit |
| --- | --- | --- |
| Web | `saved-header-review`, `har-api-inventory`, `tls-observation-review`, `cors-policy-review`, `cookie-attribute-review` | Saved HTTP/TLS evidence and configuration; no active exploitation |
| Asset reconnaissance | `scope-asset-inventory`, `har-api-inventory` | Canonical scope and observed API inventory; no network probing or CIDR expansion |
| Intranet / host configuration | `sshd-effective-config-review` | Saved `sshd -T` authentication, forwarding and logging configuration; no live session operation or lateral execution |
| Cloud / containers | `iam-policy-review`, `container-inspect-review`, `sbom-inventory-review` | Saved IAM, container and dependency declarations; no effective-access proof, cloud changes or takeover |
| Reverse engineering | `binary-format-inspection` | ELF/PE header and section inventory; imports, disassembly, unpacking and execution remain outside its scope |
| Code auditing | `python-source-review` | Literal Python AST review locations; no alias resolution, data-flow analysis or vulnerability verdict |
| Evidence / knowledge / reporting | `evidence-inventory`, `cve-record-review`, `knowledge-package-check`, `report-evidence-index` | Evidence hashes, source metadata and consistency observations; no automatic verification or publication |

The scripts, individual CLI contracts and failure cases are exercised by the
tests below. Existing evidence/knowledge/reporting packages remain separate;
these workflows address distinct input formats and decisions rather than
repackaging one workflow to increase counts. The broad-category coverage does
not establish complete screenshot parity for the parent specification.

This content batch covers offline evidence and configuration review. Exploit
delivery, credential harvesting, security evasion, takeover and lateral execution
workflows are not included, and the category counts must not imply otherwise.
The scripts do not change services, cloud policies or containers. Each reports
specific scope limits; an observation is not a verified vulnerability or full
configuration compliance result.

Run the commands from the repository root:

```sh
python3 -m unittest discover -s tests/skills -p 'test_*.py' -v
python3 scripts/skill_manifest.py --check
```

Install by deploying the repository's `skills/` directory as usual, or upload a
ZIP containing a package directory in the Skill page. Existing Agent visibility
bindings control which Agent can load a package. The new packages do not modify
those bindings. A successful Skill load records an invocation in the existing
ledger; it does not certify that a script completed or a finding was verified.
The workflow scripts return JSON on stdout, JSON errors on stderr and exit code 2
for invalid input. The result files remain task evidence. The separate
[fixed workflow runner](../SKILL-RUN-EVIDENCE.md) verifies package hashes and
records input digests, stdout, stderr, exit codes and outcomes. Authenticated
reports appear in the skill detail page as operator-reported execution evidence;
they do not alter body-load counts or claim independent verification.

These packages cover sixteen workflows. They do not claim to reproduce every
directory or capability visible in the target screenshots. Existing `api-recon`,
`playwright-cli`, and `scopesentry` content remains unchanged. On 2026-11-11,
all 31 CLI tests and sixteen authored package manifests passed on Ubuntu 22.04
with Python 3.10.12 at source `e7cddcc`. Windows Python 3.11 also passed all 31
tests. Linux HTTP/Agent evidence is recorded separately in
`docs/screenshot-parity-linux-validation.md`; earlier fourteen-package results
must not be used as sixteen-package acceptance. These checks do not certify the
complete platform image, Agent browser or unknown screenshot categories.
Repeatable commands are above and in `server/skill_catalog_http_test.go`.
