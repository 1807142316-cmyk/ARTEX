# Authored workflow packages

This release adds fourteen original workflows. Each contains executable Python
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

The added commands have bounded file and item inputs, structured JSON CLI
errors, and no network or database writes. The knowledge precheck requires a
source URL and version even though the import API permits these to be empty;
passing this check does not attest to licensing, correctness or verification.
HAR and scope outputs retain URL paths, which can still contain business data.
Review those paths before sharing evidence. Each package documents its contract
and workflow in `SKILL.md`.

Category mapping follows the implemented workflow rather than invented screenshot
names: HTTP evidence/configuration, TLS configuration, host configuration,
container configuration, cloud configuration, dependency/supply-chain review,
asset organization, knowledge organization and reporting. The recorded screenshot
evidence confirms a skill tree and category labels, but does not preserve a
complete category vocabulary or the original skill bodies. These mappings do not
certify parity with unknown categories. Existing evidence/knowledge/reporting
packages remain separate; the new audit workflows address different input formats
and decisions and do not repackage them to increase counts.

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
for invalid input. The result files remain task evidence.

These packages cover fourteen workflows. They do not claim to reproduce every
directory or capability visible in the target screenshots. Existing `api-recon`,
`playwright-cli`, and `scopesentry` content remains unchanged. On 2026-11-11,
all seventeen CLI tests and fourteen authored package manifests passed on Ubuntu
22.04 with Python 3.10.12. The actual Agent loading/resource resolution and call
count test also passed on Linux against an independent Compose PostgreSQL
database. See `docs/screenshot-parity-linux-validation.md`. These checks do not
certify the complete platform image, Agent browser or unknown screenshot
categories. Repeatable commands are above and in
`server/skill_catalog_http_test.go`.
