# Authored workflow packages

This release adds seven original workflows. Each contains executable Python
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

The last four commands have bounded file and item inputs, structured JSON CLI
errors, and no network or database writes. The knowledge precheck requires a
source URL and version even though the import API permits these to be empty;
passing this check does not attest to licensing, correctness or verification.
HAR and scope outputs retain URL paths, which can still contain business data.
Review those paths before sharing evidence. Each package documents its contract
and workflow in `SKILL.md`.

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

These packages cover seven workflows. They do not claim to reproduce every
directory or capability visible in the target screenshots. Existing `api-recon`,
`playwright-cli`, and `scopesentry` content remains unchanged. On 2026-11-11,
nine CLI tests and all seven authored package manifests passed on Ubuntu 22.04
with Python 3.10.12. See `docs/screenshot-parity-linux-validation.md`. This does
not certify the complete platform container, Agent browser or remaining content.
