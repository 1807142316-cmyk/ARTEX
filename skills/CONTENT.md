# Authored workflow packages

This release adds three original workflows: saved HTTP-header evidence review,
evidence-file inventory, and CVE record review. Each contains executable Python
standard-library code, input/output contracts, error handling, dependency notes,
and source references. `content-manifest.json` records exact SHA-256 digests and
the authored content version. It does not assert that an upstream document was
downloaded or copied.

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

These packages cover three workflows. They do not claim to reproduce every
directory or capability visible in the target screenshots. Existing `api-recon`,
`playwright-cli`, and `scopesentry` content remains unchanged. Linux runtime
execution remains part of release acceptance; local Windows Python checks alone
do not certify that environment.
