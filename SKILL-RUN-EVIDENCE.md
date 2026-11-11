# Offline workflow execution evidence

`scripts/skills/run_workflow.py` runs one fixed, authored offline workflow with a
saved local input. It emits an execution report and can submit that report to the
authenticated ARTEX API. It accepts only the fifteen named packages in its catalog;
it has no arbitrary command or script argument. The application stores reports and
does not execute uploaded skill code.

Use Python 3.10 or newer with the repository's `skills/` and distributed content
manifest available. No Python third-party dependencies are required. Read the
selected package's `SKILL.md` for its input schema and interpretation boundaries.

```bash
python3 scripts/skills/run_workflow.py saved-header-review /path/to/headers.json
```

To submit directly, put the normal authenticated application JWT in the
`ARTEX_SKILL_RUN_TOKEN` environment variable through your secret manager or local
shell. The runner does not print the token. Supply the application origin and, if
needed, an existing task identifier:

```bash
python3 scripts/skills/run_workflow.py saved-header-review /path/to/headers.json \
  --artex-url https://artex.internal --task-id 12
```

Submission requires HTTPS, with HTTP allowed for loopback development. Redirects
are rejected. `--skills-dir` can point to a local content directory, but expected
package hashes still come from the manifest distributed beside the runner; an
alternative directory cannot supply its own expected hashes. Each run verifies
both `SKILL.md` and `scripts/run.py` before starting the fixed script.

The report contains a unique client run ID, package version and hashes, input
basename and SHA-256, byte count, timestamps, exit code, outcome, and bounded stdout
and stderr. Directory identity hashes sorted relative file paths, sizes and file
digests; symlinks are skipped. Inputs are hashed before and after execution. A
change produces `input_changed`, including deletion or unreadability after the
run. Input hashing permits at most 1 GiB and 10,000 files.

The script timeout defaults to 60 seconds and is configurable from 1 to 120 seconds
with `--timeout`. Each output stream is limited to 64 KiB. An excess terminates
the workflow and produces `output_limit`; a timeout produces `timeout`. Exit 0
means the workflow succeeded; exit 1 means a recorded workflow failure; exit 2
means runner validation or submission failed. Workflow success describes execution,
not a security finding or an independent verification decision.

The complete report is printed to stdout before optional submission. A transport
failure leaves it available for retry through `POST /api/skill-runs` with the same
JSON and authenticated JWT. Successful submission prints the stored report ID to
stderr. Reports must match the currently installed content manifest when submitted.
The server labels them `operator_reported`: matching hashes identify the reported
package, but do not attest that a remote operator executed it honestly.

Reports are immutable. Retrying the same client ID and identical content returns
the stored record; changed content with that ID returns conflict. A linked task
must exist at first submission. Deleting that task clears its active reference
while preserving the historical report, and an identical retry still succeeds.
Content versions and hashes in existing reports remain historical after a package
update; browsing does not revalidate them against the current package.

`GET /api/skill-runs?skill=<name>&page=1&limit=20` returns paginated summaries and
omits stdout and stderr. `GET /api/skill-runs/<id>` returns the full stored report.
All routes use existing application authentication. Saved output may contain
sensitive material present in the chosen input, so inspect it before submitting.
Full output is available only in the authenticated detail response and is not
copied into ordinary list responses or application logs.

Skill正文加载记录 and offline execution reports are separate. Running this CLI does
not increment the Agent's `Skill()` load counter, and a skill load does not imply
that its local script ran. The skills page displays the two histories separately.
