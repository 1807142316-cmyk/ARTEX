"""Build or verify the authored skill-content manifest without network access."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "saved-header-review": ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
    "evidence-inventory": ["https://docs.python.org/3/library/hashlib.html"],
    "cve-record-review": ["https://github.com/CVEProject/cvelistV5", "https://github.com/CVEProject/cve-schema"],
}


def manifest():
    packages = []
    for name, sources in sorted(PACKAGES.items()):
        files = []
        for relative in ("SKILL.md", "scripts/run.py"):
            content = (ROOT / "skills" / name / relative).read_bytes()
            files.append({"path": relative, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        packages.append({"name": name, "version": "artex-authored-1", "license": "AGPL-3.0-only", "authored_date": "2026-11-11", "source_kind": "original-workflow-and-script", "reference_urls": sources, "files": files})
    return {"format_version": 1, "packages": packages}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "skills" / "content-manifest.json"
    expected = manifest()
    if args.check:
        if json.loads(path.read_text(encoding="utf-8")) != expected:
            parser.exit(1, "skill manifest differs; run python3 scripts/skill_manifest.py\n")
        print("3 authored skill packages match their manifest")
    else:
        path.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
