"""Build or verify the authored skill-content manifest without network access."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "binary-format-inspection": ["https://gabi.xinuos.com/elf/02-eheader.html", "https://gabi.xinuos.com/elf/03-sheader.html", "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"],
    "saved-header-review": ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
    "evidence-inventory": ["https://docs.python.org/3/library/hashlib.html"],
    "cve-record-review": ["https://github.com/CVEProject/cvelistV5", "https://github.com/CVEProject/cve-schema"],
    "scope-asset-inventory": ["https://docs.python.org/3/library/ipaddress.html", "https://docs.python.org/3/library/urllib.parse.html"],
    "har-api-inventory": ["https://www.softwareishard.com/blog/har-12-spec/"],
    "knowledge-package-check": ["https://docs.python.org/3/library/hashlib.html"],
    "report-evidence-index": ["https://docs.python.org/3/library/hashlib.html"],
    "tls-observation-review": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html", "https://docs.python.org/3/library/ssl.html"],
    "cors-policy-review": ["https://fetch.spec.whatwg.org/#http-cors-protocol"],
    "cookie-attribute-review": ["https://www.rfc-editor.org/rfc/rfc6265", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"],
    "sshd-effective-config-review": ["https://man.openbsd.org/sshd.8", "https://man.openbsd.org/sshd_config.5"],
    "container-inspect-review": ["https://docs.docker.com/reference/cli/docker/inspect/", "https://docs.docker.com/engine/security/"],
    "iam-policy-review": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"],
    "sbom-inventory-review": ["https://cyclonedx.org/docs/1.6/json/", "https://spdx.github.io/spdx-spec/v2.3/package-information/"],
    "python-source-review": ["https://docs.python.org/3/library/ast.html", "https://docs.python.org/3/library/subprocess.html#security-considerations"],
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
        print(f"{len(expected['packages'])} authored skill packages match their manifest")
    else:
        path.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
