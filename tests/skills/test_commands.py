import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2] / "skills"


class SkillCommandTests(unittest.TestCase):
    def run_skill(self, skill, *args):
        return subprocess.run([sys.executable, str(ROOT / skill / "scripts" / "run.py"), *map(str, args)], capture_output=True, text=True, encoding="utf-8")

    def test_saved_headers_report_missing_controls_without_cookie_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "headers.json"
            cookie_value = "session=" + "local-test-value"
            path.write_text(json.dumps({"url": "https://service.test/", "headers": {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "Set-Cookie": cookie_value + "; Secure; HttpOnly"}}), encoding="utf-8")
            result = self.run_skill("saved-header-review", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["missing"], ["strict-transport-security", "referrer-policy"])
            self.assertNotIn("local-test-value", result.stdout)
            self.assertEqual(len(report["evidence_sha256"]), 64)
            path.write_text('{"url":"ftp://bad","headers":{}}', encoding="utf-8")
            self.assertEqual(self.run_skill("saved-header-review", path).returncode, 2)

    def test_evidence_inventory_hashes_files_without_embedding_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.txt"
            path.write_bytes(b"hello")
            result = self.run_skill("evidence-inventory", directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["files"], [{"path": "evidence.txt", "bytes": 5, "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}])
            self.assertNotIn("hello", result.stdout)
            self.assertEqual(self.run_skill("evidence-inventory", path).returncode, 2)

    def test_cve_review_retains_container_provenance_and_rejected_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cve.json"
            path.write_text(json.dumps({"cveMetadata": {"cveId": "CVE-2099-12345", "state": "REJECTED"}, "dataVersion": "5.1", "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Withdrawn record"}], "references": [{"url": "https://vendor.test/advisory"}]}, "adp": [{"references": [{"url": "https://program.test/record"}]}]}}), encoding="utf-8")
            result = self.run_skill("cve-record-review", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["records"][0]["state"], "REJECTED")
            self.assertEqual(report["records"][0]["references"], [{"container": "cna", "url": "https://vendor.test/advisory"}, {"container": "adp:0", "url": "https://program.test/record"}])
            self.assertFalse(report["records"][0]["confirms_vulnerability"])
            path.write_text('{"cveMetadata":{"cveId":"broken","state":"PUBLISHED"}}', encoding="utf-8")
            self.assertEqual(self.run_skill("cve-record-review", path).returncode, 2)


if __name__ == "__main__":
    unittest.main()
