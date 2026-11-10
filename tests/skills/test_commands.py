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
            path.write_text(json.dumps({"cveMetadata": {"cveId": "CVE-2099-12345", "state": "REJECTED"}, "dataVersion": "5.1", "containers": {"cna": {"affected": [{"vendor": "Acme", "product": "Portal", "platforms": ["linux"], "defaultStatus": "unaffected", "modules": ["payments"]}], "descriptions": [{"lang": "en", "value": "Withdrawn record"}], "references": [{"url": "https://vendor.test/advisory"}]}, "adp": [{"references": [{"url": "https://program.test/record"}]}]}}), encoding="utf-8")
            result = self.run_skill("cve-record-review", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["records"][0]["state"], "REJECTED")
            self.assertEqual(report["records"][0]["references"], [{"container": "cna", "url": "https://vendor.test/advisory"}, {"container": "adp:0", "url": "https://program.test/record"}])
            self.assertEqual(report["records"][0]["affected"], [{"container": "cna", "vendor": "Acme", "product": "Portal", "platforms": ["linux"], "defaultStatus": "unaffected", "modules": ["payments"]}])
            self.assertFalse(report["records"][0]["confirms_vulnerability"])
            path.write_text('{"cveMetadata":{"cveId":"broken","state":"PUBLISHED"}}', encoding="utf-8")
            self.assertEqual(self.run_skill("cve-record-review", path).returncode, 2)

    def test_scope_inventory_canonicalizes_deduplicates_without_expanding_networks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(json.dumps({"targets": ["HTTPS://Example.TEST:443/api?access_token=private-value#part", "https://example.test/api", "192.0.2.42/24", "192.0.2.0/24", "2001:0db8::1", "https://[2001:db8::1]:443/"]}), encoding="utf-8")
            result = self.run_skill("scope-asset-inventory", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["assets"], [
                {"kind": "cidr", "value": "192.0.2.0/24"},
                {"kind": "ip", "value": "2001:db8::1"},
                {"kind": "url", "value": "https://[2001:db8::1]/"},
                {"kind": "url", "value": "https://example.test/api"},
            ])
            self.assertEqual(report["input_count"], 6)
            self.assertEqual(report["duplicate_count"], 2)
            self.assertEqual(report["urls_with_query_or_fragment_removed"], 1)
            self.assertNotIn("private-value", result.stdout)
            self.assertEqual(len(report["input_sha256"]), 64)
            for target in ("https://user:private-value@example.test", "https://example.test:99999", "https://exa\nmple.test", "ftp://example.test", "192.0.2.1/999"):
                path.write_text(json.dumps({"targets": [target]}), encoding="utf-8")
                invalid = self.run_skill("scope-asset-inventory", path)
                self.assertEqual(invalid.returncode, 2, invalid.stdout)
                self.assertEqual(json.loads(invalid.stderr)["target_index"], 0)
                self.assertNotIn("private-value", invalid.stderr)

    def test_har_inventory_groups_methods_paths_and_statuses_without_sensitive_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.har"
            entries = []
            for url, method, status in (("https://API.test:443/v1/orders?token=query-secret", "GET", 200), ("https://api.test/v1/orders?token=other-secret", "GET", 403), ("https://api.test/v1/orders", "POST", 201), ("https://api.test/v1/orders", "get", 405)):
                entries.append({"request": {"url": url, "method": method, "headers": [{"name": "Authorization", "value": "auth-secret"}], "cookies": [{"name": "session", "value": "cookie-secret"}], "postData": {"text": "body-secret"}}, "response": {"status": status, "content": {"text": "response-secret"}}})
            path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8")
            result = self.run_skill("har-api-inventory", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["endpoints"], [
                {"origin": "https://api.test", "path": "/v1/orders", "method": "GET", "count": 2, "status_counts": {"200": 1, "403": 1}},
                {"origin": "https://api.test", "path": "/v1/orders", "method": "POST", "count": 1, "status_counts": {"201": 1}},
                {"origin": "https://api.test", "path": "/v1/orders", "method": "get", "count": 1, "status_counts": {"405": 1}},
            ])
            self.assertEqual(report["entry_count"], 4)
            self.assertEqual(report["urls_with_query_or_fragment_removed"], 2)
            for secret in ("query-secret", "other-secret", "auth-secret", "cookie-secret", "body-secret", "response-secret", "Authorization"):
                self.assertNotIn(secret, result.stdout + result.stderr)
            for invalid_entry in ({"request": {"url": "https://user:secret@example.test/", "method": "GET"}, "response": {"status": 200}}, {"request": {"url": "https://example.test/", "method": "GET"}, "response": {"status": True}}):
                path.write_text(json.dumps({"log": {"entries": [invalid_entry]}}), encoding="utf-8")
                invalid = self.run_skill("har-api-inventory", path)
                self.assertEqual(invalid.returncode, 2)
                self.assertEqual(json.loads(invalid.stderr)["entry_index"], 0)
                self.assertNotIn("secret", invalid.stderr)

    def test_knowledge_package_checks_provenance_duplicates_and_preserves_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "knowledge.json"
            first = {"code": "  KB   TLS  ", "category": "Configuration", "kind": "review", "tier": "basic", "summary": "TLS configuration review", "body": "Inspect saved certificate evidence.", "source_url": "https://docs.python.org/3/library/ssl.html", "source_version": "3.11"}
            second = dict(first, code="KB-TLS-ALT", summary="Alternative certificate workflow")
            raw = json.dumps({"items": [first, second]}).encode("utf-8")
            path.write_bytes(raw)
            result = self.run_skill("knowledge-package-check", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["valid"])
            self.assertEqual(report["items"][0]["code"], "KB TLS")
            self.assertEqual(report["duplicate_bodies"][0]["item_indices"], [0, 1])
            self.assertEqual(report["items"][0]["content_sha256"], "ffe0c29f2a1e98a9144da075dfe4d0171804523743b411d316543035f5ce3129")
            self.assertEqual(report["items"][0]["body_sha256"], "dde6fa0eb6a5f04351ecba4e6aadfd4803bb7dbe531d278a089936179f3983b3")
            self.assertNotIn(first["body"], result.stdout)
            self.assertEqual(path.read_bytes(), raw)
            for items, field in (([first, dict(first, code="kb tls")], "code"), ([dict(first, source_version="")], "source_version"), ([dict(first, source_url="https://user:{{PASSWORD_mcutdemk}}@source.test/")], "source_url"), ([dict(first, published=True)], "published"), ([dict(first, body=12)], "body")):
                path.write_text(json.dumps({"items": items}), encoding="utf-8")
                invalid = self.run_skill("knowledge-package-check", path)
                self.assertEqual(invalid.returncode, 2, invalid.stdout)
                failure = json.loads(invalid.stderr)
                self.assertFalse(failure["valid"])
                self.assertTrue(any(error["field"] == field for error in failure["errors"]))
                self.assertNotIn("{{PASSWORD_mcutdemk}}", invalid.stderr)

    def test_report_index_retains_actual_status_and_flags_missing_evidence_and_stale_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report-data.json"
            data = {"task": {"id": "31", "status": "paused"}, "findings": [
                {"id": "8", "task_id": "31", "status": "pending", "evidence_version": 2, "report_evidence_version": 1, "evidence_refs": [{"snapshot_id": "snap-a", "role": "proof"}, {"snapshot_id": "snap-missing", "role": "verification"}], "summary": "private-summary"},
                {"id": "9", "task_id": "31", "status": "false_positive", "evidence_version": 1, "report_evidence_version": 1, "evidence_refs": []},
                {"id": "10", "task_id": "31", "status": "confirmed", "evidence_version": 3, "report_evidence_version": 3, "evidence_refs": [{"snapshot_id": "snap-b", "role": "supporting"}]},
            ], "evidence": [{"id": "snap-a", "status": "available", "body": "private-body"}, {"id": "snap-b", "status": "unreadable"}, {"id": "snap-unused", "status": "available"}]}
            path.write_text(json.dumps(data), encoding="utf-8")
            result = self.run_skill("report-evidence-index", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["task"], {"id": "31", "status": "paused"})
            self.assertEqual([finding["status"] for finding in report["findings"]], ["pending", "false_positive", "confirmed"])
            self.assertTrue(report["findings"][0]["report_stale"])
            self.assertEqual(report["findings"][0]["evidence_refs"][1]["status"], "unknown_reference")
            self.assertEqual(report["findings"][2]["evidence_refs"][0]["status"], "unreadable")
            self.assertEqual(report["finding_status_counts"], {"pending": 1, "false_positive": 1, "confirmed": 1})
            self.assertEqual(report["unreferenced_evidence_ids"], ["snap-unused"])
            self.assertNotIn("private-", result.stdout)
            for invalid in (dict(data, findings=[dict(data["findings"][0], task_id="999")]), dict(data, findings=[data["findings"][0], data["findings"][0]]), dict(data, findings=[dict(data["findings"][0], status="probably_confirmed")])):
                path.write_text(json.dumps(invalid), encoding="utf-8")
                failed = self.run_skill("report-evidence-index", path)
                self.assertEqual(failed.returncode, 2)
                self.assertIn("error", json.loads(failed.stderr))

    def test_new_commands_return_json_errors_for_malformed_missing_and_excessive_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            excessive = {
                "scope-asset-inventory": {"targets": ["192.0.2.1"] * 10001},
                "har-api-inventory": {"log": {"entries": [None] * 50001}},
                "knowledge-package-check": {"items": [{}] * 101},
                "report-evidence-index": {"task": {"id": "1", "status": "running"}, "findings": [], "evidence": [None] * 10001},
            }
            for skill, too_many in excessive.items():
                for raw in (b"[", json.dumps(too_many).encode("utf-8")):
                    path.write_bytes(raw)
                    result = self.run_skill(skill, path)
                    self.assertEqual(result.returncode, 2, skill + result.stdout)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("error", json.loads(result.stderr))
                for args in ((path.with_name("not-present.json"),), ()):
                    result = self.run_skill(skill, *args)
                    self.assertEqual(result.returncode, 2, skill + result.stdout)
                    self.assertIn("error", json.loads(result.stderr))

    def test_url_commands_reject_invalid_percent_encoding_and_surrogate_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for target in ("https://example.test/%zz", "https://example.test/\ud800"):
                for skill, data in (("scope-asset-inventory", {"targets": [target]}), ("har-api-inventory", {"log": {"entries": [{"request": {"url": target, "method": "GET"}, "response": {"status": 200}}]}})):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    result = self.run_skill(skill, path)
                    self.assertEqual(result.returncode, 2, skill + result.stdout)
                    self.assertIn("error", json.loads(result.stderr))


if __name__ == "__main__":
    unittest.main()
