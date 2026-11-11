import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "skills" / "run_workflow.py"


class SkillRunEvidenceCommandTests(unittest.TestCase):
    def test_directory_evidence_and_output_limit_come_from_fixed_workflows(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "evidence"
            source.mkdir()
            (source / "response.txt").write_bytes(b"saved response")
            command = [sys.executable, str(RUNNER), "evidence-inventory", str(source)]
            first = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
            second = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            report = json.loads(first.stdout)
            self.assertEqual(report["input_kind"], "directory")
            self.assertEqual(report["input_sha256"], json.loads(second.stdout)["input_sha256"])
            self.assertEqual(report["input_bytes"], len(b"saved response"))
            targets = Path(directory) / "targets.json"
            targets.write_text(json.dumps({"targets": ["https://host-" + str(index) + ".test/" for index in range(4000)]}), encoding="utf-8")
            limited = subprocess.run([sys.executable, str(RUNNER), "scope-asset-inventory", str(targets)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(limited.returncode, 1, limited.stderr)
            report = json.loads(limited.stdout)
            self.assertEqual(report["outcome"], "output_limit")
            self.assertTrue(report["truncated"])
            self.assertLessEqual(len(report["stdout"].encode("utf-8")), 64 * 1024)

    def test_fixed_workflow_records_input_digest_and_real_exit_without_modifying_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "headers.json"
            raw = b'{"url":"https://service.test/","headers":{}}'
            source.write_bytes(raw)
            result = subprocess.run([sys.executable, str(RUNNER), "saved-header-review", str(source)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertEqual(evidence["outcome"], "succeeded")
            self.assertEqual(evidence["exit_code"], 0)
            self.assertEqual(evidence["input_label"], "headers.json")
            self.assertEqual(evidence["input_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(evidence["input_bytes"], len(raw))
            self.assertEqual(json.loads(evidence["stdout"])["missing"], ["strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy"])
            self.assertEqual(source.read_bytes(), raw)
            source.write_text('{"url":"ftp://invalid","headers":{}}', encoding="utf-8")
            failed = subprocess.run([sys.executable, str(RUNNER), "saved-header-review", str(source)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(failed.returncode, 1, failed.stderr)
            self.assertEqual(json.loads(failed.stdout)["exit_code"], 2)
            self.assertEqual(json.loads(failed.stdout)["outcome"], "failed")

    def test_tampered_package_is_rejected_before_running_its_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "skills"
            root.mkdir()
            shutil.copyfile(ROOT / "skills/content-manifest.json", root / "content-manifest.json")
            shutil.copytree(ROOT / "skills/saved-header-review", root / "saved-header-review")
            marker = Path(directory) / "executed.txt"
            script = root / "saved-header-review/scripts/run.py"
            script.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n", encoding="utf-8")
            changed_manifest = json.loads((root / "content-manifest.json").read_text(encoding="utf-8-sig"))
            for package in changed_manifest["packages"]:
                if package["name"] == "saved-header-review":
                    for item in package["files"]:
                        if item["path"] == "scripts/run.py":
                            item["bytes"] = script.stat().st_size
                            item["sha256"] = hashlib.sha256(script.read_bytes()).hexdigest()
            (root / "content-manifest.json").write_text(json.dumps(changed_manifest), encoding="utf-8")
            source = Path(directory) / "headers.json"
            source.write_text("{}", encoding="utf-8")
            result = subprocess.run([sys.executable, str(RUNNER), "saved-header-review", str(source), "--skills-dir", str(root)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 2)
            self.assertIn("hash", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(result.stdout, "")
