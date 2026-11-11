import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "skills" / "python-source-review" / "scripts" / "run.py"


class PythonSourceReviewTests(unittest.TestCase):
    def test_source_review_inventories_ast_locations_without_executing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "must-not-exist"
            source = (
                "import subprocess\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('source-was-executed')\n"
                "def build(value):\n"
                "    return eval(value)\n"
                "async def inspect():\n"
                "    subprocess.run(['tool'], shell=True)\n"
                "    exec('pass')\n"
            )
            path = root / "source.py"
            raw = source.encode("utf-8")
            path.write_bytes(raw)
            completed = subprocess.run([sys.executable, str(SCRIPT), "--input", str(path)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertFalse(marker.exists())
            self.assertEqual(report["input_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual([(item["name"], item["line"], item["async"]) for item in report["functions"]], [("build", 4, False), ("inspect", 6, True)])
            self.assertEqual([(item["module"], item["line"]) for item in report["imports"]], [("subprocess", 1), ("pathlib", 2)])
            self.assertEqual([(item["callee"], item["line"], item["checks"]) for item in report["review_sites"]], [("eval", 5, ["dynamic_evaluation"]), ("subprocess.run", 7, ["subprocess_invocation", "shell_enabled"]), ("exec", 8, ["dynamic_execution"])])
            self.assertEqual(report["counts"], {"functions": 2, "imports": 2, "calls": 5, "review_sites": 3})
            self.assertEqual(report["review_sites"][0]["column"], 11)
            self.assertIn("manual review", report["scope"])
            self.assertNotIn("source-was-executed", completed.stdout)

    def test_source_review_rejects_invalid_missing_and_excessive_inputs_as_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, raw, expected in [
                ("syntax.py", b"def broken(:\n", "syntax"),
                ("binary.py", b"\xff\xfe", "UTF-8"),
                ("large.py", b"#" * (1024 * 1024 + 1), "1 MiB"),
                ("nodes.py", ("values = [" + ",".join("0" for _ in range(26000)) + "]").encode(), "25000 AST nodes"),
                ("entries.py", ("def f(): pass\n" * 1001).encode(), "1000 report entries"),
                ("missing.py", None, "regular file"),
            ]:
                with self.subTest(name=name):
                    path = root / name
                    if raw is not None:
                        path.write_bytes(raw)
                    completed = subprocess.run([sys.executable, str(SCRIPT), "--input", str(path)], capture_output=True, text=True, encoding="utf-8")
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(expected, json.loads(completed.stderr)["error"])
                    self.assertNotIn("Traceback", completed.stderr)
            for args in ([], [str(root)], [str(root), "--input", str(root)]):
                completed = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8")
                self.assertEqual(completed.returncode, 2)
                self.assertIn("error", json.loads(completed.stderr))

    def test_source_review_preserves_literal_aliases_and_unknown_runtime_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.py"
            path.write_text("from subprocess import run as launch\nfrom .helpers import check\nlaunch(['tool'])\nother(shell=True)\nsubprocess.run = local\nsubprocess.run(['tool'])\n", encoding="utf-8")
            completed = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["imports"][0]["names"], [{"name": "run", "alias": "launch"}])
            self.assertEqual(report["imports"][1]["relative_level"], 1)
            self.assertEqual([(item["callee"], item["line"], item["checks"]) for item in report["review_sites"]], [("other", 4, ["shell_enabled"]), ("subprocess.run", 6, ["subprocess_invocation"])])
            self.assertIn("not resolved to runtime bindings", report["scope"])


if __name__ == "__main__":
    unittest.main()
