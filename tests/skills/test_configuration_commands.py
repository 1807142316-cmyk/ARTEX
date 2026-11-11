import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2] / "skills"


class ConfigurationCommandTests(unittest.TestCase):
    def run_json(self, name, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return subprocess.run([sys.executable, str(ROOT / name / "scripts" / "run.py"), str(path)], capture_output=True, text=True, encoding="utf-8")

    def test_tls_observation_keeps_verification_unknown_and_detects_expired_legacy_session(self):
        data = {"observed_at": "2026-11-11T00:00:00Z", "protocol": "TLSv1", "cipher": "ECDHE-RSA-AES256-SHA", "cipher_bits": 256, "certificate": {"not_before": "2025-01-01T00:00:00Z", "not_after": "2026-11-10T00:00:00Z", "hostname_match": None, "chain_verified": False}}
        result = self.run_json("tls-observation-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["certificate_time_state"], "expired")
        self.assertEqual(report["issues"], ["legacy_protocol", "certificate_expired", "chain_verification_failed"])
        self.assertEqual(report["unknown_checks"], ["hostname_match"])
        self.assertEqual(report["seconds_until_expiry"], -86400)
        data["certificate"]["hostname_match"] = "true"
        failed = self.run_json("tls-observation-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_cors_rejects_wildcard_credentials_and_keeps_omitted_policy_distinct(self):
        data = {"request_origin": "https://client.test", "credentials_mode": "include", "response_headers": [{"name": "Access-Control-Allow-Origin", "value": "*"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}, {"name": "Set-Cookie", "value": "session=private-cookie"}]}
        result = self.run_json("cors-policy-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["policy"], "wildcard")
        self.assertFalse(report["origin_permitted"])
        self.assertEqual(report["issues"], ["wildcard_with_credentials"])
        self.assertNotIn("private-cookie", result.stdout)
        data["response_headers"] = [{"name": "Access-Control-Allow-Origin", "value": "https://client.test"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}]
        report = json.loads(self.run_json("cors-policy-review", data).stdout)
        self.assertTrue(report["origin_permitted"])
        self.assertIn("origin_specific_response_without_vary_origin", report["issues"])
        data["response_headers"] = []
        report = json.loads(self.run_json("cors-policy-review", data).stdout)
        self.assertEqual(report["policy"], "absent")
        self.assertFalse(report["origin_permitted"])

    def test_cookie_attributes_preserve_duplicate_fields_without_outputting_values(self):
        data = {"scheme": "https", "set_cookie": ["__Host-session=session=private-value; Secure; HttpOnly; SameSite=None; Path=/; Domain=service.test", "session=private-value; SameSite=None; Path=/", "session=private-value; Secure; Path=/; Path=/api"]}
        result = self.run_json("cookie-attribute-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("host_prefix_with_domain", report["cookies"][0]["issues"])
        self.assertEqual(report["cookies"][1]["issues"], ["secure_absent", "httponly_absent", "samesite_none_without_secure"])
        self.assertIn("duplicate_attribute:path", report["cookies"][2]["issues"])
        self.assertNotIn("private-value", result.stdout)
        self.assertNotIn("service.test", result.stdout)
        data["set_cookie"] = ["malformed"]
        failed = self.run_json("cookie-attribute-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_sshd_effective_configuration_reports_omissions_without_parsing_source_defaults(self):
        data = {"effective_config": "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication yes\npermitemptypasswords no\npubkeyauthentication yes\nx11forwarding no\nallowtcpforwarding yes\nmaxauthtries 8\nallowusers private-user\n"}
        result = self.run_json("sshd-effective-config-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["issues"], ["root_login_enabled", "keyboard_interactive_enabled", "tcp_forwarding_enabled", "maxauthtries_above_6"])
        self.assertEqual(report["unknown_checks"], ["usepam", "loglevel"])
        self.assertNotIn("private-user", result.stdout)
        data["effective_config"] += "passwordauthentication yes\n"
        failed = self.run_json("sshd-effective-config-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_docker_inspect_reviews_isolation_without_exposing_environment_or_mount_sources(self):
        data = [{"Config": {"User": "", "Env": ["session=private-value"]}, "HostConfig": {"Privileged": True, "ReadonlyRootfs": False, "NetworkMode": "host", "PidMode": "host", "CapAdd": ["SYS_ADMIN"], "SecurityOpt": ["seccomp=unconfined"]}, "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/run/engine.sock", "RW": True}, {"Source": "/private/source", "Destination": "/data", "RW": True}]}]
        result = self.run_json("container-inspect-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["containers"][0]["issues"], ["privileged", "root_or_unspecified_user", "writable_rootfs", "host_network", "host_pid_namespace", "broad_added_capability", "seccomp_unconfined", "no_new_privileges_not_set", "engine_socket_mounted"])
        self.assertEqual(report["containers"][0]["writable_mount_count"], 2)
        self.assertNotIn("private-value", result.stdout)
        self.assertNotIn("/private/source", result.stdout)
        data[0]["HostConfig"]["Privileged"] = "false"
        failed = self.run_json("container-inspect-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_iam_policy_reports_conditional_allow_and_deny_separately_without_claiming_effective_access(self):
        data = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*", "Principal": "*", "Condition": {"StringEquals": {"aws:PrincipalAccount": "private-account"}}}, {"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}]}
        result = self.run_json("iam-policy-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["statements"][0]["issues"], ["wildcard_action", "wildcard_resource", "wildcard_principal"])
        self.assertTrue(report["statements"][0]["conditional"])
        self.assertEqual(report["statements"][1]["effect"], "Deny")
        self.assertEqual(report["statements"][1]["issues"], [])
        self.assertIn("NotAction", report["statements"][1]["manual_review"])
        self.assertNotIn("private-account", result.stdout)
        self.assertNotIn("effective_access", report)
        data["Statement"][0]["Resource"] = {"unexpected": "value"}
        failed = self.run_json("iam-policy-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_sbom_reviews_inventory_quality_for_cyclonedx_and_spdx_without_vulnerability_claims(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"bom-ref": "a", "name": "library-a", "version": "1.0", "purl": "pkg:pypi/library-a@1.0", "licenses": [{"license": {"id": "MIT"}}], "hashes": [{"alg": "SHA-256", "content": "a" * 64}], "components": [{"bom-ref": "b", "name": "library-b"}]}]}
        result = self.run_json("sbom-inventory-review", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["component_count"], 2)
        self.assertEqual(report["components"][0]["issues"], [])
        self.assertEqual(report["components"][1]["issues"], ["version_missing", "package_identifier_missing", "license_missing", "hash_missing"])
        self.assertNotIn("vulnerabilities", report)
        data = {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-A", "name": "library-a", "versionInfo": "1.0", "licenseDeclared": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": "not-a-digest"}], "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/library-a@1.0"}]}]}
        report = json.loads(self.run_json("sbom-inventory-review", data).stdout)
        self.assertEqual(report["components"][0]["issues"], ["license_missing", "no_valid_strong_hash"])
        data["packages"].append(dict(data["packages"][0]))
        failed = self.run_json("sbom-inventory-review", data)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("error", json.loads(failed.stderr))

    def test_configuration_commands_reject_malformed_and_missing_files_as_json_errors(self):
        names = ("tls-observation-review", "cors-policy-review", "cookie-attribute-review", "sshd-effective-config-review", "container-inspect-review", "iam-policy-review", "sbom-inventory-review")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{", encoding="utf-8")
            for name in names:
                script = ROOT / name / "scripts" / "run.py"
                for args in ((path,), (path.with_name("missing.json"),), ()):
                    failed = subprocess.run([sys.executable, str(script), *map(str, args)], capture_output=True, text=True, encoding="utf-8")
                    self.assertEqual(failed.returncode, 2, name)
                    self.assertEqual(failed.stdout, "")
                    self.assertIn("error", json.loads(failed.stderr))
