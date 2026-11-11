"""Audit saved sshd -T effective configuration without contacting or changing hosts."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

CHECKS = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords", "pubkeyauthentication", "x11forwarding", "allowtcpforwarding", "maxauthtries", "usepam", "loglevel")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def review(data):
    text = data.get("effective_config") if isinstance(data, dict) else None
    if not isinstance(text, str) or not text.strip() or len(text) > 512000:
        raise ValueError("effective_config must contain saved sshd -T output, at most 512000 characters")
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].isascii() or not parts[0].isalnum():
            raise ValueError("invalid effective configuration line " + str(number))
        key, value = parts[0].lower(), parts[1].strip().lower()
        if key in ("match", "include"):
            raise ValueError("source Match/Include directives are not effective sshd -T output")
        if key not in CHECKS:
            continue
        if key in values:
            raise ValueError("duplicate checked directive on line " + str(number))
        values[key] = value
    if not values:
        raise ValueError("no supported sshd -T directives were found")
    allowed = {"permitrootlogin": {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}, "allowtcpforwarding": {"yes", "no", "local", "remote"}, "loglevel": {"quiet", "fatal", "error", "info", "verbose", "debug", "debug1", "debug2", "debug3"}}
    for key, value in values.items():
        if key == "maxauthtries":
            if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 100000:
                raise ValueError("maxauthtries must be a positive integer")
        elif value not in allowed.get(key, {"yes", "no"}):
            raise ValueError("unsupported effective value for " + key)
    issues = []
    rules = (("permitrootlogin", "yes", "root_login_enabled"), ("passwordauthentication", "yes", "password_authentication_enabled"), ("kbdinteractiveauthentication", "yes", "keyboard_interactive_enabled"), ("permitemptypasswords", "yes", "empty_passwords_permitted"), ("pubkeyauthentication", "no", "public_key_authentication_disabled"), ("x11forwarding", "yes", "x11_forwarding_enabled"))
    for key, value, code in rules:
        if values.get(key) == value:
            issues.append(code)
    if "allowtcpforwarding" in values and values["allowtcpforwarding"] != "no":
        issues.append("tcp_forwarding_enabled")
    if int(values.get("maxauthtries", "1")) > 6:
        issues.append("maxauthtries_above_6")
    if values.get("loglevel") in ("quiet", "fatal", "error"):
        issues.append("limited_authentication_logging")
    return {"checked_values": values, "issues": issues, "unknown_checks": [key for key in CHECKS if key not in values], "scope": "configuration observations for one sshd -T context; forwarding and authentication exceptions require workload review"}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("input exceeds 1 MiB")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("input must be valid JSON") from None
        result = review(data)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 0
    except OSError:
        message = "input file could not be read"
    except (ValueError, TypeError) as error:
        message = str(error) if isinstance(error, ValueError) else "invalid input shape"
    print(json.dumps({"error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
