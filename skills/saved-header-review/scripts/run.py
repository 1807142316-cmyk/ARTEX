"""Analyze previously captured HTTP response headers without network access."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

CONTROLS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy")
MAX_BYTES = 4 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON object containing url and headers")
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > MAX_BYTES:
            raise ValueError("input exceeds 4 MiB")
        raw = args.input.read_bytes()
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("url"), str):
            raise ValueError("input must contain a URL string")
        parsed = urlsplit(data["url"])
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("url must be HTTP(S) without embedded credentials")
        headers = data.get("headers")
        if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
            raise ValueError("headers must map names to string values")
        headers = {key.lower(): value.strip() for key, value in headers.items()}
        checks = []
        for name in CONTROLS:
            value = headers.get(name, "")
            applicable = name != "strict-transport-security" or parsed.scheme == "https"
            checks.append({"header": name, "present": bool(value), "applicable": applicable})
        warnings = []
        if headers.get("x-content-type-options", "").lower() not in ("", "nosniff"):
            warnings.append("x-content-type-options is present but is not nosniff")
        # Output evidence identity and decisions; do not echo cookies or headers.
        result = {"origin": parsed.scheme + "://" + parsed.netloc, "evidence_sha256": hashlib.sha256(raw).hexdigest(), "checks": checks,
                  "missing": [check["header"] for check in checks if check["applicable"] and not check["present"]], "warnings": warnings,
                  "conclusion": "configuration observations; header presence does not confirm security or a vulnerability"}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
