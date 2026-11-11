"""Inspect saved Set-Cookie attributes while suppressing cookie names and values."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def review(data):
    if not isinstance(data, dict) or data.get("scheme") not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    cookies = data.get("set_cookie")
    if not isinstance(cookies, list) or len(cookies) > 1000:
        raise ValueError("set_cookie must be an array of at most 1000 individual header strings")
    result = []
    for index, header in enumerate(cookies):
        if not isinstance(header, str) or len(header) > 16384 or any(ord(char) < 32 or ord(char) == 127 for char in header):
            raise ValueError("cookie header at index " + str(index) + " is invalid")
        parts = header.split(";")
        name, separator, value = parts[0].strip().partition("=")
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("cookie pair at index " + str(index) + " is invalid")
        attrs, duplicates, valued_flags = {}, [], []
        for part in parts[1:]:
            key, equal, attr_value = part.strip().partition("=")
            key = key.lower()
            if not key:
                continue
            if not re.fullmatch(r"[a-z0-9-]{1,64}", key):
                raise ValueError("attribute at cookie index " + str(index) + " is invalid")
            if key in attrs:
                duplicates.append(key)
            attrs[key] = attr_value.strip()
            if equal and key in ("secure", "httponly", "partitioned"):
                valued_flags.append(key)
        secure, http_only = "secure" in attrs, "httponly" in attrs
        same_site = attrs.get("samesite", "").lower()
        issues = []
        if not secure:
            issues.append("secure_absent")
        if not http_only:
            issues.append("httponly_absent")
        if not same_site:
            issues.append("samesite_absent")
        elif same_site not in ("lax", "strict", "none"):
            issues.append("invalid_samesite")
        if same_site == "none" and not secure:
            issues.append("samesite_none_without_secure")
        if name.startswith(("__Secure-", "__Host-")):
            if not secure:
                issues.append("secure_prefix_without_secure")
            if data["scheme"] != "https":
                issues.append("secure_prefix_over_http")
        if name.startswith("__Host-"):
            if "domain" in attrs:
                issues.append("host_prefix_with_domain")
            if attrs.get("path") != "/":
                issues.append("host_prefix_path_not_root")
        if "partitioned" in attrs and not secure:
            issues.append("partitioned_without_secure")
        issues.extend("duplicate_attribute:" + key for key in sorted(set(duplicates)))
        issues.extend("flag_has_value:" + key for key in sorted(set(valued_flags)))
        result.append({"cookie_index": index, "secure": secure, "http_only": http_only, "same_site": same_site if same_site in ("none", "lax", "strict") else "unspecified_or_invalid", "host_only": "domain" not in attrs, "issues": issues})
    return {"cookies": result, "cookie_count": len(cookies), "scope": "attribute observations only; value handling, browser acceptance, session semantics and complete RFC grammar require separate review"}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("input exceeds 2 MiB")
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
