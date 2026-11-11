"""Assess CORS headers from one saved response without sending requests."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def valid_origin(value):
    if value == "null":
        return True
    try:
        parsed = urlsplit(value)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname) and not parsed.path and not parsed.query and not parsed.fragment and parsed.username is None and parsed.password is None and not any(char.isspace() or ord(char) < 32 for char in value) and "\\" not in value and (parsed.port is None or 1 <= parsed.port <= 65535)
    except ValueError:
        return False


def review(data):
    if not isinstance(data, dict) or not isinstance(data.get("request_origin"), str) or not valid_origin(data["request_origin"]):
        raise ValueError("request_origin must be a serialized HTTP(S) origin or null string")
    mode = data.get("credentials_mode")
    if mode not in ("include", "omit", "same-origin"):
        raise ValueError("credentials_mode must be include, omit, or same-origin")
    source = data.get("response_headers")
    if not isinstance(source, list) or len(source) > 1000:
        raise ValueError("response_headers must be an array of at most 1000 name/value objects")
    headers = {}
    for item in source:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str) or len(item["name"]) > 256 or len(item["value"]) > 16384:
            raise ValueError("header names and values must be bounded strings")
        headers.setdefault(item["name"].lower(), []).append(item["value"].strip())
    origins = headers.get("access-control-allow-origin", [])
    credentials = headers.get("access-control-allow-credentials", [])
    issues = []
    if len(origins) > 1 or len(credentials) > 1:
        return {"policy": "ambiguous", "origin_permitted": False, "issues": ["duplicate_cors_headers"], "scope": "one recorded response; duplicate singleton CORS fields require correction"}
    allowed = origins[0] if origins else ""
    credential_allowed = credentials == ["true"]
    if credentials and not credential_allowed:
        issues.append("invalid_allow_credentials_value")
    policy = "absent" if not allowed else "wildcard" if allowed == "*" else "origin" if valid_origin(allowed) else "invalid"
    permitted = False
    if policy == "wildcard":
        if mode == "include":
            issues.append("wildcard_with_credentials")
        else:
            permitted = True
    elif policy == "origin":
        permitted = allowed == data["request_origin"] and (mode != "include" or credential_allowed)
        if allowed == "null":
            issues.append("opaque_origin_allowance_requires_review")
        vary = {token.strip().lower() for value in headers.get("vary", []) for token in value.split(",")}
        if "origin" not in vary and "*" not in vary:
            issues.append("origin_specific_response_without_vary_origin")
        if mode == "include" and not credential_allowed:
            issues.append("credentials_not_allowed")
    elif policy == "invalid":
        issues.append("invalid_allow_origin_value")
    return {"policy": policy, "origin_permitted": permitted, "issues": issues, "scope": "one saved response; evaluates origin/credentials fields only, not preflight, reflection across origins, cookies, redirects, or overall exploitability"}


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
