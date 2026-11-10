"""Canonicalize an offline URL/IP/CIDR scope inventory without contacting targets."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_TARGETS = 10000


class JSONParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def canonical_target(value):
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("target must be a nonempty string of at most 8192 characters")
    value = value.strip()
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value) or "\\" in value:
        raise ValueError("target contains whitespace, control characters, or backslashes")
    if "://" not in value:
        if "%" in value:
            raise ValueError("zone identifiers are not accepted")
        try:
            if "/" in value:
                return "cidr", str(ipaddress.ip_network(value, strict=False)), False
            return "ip", str(ipaddress.ip_address(value)), False
        except ValueError:
            raise ValueError("target must be an HTTP(S) URL, IP address, or CIDR") from None
    try:
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = parsed.hostname
        if "%" in host or parsed.netloc.endswith(":"):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            host = "[" + str(address) + "]" if address.version == 6 else str(address)
        except ValueError:
            if ":" in host or re.fullmatch(r"[0-9.]+", host):
                raise ValueError from None
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
            host += ":" + str(port)
        return "url", urlunsplit((parsed.scheme, host, parsed.path or "/", "", "")), bool(parsed.query or parsed.fragment)
    except (ValueError, UnicodeError):
        raise ValueError("URL must be valid HTTP(S), with a valid host/port and without embedded credentials") from None


def main():
    parser = JSONParser(description=__doc__)
    parser.add_argument("input", type=Path, help="UTF-8 JSON object with a targets array")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 8 MiB")
        data = json.loads(raw)
        targets = data.get("targets") if isinstance(data, dict) else None
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError("targets must contain 1 to 10000 entries")
        assets = set()
        removed = 0
        for index, target in enumerate(targets):
            try:
                kind, value, stripped = canonical_target(target)
            except ValueError as error:
                print(json.dumps({"error": str(error), "target_index": index}), file=sys.stderr)
                return 2
            assets.add((kind, value))
            removed += int(stripped)
        print(json.dumps({"assets": [{"kind": kind, "value": value} for kind, value in sorted(assets)], "input_count": len(targets), "duplicate_count": len(targets) - len(assets), "urls_with_query_or_fragment_removed": removed, "input_sha256": hashlib.sha256(raw).hexdigest()}, ensure_ascii=False, sort_keys=True))
        return 0
    except OSError:
        error = "input file could not be read"
    except (ValueError, TypeError, RecursionError):
        error = "invalid JSON or input limits; expected a targets array of 1 to 10000 URLs, IPs, or CIDRs" if len(raw) <= MAX_BYTES else "input exceeds 8 MiB"
    print(json.dumps({"error": error}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
