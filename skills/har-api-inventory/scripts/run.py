"""Build a method/path/status inventory from a saved HAR without network access."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

MAX_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 50000


class JSONParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def endpoint(request):
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    value, method = request.get("url"), request.get("method")
    if not isinstance(value, str) or not 1 <= len(value) <= 16384 or any(char.isspace() or ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value) or "\\" in value:
        raise ValueError("request URL is invalid")
    if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}", method):
        raise ValueError("request method must be an HTTP token of at most 32 characters")
    try:
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.netloc.endswith(":"):
            raise ValueError
        host = parsed.hostname
        if "%" in host:
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
        return (parsed.scheme + "://" + host, parsed.path or "/", method), bool(parsed.query or parsed.fragment)
    except (ValueError, UnicodeError):
        raise ValueError("request URL must be valid HTTP(S) without embedded credentials") from None


def main():
    parser = JSONParser(description=__doc__)
    parser.add_argument("input", type=Path, help="UTF-8 HAR JSON file")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 32 MiB")
        data = json.loads(raw)
        log = data.get("log") if isinstance(data, dict) else None
        entries = log.get("entries") if isinstance(log, dict) else None
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise ValueError("HAR log.entries must be an array of at most 50000 entries")
        grouped = {}
        removed = 0
        for index, entry in enumerate(entries):
            try:
                if not isinstance(entry, dict) or not isinstance(entry.get("response"), dict):
                    raise ValueError("entry must contain request and response objects")
                key, stripped = endpoint(entry.get("request"))
                status = entry["response"].get("status")
                if type(status) is not int or not (status == 0 or 100 <= status <= 599):
                    raise ValueError("response status must be 0 or an integer from 100 to 599")
            except ValueError as error:
                print(json.dumps({"error": str(error), "entry_index": index}), file=sys.stderr)
                return 2
            grouped.setdefault(key, Counter())[status] += 1
            removed += int(stripped)
        endpoints = [{"origin": origin, "path": path, "method": method, "count": sum(counts.values()), "status_counts": {str(status): count for status, count in sorted(counts.items())}} for (origin, path, method), counts in sorted(grouped.items())]
        print(json.dumps({"endpoints": endpoints, "entry_count": len(entries), "endpoint_count": len(endpoints), "urls_with_query_or_fragment_removed": removed, "input_sha256": hashlib.sha256(raw).hexdigest()}, ensure_ascii=False, sort_keys=True))
        return 0
    except OSError:
        error = "input file could not be read"
    except (ValueError, TypeError, RecursionError):
        error = "invalid HAR JSON or input limits; expected log.entries with at most 50000 entries and 32 MiB"
    print(json.dumps({"error": error}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
