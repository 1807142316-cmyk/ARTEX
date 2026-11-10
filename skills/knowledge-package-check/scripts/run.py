"""Validate a knowledge import package offline without changing files or records."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

MAX_BYTES = 16 * 1024 * 1024
FIELDS = {"code": 160, "category": 120, "kind": 120, "tier": 80, "summary": 4000, "body": 80000, "source_url": 8192, "source_version": 240}
REQUIRED = {"code", "summary", "body", "source_url", "source_version"}


class JSONParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"valid": False, "error": message}) + "\n")


def source_valid(value):
    try:
        parsed = urlsplit(value)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname) and parsed.username is None and parsed.password is None and not any(char.isspace() or ord(char) < 32 for char in value) and "\\" not in value and not parsed.netloc.endswith(":") and (parsed.port is None or 1 <= parsed.port <= 65535)
    except ValueError:
        return False


def check(items):
    errors, normalized = [], []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append({"item_index": index, "field": "item", "message": "entry must be an object"})
            continue
        for field in sorted(set(item) - FIELDS.keys()):
            errors.append({"item_index": index, "field": field, "message": "unknown field; publication and verification decisions are not import fields"})
        entry = {}
        for field, limit in FIELDS.items():
            value = item.get(field, "")
            if not isinstance(value, str):
                errors.append({"item_index": index, "field": field, "message": "must be a string"})
                value = ""
            value = " ".join(value.split()) if field == "code" else value.strip()
            if len(value) > limit or "\x00" in value or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                errors.append({"item_index": index, "field": field, "message": "exceeds length limit or contains an unsupported character"})
            if field in REQUIRED and not value:
                errors.append({"item_index": index, "field": field, "message": "required for a traceable content package"})
            entry[field] = value
        if entry["source_url"] and not source_valid(entry["source_url"]):
            errors.append({"item_index": index, "field": "source_url", "message": "must be absolute HTTP(S), with a valid port and without embedded credentials"})
        normalized.append((index, entry))
    if errors:
        return None, errors
    codes, bodies = {}, defaultdict(list)
    result = []
    for index, entry in normalized:
        code = entry["code"].lower()
        if code in codes:
            errors.append({"item_index": index, "field": "code", "message": "duplicate normalized code", "previous_item_index": codes[code]})
        else:
            codes[code] = index
        # Match the ordered normalized fields used by the knowledge version hash.
        content_hash = hashlib.sha256("\x00".join(entry[field] for field in FIELDS).encode("utf-8")).hexdigest()
        body_hash = hashlib.sha256(entry["body"].encode("utf-8")).hexdigest()
        bodies[body_hash].append(index)
        result.append({"item_index": index, "code": entry["code"], "content_sha256": content_hash, "body_sha256": body_hash, "source_version": entry["source_version"]})
    if errors:
        return None, errors
    duplicates = [{"body_sha256": digest, "item_indices": indices} for digest, indices in sorted(bodies.items()) if len(indices) > 1]
    return {"valid": True, "item_count": len(items), "items": result, "duplicate_bodies": duplicates, "scope": "input package only; no comparison with existing database content"}, []


def main():
    parser = JSONParser(description=__doc__)
    parser.add_argument("input", type=Path, help="UTF-8 JSON object with 1 to 100 items")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 16 MiB")
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {"items"} or not isinstance(data["items"], list) or not 1 <= len(data["items"]) <= 100:
            raise ValueError("package must contain only an items array of 1 to 100 entries")
        result, errors = check(data["items"])
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
            return 2
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except OSError:
        message = "input file could not be read"
    except (ValueError, TypeError, RecursionError):
        message = "invalid JSON or package shape; expected only items with 1 to 100 entries and at most 16 MiB"
    print(json.dumps({"valid": False, "error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
