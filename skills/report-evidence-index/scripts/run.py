"""Index task findings and evidence references without inferring verification."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 10000
FINDING_STATUSES = {"pending", "in_progress", "confirmed", "resolved", "fixed", "false_positive", "ignored", "duplicate", "risk_accepted"}
EVIDENCE_STATUSES = {"available", "missing", "unreadable"}
ROLES = {"baseline", "proof", "verification", "supporting"}


class JSONParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def identifier(value):
    if type(value) is int and 0 < value <= 9223372036854775807:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", value):
        return value
    raise ValueError("identifiers must be positive integers or 1 to 160 identifier characters")


def array(value, field):
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(field + " must be an array of at most 10000 entries")
    return value


def version(value):
    if type(value) is not int or not 0 <= value <= 9223372036854775807:
        raise ValueError("evidence versions must be nonnegative 64-bit integers")
    return value


def build_index(data):
    if not isinstance(data, dict) or not isinstance(data.get("task"), dict):
        raise ValueError("input must contain task, findings and evidence")
    task_id = identifier(data["task"].get("id"))
    task_status = data["task"].get("status")
    if not isinstance(task_status, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", task_status):
        raise ValueError("task status must be a lowercase status token of at most 64 characters")
    evidence = {}
    for index, entry in enumerate(array(data.get("evidence"), "evidence")):
        if not isinstance(entry, dict):
            raise ValueError("evidence entry " + str(index) + " must be an object")
        identity = identifier(entry.get("id"))
        status = entry.get("status")
        if not isinstance(status, str) or status not in EVIDENCE_STATUSES:
            raise ValueError("evidence status must be available, missing, or unreadable")
        if identity in evidence:
            raise ValueError("duplicate evidence identifier at index " + str(index))
        evidence[identity] = status
    findings, referenced, seen = [], set(), set()
    for index, finding in enumerate(array(data.get("findings"), "findings")):
        if not isinstance(finding, dict):
            raise ValueError("finding entry " + str(index) + " must be an object")
        identity = identifier(finding.get("id"))
        if identity in seen:
            raise ValueError("duplicate finding identifier at index " + str(index))
        seen.add(identity)
        if identifier(finding.get("task_id")) != task_id:
            raise ValueError("finding task_id differs from task at index " + str(index))
        status = finding.get("status")
        if not isinstance(status, str) or status not in FINDING_STATUSES:
            raise ValueError("unknown finding status at index " + str(index))
        evidence_version = version(finding.get("evidence_version"))
        report_version = version(finding.get("report_evidence_version"))
        refs, ref_seen = [], set()
        for ref in array(finding.get("evidence_refs"), "evidence_refs"):
            if not isinstance(ref, dict):
                raise ValueError("evidence_refs entries must be objects")
            snapshot_id = identifier(ref.get("snapshot_id"))
            role = ref.get("role")
            if not isinstance(role, str) or role not in ROLES:
                raise ValueError("evidence role must be baseline, proof, verification, or supporting")
            if snapshot_id in ref_seen:
                raise ValueError("duplicate evidence reference within finding at index " + str(index))
            ref_seen.add(snapshot_id)
            referenced.add(snapshot_id)
            refs.append({"snapshot_id": snapshot_id, "role": role, "status": evidence.get(snapshot_id, "unknown_reference")})
        findings.append({"id": identity, "task_id": task_id, "status": status, "evidence_version": evidence_version, "report_evidence_version": report_version, "report_stale": evidence_version != report_version, "evidence_refs": refs})
    return {"task": {"id": task_id, "status": task_status}, "findings": findings, "finding_status_counts": dict(sorted(Counter(item["status"] for item in findings).items())), "unreferenced_evidence_ids": sorted(set(evidence) - referenced), "conclusion": "indexes recorded statuses and references only; evidence availability does not establish validity or verification"}


def main():
    parser = JSONParser(description=__doc__)
    parser.add_argument("input", type=Path, help="UTF-8 JSON with task, findings and evidence")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 16 MiB")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("input must be valid JSON within parser nesting limits") from None
        result = build_index(data)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except OSError:
        error = "input file could not be read"
    except (ValueError, TypeError, RecursionError) as failure:
        error = str(failure) if isinstance(failure, ValueError) else "invalid input shape or nesting"
    print(json.dumps({"error": error}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
