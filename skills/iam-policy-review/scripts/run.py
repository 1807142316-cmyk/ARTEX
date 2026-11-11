"""Review breadth of recorded AWS IAM statements without evaluating live access."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def strings(value, field):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not 1 <= len(values) <= 1000 or any(not isinstance(item, str) or not 1 <= len(item) <= 8192 for item in values):
        raise ValueError(field + " must be a nonempty string or bounded string array")
    return values


def principals(value):
    if isinstance(value, dict):
        if not value or len(value) > 100:
            raise ValueError("Principal object must contain 1 to 100 types")
        return [item for field, entry in value.items() for item in strings(entry, "Principal." + field)]
    return strings(value, "Principal")


def review(data):
    if not isinstance(data, dict):
        raise ValueError("input must be an IAM policy JSON object")
    version = data.get("Version")
    if version not in (None, "2012-10-17", "2008-10-17"):
        raise ValueError("unsupported policy Version")
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not 1 <= len(statements) <= 1000:
        raise ValueError("Statement must contain 1 to 1000 objects")
    result = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("statement requires Effect Allow or Deny at index " + str(index))
        if ("Action" in statement) == ("NotAction" in statement):
            raise ValueError("statement requires exactly one of Action or NotAction")
        if "Resource" in statement and "NotResource" in statement:
            raise ValueError("Resource and NotResource cannot be combined")
        if "Principal" in statement and "NotPrincipal" in statement:
            raise ValueError("Principal and NotPrincipal cannot be combined")
        action_field = "Action" if "Action" in statement else "NotAction"
        actions = strings(statement[action_field], action_field)
        resources = strings(statement["Resource"], "Resource") if "Resource" in statement else []
        if "NotResource" in statement:
            strings(statement["NotResource"], "NotResource")
        principal_values = principals(statement["Principal"]) if "Principal" in statement else []
        if "NotPrincipal" in statement:
            principals(statement["NotPrincipal"])
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict) or len(condition) > 100:
            raise ValueError("Condition must be a bounded object")
        for operator, entries in condition.items():
            if not isinstance(entries, dict) or not entries or len(entries) > 100:
                raise ValueError("Condition operators must map to bounded key/value objects")
            for key, entry in entries.items():
                strings(entry, "Condition value")
        issues = []
        if statement["Effect"] == "Allow":
            if action_field == "Action" and any("*" in item or "?" in item for item in actions):
                issues.append("wildcard_action")
            if any("*" in item or "?" in item for item in resources):
                issues.append("wildcard_resource")
            if any("*" in item or "?" in item for item in principal_values):
                issues.append("wildcard_principal")
        manual = [field for field in ("NotAction", "NotResource", "NotPrincipal") if field in statement]
        if "Resource" not in statement and "NotResource" not in statement:
            manual.append("resource_scope_not_in_document")
        result.append({"statement_index": index, "effect": statement["Effect"], "conditional": bool(condition), "action_count": len(actions), "resource_count": len(resources), "principal_count": len(principal_values), "issues": issues, "manual_review": manual})
    return {"statements": result, "policy_version": version, "scope": "single policy breadth observations; conditions, explicit denies, identity/resource policies, boundaries, SCPs and sessions are not resolved into effective permissions"}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("input exceeds 4 MiB")
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
