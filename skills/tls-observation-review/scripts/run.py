"""Review recorded TLS session and certificate verification metadata offline."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamps must be ISO 8601 strings with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp is not ISO 8601") from None
    if parsed.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return parsed.astimezone(timezone.utc)


def review(data):
    if not isinstance(data, dict) or not isinstance(data.get("certificate"), dict):
        raise ValueError("input requires certificate object")
    observed = timestamp(data.get("observed_at"))
    cert = data["certificate"]
    before, after = timestamp(cert.get("not_before")), timestamp(cert.get("not_after"))
    if after <= before:
        raise ValueError("certificate not_after must follow not_before")
    protocol = data.get("protocol")
    if protocol not in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        raise ValueError("unsupported recorded protocol token")
    cipher, bits = data.get("cipher"), data.get("cipher_bits")
    if not isinstance(cipher, str) or not 1 <= len(cipher) <= 160 or not all(char.isalnum() or char in "_-" for char in cipher):
        raise ValueError("cipher must be a nonempty cipher-name token")
    if type(bits) is not int or not 0 <= bits <= 4096:
        raise ValueError("cipher_bits must be an integer from 0 to 4096")
    issues, unknown = [], []
    if protocol not in ("TLSv1.2", "TLSv1.3"):
        issues.append("legacy_protocol")
    if bits < 128:
        issues.append("low_cipher_strength")
    state = "not_yet_valid" if observed < before else "expired" if observed > after else "valid_at_observation"
    if state != "valid_at_observation":
        issues.append("certificate_" + state)
    for field, code in (("chain_verified", "chain_verification_failed"), ("hostname_match", "hostname_mismatch")):
        value = cert.get(field)
        if value is not None and type(value) is not bool:
            raise ValueError(field + " must be true, false, or null")
        if value is None:
            unknown.append(field)
        elif not value:
            issues.append(code)
    return {"protocol": protocol, "cipher": cipher, "cipher_bits": bits, "certificate_time_state": state, "seconds_until_expiry": int((after - observed).total_seconds()), "issues": issues, "unknown_checks": unknown, "scope": "one recorded session; cipher strength and verification fields are supplied observations, not independent certificate validation"}


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
    except (ValueError, TypeError, OverflowError) as error:
        message = str(error) if isinstance(error, ValueError) else "invalid input shape or timestamp"
    print(json.dumps({"error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
