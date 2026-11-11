"""Review inventory completeness in saved CycloneDX or SPDX JSON offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def text(value, field):
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 8192 or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(field + " must be a bounded string")
    return value.strip()


def array(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 10000 or any(not isinstance(item, dict) for item in value):
        raise ValueError(field + " must be an array of at most 10000 objects")
    return value


def review(data):
    if not isinstance(data, dict):
        raise ValueError("input must be an SBOM object")
    if data.get("bomFormat") == "CycloneDX":
        kind, version = "CycloneDX", text(data.get("specVersion"), "specVersion")
        if version not in ("1.4", "1.5", "1.6"):
            raise ValueError("supported CycloneDX versions are 1.4 to 1.6")
        pending = [(item, 0) for item in reversed(array(data.get("components"), "components"))]
    elif isinstance(data.get("spdxVersion"), str) and data["spdxVersion"] in ("SPDX-2.2", "SPDX-2.3"):
        kind, version = "SPDX", data["spdxVersion"]
        pending = [(item, 0) for item in reversed(array(data.get("packages"), "packages"))]
    else:
        raise ValueError("expected CycloneDX 1.4-1.6 or SPDX 2.2-2.3 JSON")
    result, seen = [], set()
    while pending:
        item, depth = pending.pop()
        if depth > 32 or len(result) >= 10000:
            raise ValueError("SBOM exceeds 10000 components or 32 nesting levels")
        identity = text(item.get("bom-ref" if kind == "CycloneDX" else "SPDXID"), "component identifier")
        if identity:
            if identity in seen:
                raise ValueError("duplicate SBOM component identifier")
            seen.add(identity)
        name = text(item.get("name"), "component name")
        if not name:
            raise ValueError("component name is required")
        component_version = text(item.get("version" if kind == "CycloneDX" else "versionInfo"), "component version")
        if kind == "CycloneDX":
            purl = text(item.get("purl"), "purl")
            cpe = text(item.get("cpe"), "cpe")
            license_present = False
            for entry in array(item.get("licenses"), "licenses"):
                license_object = entry.get("license", {})
                if not isinstance(license_object, dict):
                    raise ValueError("license must be an object")
                license_present |= bool(text(entry.get("expression"), "license expression") or text(license_object.get("id"), "license id") or text(license_object.get("name"), "license name"))
            hashes = [(text(entry.get("alg"), "hash algorithm"), text(entry.get("content"), "hash content")) for entry in array(item.get("hashes"), "hashes")]
            pending.extend((child, depth + 1) for child in reversed(array(item.get("components"), "nested components")))
        else:
            purl, cpe = "", ""
            for entry in array(item.get("externalRefs"), "externalRefs"):
                ref_type = text(entry.get("referenceType"), "referenceType")
                locator = text(entry.get("referenceLocator"), "referenceLocator")
                if ref_type == "purl":
                    purl = locator
                if ref_type in ("cpe22Type", "cpe23Type"):
                    cpe = locator
            license_value = text(item.get("licenseDeclared"), "licenseDeclared")
            license_present = license_value not in ("", "NOASSERTION", "NONE")
            hashes = [(text(entry.get("algorithm"), "checksum algorithm"), text(entry.get("checksumValue"), "checksum value")) for entry in array(item.get("checksums"), "checksums")]
        issues = []
        if not component_version:
            issues.append("version_missing")
        if not (purl.startswith("pkg:") or cpe.startswith(("cpe:/", "cpe:2.3:"))):
            issues.append("package_identifier_missing")
        if not license_present:
            issues.append("license_missing")
        strong = any(algorithm.replace("-", "").upper() in ("SHA256", "SHA384", "SHA512") and re.fullmatch(r"[0-9a-fA-F]{" + str({"SHA256": 64, "SHA384": 96, "SHA512": 128}[algorithm.replace("-", "").upper()]) + r"}", value) for algorithm, value in hashes)
        if not hashes:
            issues.append("hash_missing")
        elif not strong:
            issues.append("no_valid_strong_hash")
        result.append({"component_index": len(result), "name": name, "version": component_version, "issues": issues})
    return {"format": kind, "format_version": version, "component_count": len(result), "components": result, "scope": "declared software inventory quality only; package identifiers/licenses are not fully validated, hashes are not checked against artifacts, no advisory matching or reachability analysis"}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("input exceeds 16 MiB")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("input must be valid JSON") from None
        result = review(data)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except OSError:
        message = "input file could not be read"
    except (ValueError, TypeError) as error:
        message = str(error) if isinstance(error, ValueError) else "invalid input shape"
    print(json.dumps({"error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
