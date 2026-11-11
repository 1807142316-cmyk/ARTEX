#!/usr/bin/env python3
"""Run a fixed manifest-verified offline workflow and emit immutable execution evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid

WORKFLOWS = frozenset(("saved-header-review", "evidence-inventory", "cve-record-review", "scope-asset-inventory", "har-api-inventory", "knowledge-package-check", "report-evidence-index", "tls-observation-review", "cors-policy-review", "cookie-attribute-review", "sshd-effective-config-review", "container-inspect-review", "iam-policy-review", "sbom-inventory-review", "python-source-review"))
OUTPUT_LIMIT = 64 * 1024
INPUT_LIMIT = 1024 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sha_file(path, limit):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("input exceeds size limit")
            digest.update(chunk)
    return size, digest.hexdigest()


def input_identity(path):
    if path.is_symlink():
        raise ValueError("input must not be a symlink")
    if path.is_file():
        size, digest = sha_file(path, INPUT_LIMIT)
        return "file", size, digest
    if not path.is_dir():
        raise ValueError("input must be an existing file or directory")
    digest = hashlib.sha256()
    total = 0
    entries = 0
    pending = [path]
    files = []
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > 50000:
                    raise ValueError("input exceeds 50000 directory entries")
                if child.is_symlink():
                    continue
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    files.append(Path(child.path))
                    if len(files) > 10000:
                        raise ValueError("input exceeds 10000 files")
    for item in sorted(files):
        size, item_digest = sha_file(item, INPUT_LIMIT - total)
        total += size
        row = [item.relative_to(path).as_posix(), size, item_digest]
        digest.update(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
    return "directory", total, digest.hexdigest()


def package_identity(root, name):
    # The runner's distributed manifest is the trust source. An alternative
    # content directory cannot replace its own expected hashes.
    manifest = Path(__file__).resolve().parents[2] / "skills/content-manifest.json"
    with manifest.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("manifest exceeds size limit")
    data = json.loads(raw.decode("utf-8-sig"))
    packages = [item for item in data["packages"] if item["name"] == name]
    if len(packages) != 1:
        raise ValueError("workflow is absent or duplicated in content manifest")
    package = packages[0]
    hashes = {}
    script = None
    for relative in ("SKILL.md", "scripts/run.py"):
        records = [item for item in package["files"] if item["path"] == relative]
        if len(records) != 1:
            raise ValueError("manifest lacks workflow resource hash")
        path = root / name / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("workflow resource path escapes content root")
        with path.open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        size, digest = len(content), hashlib.sha256(content).hexdigest()
        if size > 1024 * 1024:
            raise ValueError("workflow resource exceeds size limit")
        record = records[0]
        if size != record["bytes"] or digest != record["sha256"]:
            raise ValueError("workflow resource hash differs from content manifest")
        hashes[relative] = digest
        if relative == "scripts/run.py":
            script = content
    return package["version"], hashes, script


def run_bounded(command, timeout):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    exceeded = threading.Event()
    outputs = [bytearray(), bytearray()]
    def read(index, stream):
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            room = OUTPUT_LIMIT - len(outputs[index])
            outputs[index].extend(chunk[:room])
            if len(chunk) > room:
                exceeded.set()
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        stream.close()
    readers = [threading.Thread(target=read, args=(index, stream), daemon=True) for index, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()
    for reader in readers:
        reader.join()
    outcome = "timeout" if timed_out else "output_limit" if exceeded.is_set() else "succeeded" if process.returncode == 0 else "failed"
    # Windows termination codes are unsigned; retain the outcome with a bounded portable code.
    exit_code = process.returncode if -255 <= process.returncode <= 255 else -1
    if timed_out and exit_code == 0:
        exit_code = -1
    decoded = [bytes(value).decode("utf-8", errors="replace").encode("utf-8")[:OUTPUT_LIMIT].decode("utf-8", errors="ignore") for value in outputs]
    return outcome, exit_code, exceeded.is_set(), *decoded


def server_origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("artex-url must be an HTTP(S) origin without credentials")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not loopback:
        raise ValueError("artex-url requires HTTPS or loopback HTTP")
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skill", choices=sorted(WORKFLOWS))
    parser.add_argument("input", type=Path)
    parser.add_argument("--skills-dir", type=Path, default=Path(__file__).resolve().parents[2] / "skills")
    parser.add_argument("--task-id", type=int)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--artex-url", help="Optional authenticated evidence submission; JWT is read from ARTEX_SKILL_RUN_TOKEN")
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout <= 120 or args.task_id is not None and args.task_id < 1:
            raise ValueError("timeout must be 1..120 and task-id positive")
        origin = server_origin(args.artex_url) if args.artex_url else None
        token = os.environ.get("ARTEX_SKILL_RUN_TOKEN", "").strip()
        if origin and not token:
            raise ValueError("ARTEX_SKILL_RUN_TOKEN is required for submission")
        version, hashes, script = package_identity(args.skills_dir, args.skill)
        source = args.input.absolute()
        identity = input_identity(source)
        started = datetime.now(timezone.utc).isoformat()
        # Execute the exact verified bytes, independent of subsequent content-directory edits.
        with tempfile.TemporaryDirectory(prefix="artex-skill-run-") as directory:
            executable = Path(directory) / "run.py"
            executable.write_bytes(script)
            result = run_bounded([sys.executable, "-I", str(executable), str(source)], args.timeout)
        outcome, code, truncated, stdout, stderr = result
        finished = datetime.now(timezone.utc).isoformat()
        try:
            changed = input_identity(source) != identity
        except (OSError, ValueError):
            changed = True
        if changed:
            outcome = "input_changed"
        report = {"client_run_id": str(uuid.uuid4()), "skill": args.skill, "package_version": version, "script_sha256": hashes["scripts/run.py"], "instructions_sha256": hashes["SKILL.md"], "input_label": source.name or "directory", "input_sha256": identity[2], "input_kind": identity[0], "input_bytes": identity[1], "started_at": started, "finished_at": finished, "exit_code": code, "outcome": outcome, "stdout": stdout, "stderr": stderr, "truncated": truncated}
        if args.task_id is not None:
            report["task_id"] = args.task_id
        # Emit the complete bounded evidence before optional submission so a transport failure is recoverable.
        print(json.dumps(report, ensure_ascii=True, sort_keys=True), flush=True)
        if origin:
            request = Request(origin + "/api/skill-runs", data=json.dumps(report).encode("utf-8"), headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST")
            with build_opener(NoRedirect()).open(request, timeout=15) as response:
                response_body = response.read(1024 * 1024 + 1)
                if len(response_body) > 1024 * 1024:
                    raise ValueError("submission response exceeds size limit")
                submitted = json.loads(response_body)
            print(json.dumps({"submitted_id": submitted["id"], "attestation": submitted["attestation"]}), file=sys.stderr)
        return 0 if outcome == "succeeded" else 1
    except (OSError, ValueError, TypeError, KeyError, HTTPError, URLError) as error:
        # Never include transport exception text, request headers or token values.
        message = "evidence submission failed; retain stdout report for retry" if isinstance(error, (HTTPError, URLError)) else str(error)
        print(json.dumps({"error": message}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
