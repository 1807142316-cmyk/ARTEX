"""Produce a deterministic local evidence inventory with SHA-256 digests."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

MAX_FILES = 10000
MAX_BYTES = 1024 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.directory.is_symlink() or not args.directory.is_dir():
            raise ValueError("input must be an existing directory without a symlink root")
        root = args.directory.resolve()
        files, skipped = [], []
        total = 0
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append(relative)
                continue
            if not path.resolve().is_relative_to(root):
                skipped.append(relative)
                continue
            if not path.is_file():
                continue
            if len(files) >= MAX_FILES:
                raise ValueError("inventory exceeds 10000 files")
            size = path.stat().st_size
            total += size
            if total > MAX_BYTES:
                raise ValueError("inventory exceeds 1 GiB")
            digest = hashlib.sha256()
            read_bytes = 0
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    read_bytes += len(chunk)
                    if read_bytes > size:
                        raise ValueError("evidence changed while reading: " + relative)
                    digest.update(chunk)
            if read_bytes != size:
                raise ValueError("evidence changed while reading: " + relative)
            files.append({"path": relative, "bytes": size, "sha256": digest.hexdigest()})
        print(json.dumps({"files": files, "total_bytes": total, "skipped_symlinks": skipped}, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
