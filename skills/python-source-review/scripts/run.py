"""Inventory one saved Python source file and mark AST sites for manual review."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys


MAX_BYTES = 1024 * 1024
MAX_NODES = 25000
MAX_ENTRIES = 1000


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def callee_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def location(node):
    return {"line": node.lineno, "column": node.col_offset}


def review(raw):
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("source must be UTF-8 encoded") from None
    try:
        tree = ast.parse(source, filename="saved-source.py")
    except SyntaxError as error:
        raise ValueError("invalid Python syntax at line " + str(error.lineno or 0)) from None
    functions, imports, sites = [], [], []
    nodes = calls = 0
    for node in ast.walk(tree):
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError("source exceeds 25000 AST nodes")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append({"name": node.name, "async": isinstance(node, ast.AsyncFunctionDef), **location(node)})
        elif isinstance(node, ast.Import):
            imports.append({"module": ",".join(item.name for item in node.names), "names": [{"name": item.name, "alias": item.asname} for item in node.names], "relative_level": 0, **location(node)})
        elif isinstance(node, ast.ImportFrom):
            imports.append({"module": node.module or "", "names": [{"name": item.name, "alias": item.asname} for item in node.names], "relative_level": node.level, **location(node)})
        elif isinstance(node, ast.Call):
            calls += 1
            callee = callee_name(node.func)
            checks = []
            if callee in ("eval", "builtins.eval"):
                checks.append("dynamic_evaluation")
            if callee in ("exec", "builtins.exec"):
                checks.append("dynamic_execution")
            if callee is not None and callee.startswith("subprocess."):
                checks.append("subprocess_invocation")
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                checks.append("shell_enabled")
            if checks:
                sites.append({"callee": callee, "checks": checks, **location(node)})
        if max(len(functions), len(imports), len(sites)) > MAX_ENTRIES:
            raise ValueError("source exceeds 1000 report entries in one section")
    for entries in (functions, imports, sites):
        entries.sort(key=lambda entry: (entry["line"], entry["column"]))
    return {
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "input_bytes": len(raw),
        "counts": {"functions": len(functions), "imports": len(imports), "calls": calls, "review_sites": len(sites)},
        "functions": functions,
        "imports": imports,
        "review_sites": sites,
        "scope": "AST inventory and manual review locations only; literal call names are not resolved to runtime bindings and do not establish vulnerabilities",
        "column_unit": "zero-based UTF-8 byte offset",
    }


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--input", "-input", dest="input_option", type=Path)
    args = parser.parse_args()
    if (args.input is None) == (args.input_option is None):
        parser.error("supply one input path, positionally or with --input")
    path = args.input if args.input is not None else args.input_option
    try:
        if not path.is_file():
            raise ValueError("input must be a readable regular file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 1 MiB")
        result = review(raw)
        print(json.dumps(result, sort_keys=True))
        return 0
    except OSError:
        message = "input file could not be read"
    except (RecursionError, MemoryError):
        message = "source exceeds parser complexity limits"
    except ValueError as error:
        message = str(error)
    print(json.dumps({"error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
