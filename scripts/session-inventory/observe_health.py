#!/usr/bin/env python3
"""Report one ordinary HTTP health check to ARTEX's authenticated observer inventory."""
import argparse
import ipaddress
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("URL must be HTTP(S) without credentials, query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artex-url", required=True, type=endpoint)
    parser.add_argument("--health-url", required=True, type=endpoint)
    parser.add_argument("--source", default="http-health-observer")
    parser.add_argument("--source-id")
    parser.add_argument("--kind", choices=("c2", "webshell"), default="c2", help="Inventory source label; does not select a command protocol")
    parser.add_argument("--task-id", type=int)
    parser.add_argument("--asset-id", type=int)
    parser.add_argument("--ttl", type=int, default=120)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    token = os.environ.get("ARTEX_OBSERVER_TOKEN", "").strip()
    if not token:
        parser.error("ARTEX_OBSERVER_TOKEN is required")
    if not 1 <= args.ttl <= 86400 or not 1 <= args.timeout <= 30:
        parser.error("ttl must be 1..86400 and timeout 1..30 seconds")
    if any(value is not None and value < 1 for value in (args.task_id, args.asset_id)):
        parser.error("task-id and asset-id must be positive")
    parsed = urlsplit(args.artex_url)
    if parsed.path not in ("", "/"):
        parser.error("artex-url must be a server origin")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not loopback:
        parser.error("artex-url must use HTTPS or loopback HTTP")
    opener = build_opener(NoRedirect())
    reason = ""
    try:
        with opener.open(Request(args.health_url, method="GET", headers={"User-Agent": "ARTEX-Inventory-Observer/1"}), timeout=args.timeout) as response:
            state = "connected" if 200 <= response.status < 300 else "disconnected"
            if state != "connected":
                reason = "Health endpoint HTTP " + str(response.status)
    except HTTPError as exc:
        state, reason = "disconnected", "Health endpoint HTTP " + str(exc.code)
        exc.close()
    except (URLError, TimeoutError, OSError):
        state, reason = "disconnected", "Health endpoint unavailable"
    observation = {
        "source": args.source,
        "source_id": args.source_id or args.health_url,
        "sequence": time.time_ns() // 1000,
        "kind": args.kind,
        "protocol_label": "http-health-observer",
        "state": state,
        "host": urlsplit(args.health_url).hostname,
        "url": args.health_url,
        "heartbeat_ttl_seconds": args.ttl,
        "disconnect_reason": reason,
    }
    if args.task_id is not None:
        observation["task_id"] = args.task_id
    if args.asset_id is not None:
        observation["asset_id"] = args.asset_id
    body = json.dumps(observation).encode("utf-8")
    request = Request(args.artex_url.rstrip("/") + "/api/session-inventory/observations", data=body, headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST")
    try:
        with opener.open(request, timeout=args.timeout) as response:
            result = json.loads(response.read(65537))
        session = result["session"]
        print(json.dumps({"id": session["id"], "state": session["effective_state"], "mode": session["mode"]}))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError):
        print(json.dumps({"error": "Inventory submission failed"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
