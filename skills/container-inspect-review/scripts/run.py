"""Review isolation controls in saved Docker container-inspect JSON offline."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 1000 or any(not isinstance(item, str) or len(item) > 8192 for item in value):
        raise ValueError(field + " must be a bounded string array or null")
    return value


def review(data):
    if not isinstance(data, list) or not 1 <= len(data) <= 1000:
        raise ValueError("input must be a container inspect array of 1 to 1000 objects")
    containers = []
    for index, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("Config"), dict) or not isinstance(item.get("HostConfig"), dict):
            raise ValueError("container requires Config and HostConfig objects at index " + str(index))
        config, host = item["Config"], item["HostConfig"]
        user = config.get("User")
        if user is not None and (not isinstance(user, str) or len(user) > 1024):
            raise ValueError("Config.User must be a bounded string or absent")
        for field in ("Privileged", "ReadonlyRootfs"):
            if field in host and type(host[field]) is not bool:
                raise ValueError("HostConfig." + field + " must be boolean")
        for field in ("NetworkMode", "PidMode"):
            if field in host and (not isinstance(host[field], str) or len(host[field]) > 1024):
                raise ValueError("HostConfig." + field + " must be a bounded string")
        caps = string_list(host.get("CapAdd"), "CapAdd")
        options = string_list(host.get("SecurityOpt"), "SecurityOpt")
        mounts = item.get("Mounts")
        if not isinstance(mounts, list) or len(mounts) > 10000:
            raise ValueError("Mounts must be an array of at most 10000 objects")
        writable, socket_mount = 0, False
        for mount in mounts:
            if not isinstance(mount, dict) or type(mount.get("RW")) is not bool or not isinstance(mount.get("Source"), str) or not isinstance(mount.get("Destination"), str):
                raise ValueError("mount requires Source, Destination and boolean RW")
            writable += int(mount["RW"])
            socket_mount |= mount["Source"].rstrip("/") in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock")
        issues, unknown = [], []
        if host.get("Privileged"):
            issues.append("privileged")
        if user is not None and user.split(":", 1)[0] in ("", "0", "root"):
            issues.append("root_or_unspecified_user")
        if host.get("ReadonlyRootfs") is False:
            issues.append("writable_rootfs")
        if host.get("NetworkMode") == "host":
            issues.append("host_network")
        if host.get("PidMode") == "host":
            issues.append("host_pid_namespace")
        if any(cap.upper().removeprefix("CAP_") in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE") for cap in caps):
            issues.append("broad_added_capability")
        if "seccomp=unconfined" in options or "seccomp:unconfined" in options:
            issues.append("seccomp_unconfined")
        if not any(option in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true") for option in options):
            issues.append("no_new_privileges_not_set")
        if socket_mount:
            issues.append("engine_socket_mounted")
        if "User" not in config:
            unknown.append("Config.User")
        unknown.extend("HostConfig." + field for field in ("Privileged", "ReadonlyRootfs", "NetworkMode", "PidMode") if field not in host)
        containers.append({"container_index": index, "issues": issues, "unknown_checks": unknown, "writable_mount_count": writable, "mount_count": len(mounts)})
    return {"containers": containers, "scope": "saved Docker inspect isolation subset; no environment, commands, identity or host paths are output; daemon/rootless/host policy and runtime behavior are not verified"}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("input exceeds 8 MiB")
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
