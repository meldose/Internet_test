#!/usr/bin/env python3
"""Monitor internet connectivity loss from Linux or WSL.

This script focuses on internet availability instead of Wi-Fi association state.
It logs when external reachability is lost, whether the local gateway is still
reachable, whether DNS still works, and when connectivity is restored.

Examples:
    python3 internet_connection_monitor.py
    python3 internet_connection_monitor.py --interval 0.5
    python3 internet_connection_monitor.py --ping-target 1.1.1.1 --ping-target 8.8.8.8
"""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


LOG = logging.getLogger("internet_connection_monitor")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class Snapshot:
    timestamp: str
    iface: str
    operstate: str
    carrier: str
    ip_address: str
    gateway: str
    routes: list[str]
    gateway_ping_ok: bool | None
    gateway_ping_rtt_ms: float | None
    gateway_ping_error: str
    internet_targets: list[str]
    internet_ok: bool | None
    internet_target_successes: list[str]
    internet_errors: list[str]
    dns_target: str
    dns_ok: bool | None
    dns_addresses: list[str]
    dns_error: str


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run_command(argv: Iterable[str], timeout: float = 3.0) -> CommandResult:
    args = list(argv)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            argv=args,
            returncode=proc.returncode,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
        )
    except FileNotFoundError as exc:
        return CommandResult(args, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.strip() if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr.strip() if isinstance(exc.stderr, str) else ""
        return CommandResult(args, 124, stdout, stderr or "command timed out")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def detect_default_route_interface() -> str:
    text = read_text(Path("/proc/net/route"))
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 11:
            continue
        iface, destination, _, flags = parts[0], parts[1], parts[2], parts[3]
        if destination != "00000000":
            continue
        if not (int(flags, 16) & 0x2):
            continue
        return iface
    result = run_command(["ip", "route", "show", "default"])
    if result.ok:
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    raise SystemExit("No default route interface found. Pass one with --iface.")


def get_ipv4_address(iface: str) -> str:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", iface[:15].encode("utf-8"))
        response = fcntl.ioctl(sock.fileno(), 0x8915, request)
        return socket.inet_ntoa(response[20:24])
    except OSError:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def hex_ipv4_le_to_str(value: str) -> str:
    try:
        packed = struct.pack("<L", int(value, 16))
        return socket.inet_ntoa(packed)
    except OSError:
        return ""


def get_routes(iface: str) -> list[str]:
    text = read_text(Path("/proc/net/route"))
    routes: list[str] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 11:
            continue
        route_iface, destination_hex, gateway_hex, flags_hex, _, _, _, mask_hex = (
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
            parts[6],
            parts[7],
        )
        if route_iface != iface:
            continue
        flags = int(flags_hex, 16)
        destination = hex_ipv4_le_to_str(destination_hex)
        gateway = hex_ipv4_le_to_str(gateway_hex)
        mask = hex_ipv4_le_to_str(mask_hex)
        if destination == "0.0.0.0":
            routes.append(f"default via {gateway} dev {iface}")
        else:
            routes.append(f"{destination}/{mask} dev {iface} flags=0x{flags:x}")
    return routes


def get_default_gateway(routes: list[str]) -> str:
    for route in routes:
        if route.startswith("default via "):
            parts = route.split()
            if len(parts) >= 3:
                return parts[2]
    return ""


def ping_once(iface: str, target: str, timeout_seconds: float) -> tuple[bool | None, float | None, str]:
    if not target:
        return None, None, ""
    result = run_command(
        ["ping", "-n", "-c", "1", "-W", str(int(max(1.0, timeout_seconds))), "-I", iface, target],
        timeout=timeout_seconds + 1.0,
    )
    if result.ok:
        match = re.search(r"time=([0-9.]+)\s*ms", result.stdout)
        rtt = float(match.group(1)) if match else None
        return True, rtt, ""
    if result.stderr:
        error = result.stderr
    elif result.stdout:
        error = result.stdout.splitlines()[-1]
    else:
        error = f"ping exited with {result.returncode}"
    return False, None, error


def probe_gateway(iface: str, gateway: str, timeout_seconds: float) -> tuple[bool | None, float | None, str]:
    return ping_once(iface, gateway, timeout_seconds)


def probe_internet(
    iface: str,
    targets: list[str],
    timeout_seconds: float,
) -> tuple[bool | None, list[str], list[str]]:
    if not targets:
        return None, [], []
    successes: list[str] = []
    errors: list[str] = []
    for target in targets:
        ok, _rtt, error = ping_once(iface, target, timeout_seconds)
        if ok:
            successes.append(target)
        else:
            errors.append(f"{target}: {error}")
    return bool(successes), successes, errors


def probe_dns(target: str, timeout_seconds: float) -> tuple[bool | None, list[str], str]:
    if not target:
        return None, [], ""
    result = run_command(["getent", "ahostsv4", target], timeout=timeout_seconds)
    if result.ok and result.stdout:
        addresses: list[str] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            address = parts[0]
            if re.match(r"^[0-9.]+$", address) and address not in seen:
                seen.add(address)
                addresses.append(address)
        return True, addresses, ""
    if result.stderr:
        return False, [], result.stderr
    if result.stdout:
        return False, [], result.stdout.splitlines()[-1]
    return False, [], f"getent exited with {result.returncode}"


def take_snapshot(iface: str, targets: list[str], timeout_seconds: float, dns_target: str) -> Snapshot:
    routes = get_routes(iface)
    gateway = get_default_gateway(routes)
    gateway_ping_ok, gateway_ping_rtt_ms, gateway_ping_error = probe_gateway(iface, gateway, timeout_seconds)
    internet_ok, internet_target_successes, internet_errors = probe_internet(iface, targets, timeout_seconds)
    dns_ok, dns_addresses, dns_error = probe_dns(dns_target, timeout_seconds)

    return Snapshot(
        timestamp=utc_now(),
        iface=iface,
        operstate=read_text(Path("/sys/class/net") / iface / "operstate") or "unknown",
        carrier=read_text(Path("/sys/class/net") / iface / "carrier") or "unknown",
        ip_address=get_ipv4_address(iface),
        gateway=gateway,
        routes=routes,
        gateway_ping_ok=gateway_ping_ok,
        gateway_ping_rtt_ms=gateway_ping_rtt_ms,
        gateway_ping_error=gateway_ping_error,
        internet_targets=targets,
        internet_ok=internet_ok,
        internet_target_successes=internet_target_successes,
        internet_errors=internet_errors,
        dns_target=dns_target,
        dns_ok=dns_ok,
        dns_addresses=dns_addresses,
        dns_error=dns_error,
    )


def assess_loss(snapshot: Snapshot) -> tuple[bool, str, str]:
    if not snapshot.routes:
        return True, "routing", "Default route is missing"
    if not snapshot.ip_address:
        return True, "ip-address", "IPv4 address is missing"
    if snapshot.gateway and snapshot.gateway_ping_ok is False:
        return True, "gateway", f"Gateway {snapshot.gateway} is unreachable"
    if snapshot.internet_ok is False and snapshot.dns_ok is True:
        return True, "internet", "Internet reachability failed while DNS still works"
    if snapshot.internet_ok is False and snapshot.dns_ok is False:
        if snapshot.gateway and snapshot.gateway_ping_ok is True:
            return True, "internet-and-dns", "Gateway is reachable, but internet reachability and DNS both failed"
        return True, "reachability-and-dns", "Internet reachability and DNS both failed"
    return False, "ok", "Internet connectivity looks healthy"


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)


def write_json_event(jsonl_path: Path, payload: dict[str, Any]) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


def log_snapshot(prefix: str, snapshot: Snapshot) -> None:
    gateway_text = "disabled"
    if snapshot.gateway_ping_ok is True:
        gateway_text = f"ok target={snapshot.gateway} rtt_ms={snapshot.gateway_ping_rtt_ms}"
    elif snapshot.gateway_ping_ok is False:
        gateway_text = f"failed target={snapshot.gateway} error={snapshot.gateway_ping_error}"

    internet_text = "disabled"
    if snapshot.internet_ok is True:
        internet_text = f"ok successes={','.join(snapshot.internet_target_successes)}"
    elif snapshot.internet_ok is False:
        internet_text = f"failed errors={' | '.join(snapshot.internet_errors)}"

    dns_text = "disabled"
    if snapshot.dns_ok is True:
        dns_text = f"ok target={snapshot.dns_target} addresses={','.join(snapshot.dns_addresses)}"
    elif snapshot.dns_ok is False:
        dns_text = f"failed target={snapshot.dns_target} error={snapshot.dns_error}"

    LOG.info(
        "%s iface=%s ip=%r gateway=%r operstate=%r carrier=%r gateway_ping=%s internet=%s dns=%s",
        prefix,
        snapshot.iface,
        snapshot.ip_address,
        snapshot.gateway,
        snapshot.operstate,
        snapshot.carrier,
        gateway_text,
        internet_text,
        dns_text,
    )


def on_internet_lost(snapshot: Snapshot, previous_snapshot: Snapshot, jsonl_path: Path) -> None:
    scope_code, scope_summary = assess_loss(snapshot)
    LOG.warning("INTERNET CONNECTION LOST on %s", snapshot.iface)
    LOG.warning(
        "Loss time: current_snapshot=%s previous_healthy_snapshot=%s",
        snapshot.timestamp,
        previous_snapshot.timestamp,
    )
    LOG.warning("Loss scope: %s (%s)", scope_summary, scope_code)
    LOG.warning(
        "Current state: ip=%r gateway=%r operstate=%r carrier=%r gateway_ok=%s internet_ok=%s dns_ok=%s",
        snapshot.ip_address,
        snapshot.gateway,
        snapshot.operstate,
        snapshot.carrier,
        snapshot.gateway_ping_ok,
        snapshot.internet_ok,
        snapshot.dns_ok,
    )
    if snapshot.gateway:
        LOG.warning(
            "Gateway probe: target=%s ok=%s rtt_ms=%s error=%s",
            snapshot.gateway,
            snapshot.gateway_ping_ok,
            snapshot.gateway_ping_rtt_ms,
            snapshot.gateway_ping_error,
        )
    if snapshot.internet_errors:
        for error in snapshot.internet_errors:
            LOG.warning("Internet probe: %s", error)
    if snapshot.dns_ok is False:
        LOG.warning("DNS probe: target=%s error=%s", snapshot.dns_target, snapshot.dns_error)
    for route in snapshot.routes:
        LOG.warning("Route: %s", route)

    write_json_event(
        jsonl_path,
        {
            "event": "internet_lost",
            "timestamp": snapshot.timestamp,
            "iface": snapshot.iface,
            "loss_scope": scope_code,
            "loss_summary": scope_summary,
            "previous_snapshot": asdict(previous_snapshot),
            "current_snapshot": asdict(snapshot),
        },
    )


def on_internet_restored(snapshot: Snapshot, jsonl_path: Path) -> None:
    LOG.info(
        "INTERNET CONNECTION RESTORED iface=%s ip=%r gateway=%r successes=%s",
        snapshot.iface,
        snapshot.ip_address,
        snapshot.gateway,
        ",".join(snapshot.internet_target_successes),
    )
    write_json_event(
        jsonl_path,
        {
            "event": "internet_restored",
            "timestamp": snapshot.timestamp,
            "iface": snapshot.iface,
            "snapshot": asdict(snapshot),
        },
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor internet connection loss from Linux or WSL.")
    parser.add_argument("--iface", help="Interface name, for example eth0 or eth2.")
    parser.add_argument("--interval", type=positive_float, default=1.0, help="Polling interval in seconds. Default: 1.0")
    parser.add_argument(
        "--ping-target",
        action="append",
        default=None,
        help="External reachability target. Repeat to add more than one target.",
    )
    parser.add_argument("--ping-timeout", type=positive_float, default=1.0, help="Ping timeout in seconds. Default: 1.0")
    parser.add_argument("--dns-target", default="openai.com", help="DNS name to resolve. Default: openai.com")
    parser.add_argument("--output-dir", default=".", help="Directory for the .log and .jsonl outputs. Default: current directory")
    parser.add_argument("--prefix", default="internet_connection_monitor", help="Output filename prefix. Default: internet_connection_monitor")
    return parser


def sanitize_ping_targets(values: list[str] | None) -> list[str]:
    if not values:
        return ["1.1.1.1", "8.8.8.8"]
    return [value for value in values if value]


def main() -> int:
    args = build_arg_parser().parse_args()
    iface = args.iface or detect_default_route_interface()
    targets = sanitize_ping_targets(args.ping_target)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve()
    log_path = output_dir / f"{args.prefix}_{iface}_{timestamp}.log"
    jsonl_path = output_dir / f"{args.prefix}_{iface}_{timestamp}.jsonl"
    setup_logging(log_path)

    LOG.info("Starting internet connection monitor on iface=%s", iface)
    LOG.info("Text log: %s", log_path)
    LOG.info("JSONL log: %s", jsonl_path)
    LOG.info("Internet targets: %s", ", ".join(targets))
    LOG.info("DNS target: %s", args.dns_target)

    previous_snapshot: Snapshot | None = None
    loss_active = False
    loss_count = 0
    restore_count = 0

    try:
        while True:
            snapshot = take_snapshot(iface, targets, args.ping_timeout, args.dns_target)
            if previous_snapshot is None:
                log_snapshot("Initial snapshot:", snapshot)
                write_json_event(
                    jsonl_path,
                    {
                        "event": "startup",
                        "timestamp": snapshot.timestamp,
                        "iface": snapshot.iface,
                        "snapshot": asdict(snapshot),
                    },
                )
            else:
                lost_now, _scope_code, _scope_summary = assess_loss(snapshot)
                if not loss_active and lost_now:
                    loss_active = True
                    loss_count += 1
                    on_internet_lost(snapshot, previous_snapshot, jsonl_path)
                elif loss_active and not lost_now:
                    loss_active = False
                    restore_count += 1
                    on_internet_restored(snapshot, jsonl_path)

            previous_snapshot = snapshot
            time.sleep(args.interval)
    except KeyboardInterrupt:
        LOG.info("Received Ctrl+C, stopping monitor.")
    finally:
        if previous_snapshot is not None:
            write_json_event(
                jsonl_path,
                {
                    "event": "shutdown",
                    "timestamp": utc_now(),
                    "iface": iface,
                    "loss_count": loss_count,
                    "restore_count": restore_count,
                    "last_snapshot": asdict(previous_snapshot),
                },
            )
        LOG.info("Stopped internet connection monitor on %s. losses=%d restores=%d", iface, loss_count, restore_count)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
