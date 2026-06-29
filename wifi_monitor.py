#!/usr/bin/env python3
"""Monitor Linux / WSL network connectivity and log disconnect evidence.

On native Linux with a real wireless adapter, the monitor records Wi-Fi
association details when available. Inside WSL, Linux usually only sees a
virtual Ethernet adapter, so the monitor falls back to the active routed
interface and logs WSL-visible network failures such as route loss, DNS
resolution failure, or host connectivity errors.

The monitor polls link state, IP state, optional ping reachability, optional
DNS resolution, and keeps a live buffer of recent NetworkManager /
wpa_supplicant / kernel log lines. Whenever connectivity drops, it writes a
human-readable report plus a JSONL event record with the most relevant evidence
it could gather.

Examples:
    ./wifi_monitor.py
    ./wifi_monitor.py --iface eth0
    ./wifi_monitor.py --ping-target 192.168.1.1 --ping-target 1.1.1.1
"""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Iterable


LOG = logging.getLogger("wifi_monitor")
WIFI_KEYWORDS = (
    "wifi",
    "wi-fi",
    "wlan",
    "wlp",
    "wsl",
    "wpa",
    "supplicant",
    "dhcp",
    "deauth",
    "disconnect",
    "carrier",
    "rfkill",
    "ssid",
    "nl80211",
    "getaddrinfo",
    "name resolution",
    "network is unreachable",
)

REASON_PATTERNS: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "ssid-not-found",
        "SSID not found or access point unavailable",
        ("ssid-not-found", "no network with ssid", "network not found"),
    ),
    (
        "authentication-failed",
        "Authentication or handshake failure",
        (
            "4-way handshake failed",
            "authentication failed",
            "wrong key",
            "pre-shared key may be incorrect",
            "no secrets were provided",
        ),
    ),
    (
        "dhcp-failed",
        "Wi-Fi associated but IP configuration failed",
        ("dhcp", "ip-config-unavailable", "failed to acquire", "lease", "timeout"),
    ),
    (
        "rfkill",
        "Wireless radio blocked by rfkill or hardware switch",
        ("rfkill", "radio killswitch", "blocked"),
    ),
    (
        "ap-deauth",
        "Disconnected by the access point",
        (
            "disconnected by ap",
            "deauthenticated",
            "deauthenticating",
            "ctrl-event-disconnected",
            "reason=",
        ),
    ),
    (
        "association-timeout",
        "Association or roaming timed out",
        ("association took too long", "timed out", "timeout", "roam"),
    ),
    (
        "driver-or-firmware",
        "Driver, firmware, or nl80211 error",
        ("firmware", "nl80211", "driver", "failed to initialize driver interface"),
    ),
    (
        "carrier-lost",
        "Kernel or NetworkManager reported carrier/link loss",
        ("carrier: link disconnected", "link is not ready", "link disconnected", "carrier lost"),
    ),
    (
        "dns-resolution-failed",
        "DNS resolution failed inside Linux / WSL",
        (
            "getaddrinfo() failed",
            "temporary failure in name resolution",
            "name or service not known",
            "could not resolve host",
            "dns",
        ),
    ),
    (
        "route-missing",
        "Default route missing or network unreachable",
        ("network is unreachable", "no route to host", "default route", "route"),
    ),
    (
        "wsl-host-network",
        "WSL host-side network problem surfaced inside Linux",
        ("wsl", "checkconnection"),
    ),
]


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
    mode: str
    iface: str
    operstate: str
    carrier: str
    connected: bool
    is_wireless: bool
    has_ip: bool
    ssid: str
    bssid: str
    wpa_state: str
    nm_state: str
    nm_connection: str
    ip_address: str
    gateway: str
    gateway_ping_ok: bool | None
    gateway_ping_rtt_ms: float | None
    gateway_ping_error: str
    dns_server: str
    wireless_link: str
    signal_level_dbm: str
    noise_level_dbm: str
    ping_target: str
    ping_ok: bool | None
    ping_rtt_ms: float | None
    ping_error: str
    dns_target: str
    dns_ok: bool | None
    dns_addresses: list[str]
    dns_error: str
    ip_brief: str
    routes: list[str]


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run_command(argv: Iterable[str], timeout: float = 4.0) -> CommandResult:
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
        return CommandResult(argv=args, returncode=127, stdout="", stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=args,
            returncode=124,
            stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            stderr=((exc.stderr or "").strip() if isinstance(exc.stderr, str) else "") or "command timed out",
        )


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def parse_nmcli_kv(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def parse_wpa_kv(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def parse_proc_net_wireless(iface: str) -> dict[str, str]:
    path = Path("/proc/net/wireless")
    text = read_text(path)
    if not text:
        return {}
    for line in text.splitlines()[2:]:
        raw = line.strip()
        if not raw or ":" not in raw:
            continue
        left, right = raw.split(":", 1)
        if left.strip() != iface:
            continue
        columns = right.split()
        if len(columns) < 5:
            return {}
        return {
            "link": columns[1].rstrip("."),
            "level": columns[2].rstrip("."),
            "noise": columns[3].rstrip("."),
        }
    return {}


def is_wsl() -> bool:
    osrelease = read_text(Path("/proc/sys/kernel/osrelease")).lower()
    version = read_text(Path("/proc/version")).lower()
    return (
        "microsoft" in osrelease
        or "wsl" in osrelease
        or "microsoft" in version
        or "wsl" in version
        or "WSL_INTEROP" in os.environ
    )


def is_wireless_interface(iface: str) -> bool:
    return (Path("/sys/class/net") / iface / "wireless").exists() or bool(parse_proc_net_wireless(iface))


def detect_wireless_interfaces() -> list[str]:
    found: list[str] = []
    sys_class_net = Path("/sys/class/net")
    for entry in sorted(sys_class_net.iterdir()):
        if (entry / "wireless").exists():
            found.append(entry.name)
    if found:
        return found

    text = read_text(Path("/proc/net/wireless"))
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        iface = line.split(":", 1)[0].strip()
        if iface:
            found.append(iface)
    if found:
        return found

    result = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"])
    if result.ok:
        for line in result.stdout.splitlines():
            device, _, dev_type = line.partition(":")
            if dev_type.strip().lower() == "wifi" and device.strip():
                found.append(device.strip())
    return sorted(set(found))


def detect_default_route_interface() -> str:
    path = Path("/proc/net/route")
    text = read_text(path)
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
                index = parts.index("dev")
                if index + 1 < len(parts):
                    return parts[index + 1]
    return ""


def detect_up_non_loopback_interfaces() -> list[str]:
    found: list[str] = []
    for entry in sorted(Path("/sys/class/net").iterdir()):
        iface = entry.name
        if iface == "lo":
            continue
        state = read_text(entry / "operstate").lower()
        if state in {"up", "unknown", "dormant"}:
            found.append(iface)
    return found


def pick_interface(explicit_iface: str | None) -> str:
    if explicit_iface:
        return explicit_iface
    wireless_ifaces = detect_wireless_interfaces()
    if wireless_ifaces:
        return wireless_ifaces[0]

    default_iface = detect_default_route_interface()
    if default_iface:
        return default_iface

    up_ifaces = detect_up_non_loopback_interfaces()
    if up_ifaces:
        return up_ifaces[0]

    raise SystemExit(
        "No usable network interface auto-detected. Pass one explicitly, for example: --iface eth0"
    )


def get_nmcli_details(iface: str) -> dict[str, str]:
    result = run_command(
        [
            "nmcli",
            "-t",
            "-f",
            "GENERAL.TYPE,GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY",
            "device",
            "show",
            iface,
        ]
    )
    return parse_nmcli_kv(result.stdout) if result.ok else {}


def get_wpa_details(iface: str) -> dict[str, str]:
    details = parse_wpa_kv(run_command(["wpa_cli", "-i", iface, "status"]).stdout)
    signal_poll = parse_wpa_kv(run_command(["wpa_cli", "-i", iface, "signal_poll"]).stdout)
    details.update(signal_poll)
    return details


def get_ip_brief(iface: str) -> str:
    address = get_ipv4_address(iface)
    operstate = read_text(Path("/sys/class/net") / iface / "operstate") or "unknown"
    if address:
        return f"{iface} {operstate.upper()} {address}"
    return f"{iface} {operstate.upper()}"


def get_routes(iface: str) -> list[str]:
    path = Path("/proc/net/route")
    text = read_text(path)
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


def hex_ipv4_le_to_str(value: str) -> str:
    try:
        packed = struct.pack("<L", int(value, 16))
        return socket.inet_ntoa(packed)
    except OSError:
        return ""


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


def get_resolv_nameserver() -> str:
    text = read_text(Path("/etc/resolv.conf"))
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver "):
            return line.split(None, 1)[1].strip()
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


def ping_probe(iface: str, targets: list[str], timeout_seconds: float) -> tuple[str, bool | None, float | None, str]:
    if not targets:
        return "", None, None, ""

    for target in targets:
        ok, rtt, error = ping_once(iface, target, timeout_seconds)
        if ok:
            return target, ok, rtt, ""
        last_error = error
    return targets[0], False, None, last_error


def gateway_probe(iface: str, gateway: str, timeout_seconds: float) -> tuple[bool | None, float | None, str]:
    return ping_once(iface, gateway, timeout_seconds)


def dns_probe(target: str, timeout_seconds: float) -> tuple[bool | None, list[str], str]:
    if not target:
        return None, [], ""

    result = run_command(["getent", "ahostsv4", target], timeout=timeout_seconds)
    if result.ok and result.stdout:
        addresses = []
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


def take_snapshot(iface: str, ping_targets: list[str], ping_timeout: float) -> Snapshot:
    nm_details = get_nmcli_details(iface)
    wpa_details = get_wpa_details(iface)
    wireless_stats = parse_proc_net_wireless(iface)
    ip_brief = get_ip_brief(iface)
    routes = get_routes(iface)
    ipv4_address = get_ipv4_address(iface)
    wireless = is_wireless_interface(iface)
    mode = "wsl-network" if is_wsl() and not wireless else ("native-wifi" if wireless else "linux-network")

    operstate = read_text(Path("/sys/class/net") / iface / "operstate") or "unknown"
    carrier = read_text(Path("/sys/class/net") / iface / "carrier") or "unknown"
    ip_address = (
        ipv4_address
        or wpa_details.get("ip_address")
        or nm_details.get("IP4.ADDRESS[1]", "")
        or nm_details.get("IP4.ADDRESS[0]", "")
    )
    gateway = nm_details.get("IP4.GATEWAY", "")
    if not gateway:
        for route in routes:
            if route.startswith("default via "):
                parts = route.split()
                if len(parts) >= 3:
                    gateway = parts[2]
                    break
    ssid = wpa_details.get("ssid", "")
    bssid = wpa_details.get("bssid", "")
    wpa_state = wpa_details.get("wpa_state", "")
    nm_state = nm_details.get("GENERAL.STATE", "")
    nm_connection = nm_details.get("GENERAL.CONNECTION", "")

    connected = False
    if wireless:
        if wpa_state:
            connected = wpa_state.upper() == "COMPLETED"
        elif nm_state:
            connected = "connected" in nm_state.lower()
        elif ssid:
            connected = True
        elif wireless_stats:
            connected = carrier == "1" and operstate in {"up", "unknown", "dormant"}
    else:
        connected = operstate in {"up", "unknown", "dormant"} and carrier != "0"

    has_ip = bool(ip_address)
    ping_target, ping_ok, ping_rtt_ms, ping_error = ping_probe(iface, ping_targets, ping_timeout)
    gateway_ping_ok, gateway_ping_rtt_ms, gateway_ping_error = gateway_probe(iface, gateway, ping_timeout)
    dns_target = "openai.com"
    dns_ok, dns_addresses, dns_error = dns_probe(dns_target, ping_timeout)
    dns_server = get_resolv_nameserver()

    return Snapshot(
        timestamp=utc_now(),
        mode=mode,
        iface=iface,
        operstate=operstate,
        carrier=carrier,
        connected=connected,
        is_wireless=wireless,
        has_ip=has_ip,
        ssid=ssid,
        bssid=bssid,
        wpa_state=wpa_state,
        nm_state=nm_state,
        nm_connection=nm_connection,
        ip_address=ip_address,
        gateway=gateway,
        gateway_ping_ok=gateway_ping_ok,
        gateway_ping_rtt_ms=gateway_ping_rtt_ms,
        gateway_ping_error=gateway_ping_error,
        dns_server=dns_server,
        wireless_link=wireless_stats.get("link", ""),
        signal_level_dbm=wireless_stats.get("level", ""),
        noise_level_dbm=wireless_stats.get("noise", ""),
        ping_target=ping_target,
        ping_ok=ping_ok,
        ping_rtt_ms=ping_rtt_ms,
        ping_error=ping_error,
        dns_target=dns_target,
        dns_ok=dns_ok,
        dns_addresses=dns_addresses,
        dns_error=dns_error,
        ip_brief=ip_brief,
        routes=routes,
    )


class JournalFollower:
    def __init__(self, max_lines: int) -> None:
        self._max_lines = max_lines
        self._lines: Deque[str] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen[str] | None = None

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                [
                    "journalctl",
                    "-f",
                    "-n",
                    "0",
                    "--no-pager",
                    "-o",
                    "short-iso",
                    "-u",
                    "NetworkManager",
                    "-u",
                    "wpa_supplicant",
                    "-k",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            LOG.warning("Journal follow disabled: %s", exc)
            return

        self._thread = threading.Thread(target=self._reader_loop, name="journal-follower", daemon=True)
        self._thread.start()

    def _reader_loop(self) -> None:
        assert self._proc is not None
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            cleaned = line.rstrip()
            if not cleaned:
                continue
            with self._lock:
                self._lines.append(cleaned)

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def recent_lines(self, iface: str, limit: int) -> list[str]:
        with self._lock:
            lines = list(self._lines)
        iface_lower = iface.lower()
        filtered = [
            line
            for line in lines
            if iface_lower in line.lower() or any(keyword in line.lower() for keyword in WIFI_KEYWORDS)
        ]
        source = filtered if filtered else lines
        return source[-limit:]


def infer_reason(lines: list[str]) -> tuple[str, str, str]:
    for line in reversed(lines):
        lowered = line.lower()
        for code, summary, patterns in REASON_PATTERNS:
            if any(pattern in lowered for pattern in patterns):
                return code, summary, line
    if lines:
        return "unknown", "Disconnect detected but no clear root cause matched", lines[-1]
    return "unknown", "Disconnect detected but no journal evidence was captured", ""


def infer_reason_from_snapshot(snapshot: Snapshot) -> tuple[str, str]:
    if not snapshot.routes:
        return "route-missing", "No route entries are present for the monitored interface"
    if not snapshot.has_ip:
        return "dhcp-failed", "Interface has no IPv4 address inside Linux / WSL"
    if snapshot.ping_ok is False and snapshot.dns_ok is False:
        return "wsl-host-network", "Both raw connectivity and DNS resolution failed inside Linux / WSL"
    if snapshot.ping_ok is True and snapshot.dns_ok is False:
        return "dns-resolution-failed", "Network is up but DNS resolution failed"
    if snapshot.ping_ok is False:
        return "carrier-lost", "Reachability probe failed while interface state still looked up"
    return "unknown", "No snapshot-based reason matched"


def snapshot_connection_loss(snapshot: Snapshot) -> tuple[bool, str, str, str]:
    if not snapshot.connected:
        reason_code, reason_summary = infer_reason_from_snapshot(snapshot)
        if snapshot.carrier == "0" or snapshot.operstate.lower() in {"down", "lowerlayerdown", "notpresent"}:
            return True, reason_code, reason_summary, "link"
        return True, reason_code, reason_summary, "association"
    if not snapshot.routes:
        return True, "route-missing", "Default route disappeared while the interface still looked up", "routing"
    if not snapshot.has_ip:
        return True, "dhcp-failed", "IPv4 address disappeared while the interface still looked up", "ip-address"
    if snapshot.ping_ok is False and snapshot.dns_ok is False:
        return True, "wsl-host-network", "Both ping reachability and DNS resolution failed", "reachability-and-dns"
    return False, "", "", ""


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
    ping_text = "disabled"
    if snapshot.ping_ok is True:
        ping_text = f"ok target={snapshot.ping_target} rtt_ms={snapshot.ping_rtt_ms}"
    elif snapshot.ping_ok is False:
        ping_text = f"failed target={snapshot.ping_target} error={snapshot.ping_error}"
    dns_text = "disabled"
    if snapshot.dns_ok is True:
        dns_text = f"ok target={snapshot.dns_target} addresses={','.join(snapshot.dns_addresses)}"
    elif snapshot.dns_ok is False:
        dns_text = f"failed target={snapshot.dns_target} error={snapshot.dns_error}"

    LOG.info(
        "%s mode=%s iface=%s connected=%s has_ip=%s ssid=%r wpa_state=%r nm_state=%r ip=%r gateway=%r gateway_ping=%s signal_dbm=%r ping=%s dns=%s",
        prefix,
        snapshot.mode,
        snapshot.iface,
        snapshot.connected,
        snapshot.has_ip,
        snapshot.ssid,
        snapshot.wpa_state,
        snapshot.nm_state,
        snapshot.ip_address,
        snapshot.gateway,
        gateway_text,
        snapshot.signal_level_dbm,
        ping_text,
        dns_text,
    )


def assess_connectivity_scope(snapshot: Snapshot) -> tuple[str, str]:
    if not snapshot.routes:
        return "routing", "Default route is missing"
    if not snapshot.has_ip:
        return "ip-address", "IPv4 address is missing"
    if snapshot.gateway and snapshot.gateway_ping_ok is False:
        return "gateway", f"Gateway {snapshot.gateway} is unreachable from {snapshot.iface}"
    if snapshot.ping_ok is False and snapshot.dns_ok is True:
        if snapshot.gateway and snapshot.gateway_ping_ok is True:
            return "internet", "Gateway is reachable and DNS works, but internet reachability failed"
        return "internet", "External internet reachability failed"
    if snapshot.ping_ok is False and snapshot.dns_ok is False:
        if snapshot.gateway and snapshot.gateway_ping_ok is True:
            return "internet-and-dns", "Gateway is reachable, but both internet reachability and DNS failed"
        return "reachability-and-dns", "Both internet reachability and DNS failed"
    return "unknown", "No connectivity scope matched"


def on_disconnect(
    snapshot: Snapshot,
    previous_snapshot: Snapshot,
    journal: JournalFollower,
    jsonl_path: Path,
    journal_context: int,
    event_name: str = "disconnect",
    headline: str = "DISCONNECT detected",
    reason_override: tuple[str, str] | None = None,
    loss_stage: str = "",
) -> None:
    recent = journal.recent_lines(snapshot.iface, journal_context)
    reason_code, reason_summary, matched_line = infer_reason(recent)
    if reason_code == "unknown":
        if reason_override is not None:
            reason_code, reason_summary = reason_override
        else:
            reason_code, reason_summary = infer_reason_from_snapshot(snapshot)

    LOG.warning("%s on %s", headline, snapshot.iface)
    LOG.warning(
        "Loss time: current_snapshot=%s previous_healthy_snapshot=%s",
        snapshot.timestamp,
        previous_snapshot.timestamp,
    )
    if loss_stage:
        LOG.warning("Loss point: %s", loss_stage)
    LOG.warning(
        "Previous state: connected=%s ssid=%r ip=%r ping_ok=%s dns_ok=%s",
        previous_snapshot.connected,
        previous_snapshot.ssid,
        previous_snapshot.ip_address,
        previous_snapshot.ping_ok,
        previous_snapshot.dns_ok,
    )
    LOG.warning(
        "Current state: connected=%s ssid=%r ip=%r operstate=%r carrier=%r ping_ok=%s dns_ok=%s",
        snapshot.connected,
        snapshot.ssid,
        snapshot.ip_address,
        snapshot.operstate,
        snapshot.carrier,
        snapshot.ping_ok,
        snapshot.dns_ok,
    )
    if snapshot.connected:
        LOG.warning(
            "Interface still reports link up, but usable connectivity was lost on %s",
            snapshot.iface,
        )
    LOG.warning("Inferred reason: %s (%s)", reason_summary, reason_code)
    if matched_line:
        LOG.warning("Matched log line: %s", matched_line)
    if snapshot.ip_brief:
        LOG.warning("ip -brief: %s", snapshot.ip_brief)
    if snapshot.dns_server:
        LOG.warning("dns server: %s", snapshot.dns_server)
    if snapshot.dns_ok is False:
        LOG.warning("dns probe: target=%s error=%s", snapshot.dns_target, snapshot.dns_error)
    if snapshot.gateway:
        LOG.warning(
            "gateway probe: target=%s ok=%s rtt_ms=%s error=%s",
            snapshot.gateway,
            snapshot.gateway_ping_ok,
            snapshot.gateway_ping_rtt_ms,
            snapshot.gateway_ping_error,
        )
    scope_code, scope_summary = assess_connectivity_scope(snapshot)
    LOG.warning("Connectivity scope: %s (%s)", scope_summary, scope_code)
    for route in snapshot.routes:
        LOG.warning("route: %s", route)
    if recent:
        LOG.warning("Recent journal lines around disconnect:")
        for line in recent:
            LOG.warning("journal: %s", line)

    write_json_event(
        jsonl_path,
        {
            "event": event_name,
            "timestamp": snapshot.timestamp,
            "iface": snapshot.iface,
            "loss_stage": loss_stage,
            "reason_code": reason_code,
            "reason_summary": reason_summary,
            "matched_line": matched_line,
            "previous_snapshot": asdict(previous_snapshot),
            "current_snapshot": asdict(snapshot),
            "recent_journal": recent,
        },
    )


def on_reconnect(snapshot: Snapshot, jsonl_path: Path) -> None:
    LOG.info(
        "RECONNECTED iface=%s ip=%r gateway=%r signal_dbm=%r",
        snapshot.iface,
        snapshot.ip_address,
        snapshot.gateway,
        snapshot.signal_level_dbm,
    )
    write_json_event(
        jsonl_path,
        {
            "event": "reconnect",
            "timestamp": snapshot.timestamp,
            "iface": snapshot.iface,
            "snapshot": asdict(snapshot),
        },
    )


def on_probe_failure(snapshot: Snapshot, previous_snapshot: Snapshot, jsonl_path: Path) -> None:
    LOG.warning(
        "CONNECTIVITY probe failed while interface still appears connected: iface=%s target=%s error=%s",
        snapshot.iface,
        snapshot.ping_target,
        snapshot.ping_error,
    )
    LOG.warning(
        "Loss time: current_snapshot=%s previous_healthy_snapshot=%s",
        snapshot.timestamp,
        previous_snapshot.timestamp,
    )
    LOG.warning("Loss point: reachability")
    LOG.warning(
        "Current state: ip=%r gateway=%r operstate=%r carrier=%r ping_ok=%s dns_ok=%s",
        snapshot.ip_address,
        snapshot.gateway,
        snapshot.operstate,
        snapshot.carrier,
        snapshot.ping_ok,
        snapshot.dns_ok,
    )
    if snapshot.gateway:
        LOG.warning(
            "gateway probe: target=%s ok=%s rtt_ms=%s error=%s",
            snapshot.gateway,
            snapshot.gateway_ping_ok,
            snapshot.gateway_ping_rtt_ms,
            snapshot.gateway_ping_error,
        )
    if snapshot.dns_ok is False:
        LOG.warning("dns probe: target=%s error=%s", snapshot.dns_target, snapshot.dns_error)
    scope_code, scope_summary = assess_connectivity_scope(snapshot)
    LOG.warning("Connectivity scope: %s (%s)", scope_summary, scope_code)
    for route in snapshot.routes:
        LOG.warning("route: %s", route)
    write_json_event(
        jsonl_path,
        {
            "event": "probe_failure",
            "timestamp": snapshot.timestamp,
            "iface": snapshot.iface,
            "loss_stage": "reachability",
            "previous_snapshot": asdict(previous_snapshot),
            "snapshot": asdict(snapshot),
        },
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor native Linux or WSL network disconnects and log likely causes.")
    parser.add_argument("--iface", help="Interface name, for example wlan0, wlp2s0, eth0, or eth2.")
    parser.add_argument("--interval", type=positive_float, default=2.0, help="Polling interval in seconds. Default: 2.0")
    parser.add_argument(
        "--ping-target",
        action="append",
        default=None,
        help="Optional reachability probe target. Repeat to add more than one target. Pass --ping-target '' to disable.",
    )
    parser.add_argument("--ping-timeout", type=positive_float, default=1.0, help="Ping timeout in seconds. Default: 1.0")
    parser.add_argument("--journal-buffer-size", type=int, default=500, help="How many live journal lines to retain. Default: 500")
    parser.add_argument("--journal-context", type=int, default=40, help="How many recent journal lines to attach to a disconnect event. Default: 40")
    parser.add_argument("--output-dir", default=".", help="Directory for the .log and .jsonl outputs. Default: current directory")
    parser.add_argument("--prefix", default="wifi_monitor", help="Output filename prefix. Default: wifi_monitor")
    return parser


def sanitize_ping_targets(values: list[str] | None) -> list[str]:
    if not values:
        return ["1.1.1.1"]
    return [value for value in values if value]


def main() -> int:
    args = build_arg_parser().parse_args()
    iface = pick_interface(args.iface)
    ping_targets = sanitize_ping_targets(args.ping_target)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve()
    log_path = output_dir / f"{args.prefix}_{iface}_{timestamp}.log"
    jsonl_path = output_dir / f"{args.prefix}_{iface}_{timestamp}.jsonl"
    setup_logging(log_path)

    journal = JournalFollower(max_lines=max(50, args.journal_buffer_size))
    journal.start()

    stop_event = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("Received signal %s, stopping monitor.", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    LOG.info("Starting network monitor on iface=%s", iface)
    LOG.info("Environment mode: %s", "WSL" if is_wsl() else "native Linux")
    LOG.info("Text log: %s", log_path)
    LOG.info("JSONL log: %s", jsonl_path)
    if ping_targets:
        LOG.info("Ping targets: %s", ", ".join(ping_targets))
    else:
        LOG.info("Ping probe disabled.")

    previous_snapshot: Snapshot | None = None
    disconnect_count = 0
    reconnect_count = 0
    connection_loss_active = False
    probe_failure_active = False

    try:
        while not stop_event.is_set():
            snapshot = take_snapshot(iface, ping_targets, args.ping_timeout)
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
                loss_active_now, loss_reason_code, loss_reason_summary, loss_stage = snapshot_connection_loss(snapshot)
                if not connection_loss_active and loss_active_now:
                    connection_loss_active = True
                    disconnect_count += 1
                    event_name = "disconnect" if not snapshot.connected else "connection_lost"
                    headline = "DISCONNECT detected" if not snapshot.connected else "CONNECTION LOST detected"
                    on_disconnect(
                        snapshot,
                        previous_snapshot,
                        journal,
                        jsonl_path,
                        args.journal_context,
                        event_name=event_name,
                        headline=headline,
                        reason_override=(loss_reason_code, loss_reason_summary),
                        loss_stage=loss_stage,
                    )
                elif connection_loss_active and not loss_active_now:
                    connection_loss_active = False
                    reconnect_count += 1
                    on_reconnect(snapshot, jsonl_path)

                if not loss_active_now and snapshot.connected and snapshot.ping_ok is False and not probe_failure_active:
                    probe_failure_active = True
                    on_probe_failure(snapshot, previous_snapshot, jsonl_path)
                elif loss_active_now or snapshot.ping_ok in {True, None}:
                    probe_failure_active = False

            previous_snapshot = snapshot
            stop_event.wait(args.interval)
    finally:
        journal.stop()
        if previous_snapshot is not None:
            write_json_event(
                jsonl_path,
                {
                    "event": "shutdown",
                    "timestamp": utc_now(),
                    "iface": iface,
                    "disconnect_count": disconnect_count,
                    "reconnect_count": reconnect_count,
                    "last_snapshot": asdict(previous_snapshot),
                },
            )
        LOG.info(
            "Stopped network monitor on %s. disconnects=%d reconnects=%d",
            iface,
            disconnect_count,
            reconnect_count,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
