"""Parse network connections directly from /proc/net (no external tools).

Reading /proc/net/tcp{,6} lets us list listening ports and established
connections without shelling out to `ss`/`netstat`. This keeps the tool
dependency-free and portable across Linux systems.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# TCP state codes used in /proc/net/tcp (hex strings).
TCP_LISTEN = "0A"
TCP_ESTABLISHED = "01"

_STATE_NAMES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass
class Connection:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int


def _decode_addr(token: str, ipv6: bool) -> tuple[str, int]:
    addr_hex, port_hex = token.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(addr_hex)
    if ipv6:
        # /proc stores IPv6 as 4 little-endian 32-bit words.
        words = struct.unpack("<4I", raw)
        packed = struct.pack(">4I", *words)
        ip = socket.inet_ntop(socket.AF_INET6, packed)
    else:
        # IPv4 is a single little-endian 32-bit word, e.g. 127.0.0.1 is
        # stored as "0100007F". Packing the integer little-endian yields the
        # dotted-quad bytes in the right order for inet_ntoa.
        ip = socket.inet_ntoa(struct.pack("<I", int(addr_hex, 16)))
    return ip, port


def _parse_file(path: str, proto: str, ipv6: bool) -> list[Connection]:
    conns: list[Connection] = []
    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except OSError:
        return conns

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_ip, local_port = _decode_addr(parts[1], ipv6)
            remote_ip, remote_port = _decode_addr(parts[2], ipv6)
            state = _STATE_NAMES.get(parts[3].upper(), parts[3])
            inode = int(parts[9])
        except (ValueError, IndexError):
            continue
        conns.append(
            Connection(
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                inode=inode,
            )
        )
    return conns


def all_connections() -> list[Connection]:
    conns: list[Connection] = []
    conns += _parse_file("/proc/net/tcp", "tcp", ipv6=False)
    conns += _parse_file("/proc/net/tcp6", "tcp6", ipv6=True)
    conns += _parse_file("/proc/net/udp", "udp", ipv6=False)
    conns += _parse_file("/proc/net/udp6", "udp6", ipv6=True)
    return conns


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::")
