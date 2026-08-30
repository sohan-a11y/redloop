"""RECOIL-v1 scope gate.

Single canonicalizing allowlist resolver. Every destination is resolved
and re-resolved at send time, and any byte is refused for addresses
outside the allowlist (loopback, RFC1918, operator --lab-cidr).
The mutation engine is structurally incapable of altering the target
host: it only changes payload / encoding / vector family.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import uuid
from dataclasses import dataclass, field
from typing import Iterable

LOOPBACK4 = ipaddress.ip_network("127.0.0.0/8")
LOOPBACK6 = ipaddress.ip_network("::1/128")
RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


@dataclass
class Allowlist:
    networks: list[ipaddress._BaseNetwork] = field(
        default_factory=lambda: [LOOPBACK4, LOOPBACK6, *RFC1918]
    )

    def add_cidr(self, cidr: str) -> None:
        self.networks.append(ipaddress.ip_network(cidr, strict=False))

    def allows(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def canonicalize(host: str, allow: Allowlist) -> str:
    """Resolve host, require every address to be in-allowlist, return it."""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if _is_ip(host):
        addrs = [host]
    else:
        addrs = _resolve(host)
    if not addrs:
        raise ValueError(f"cannot resolve {host!r}")
    for a in addrs:
        if not allow.allows(a):
            raise ValueError(
                f"target {a!r} for {host!r} is OUT of allowlist - hard refuse"
            )
    primary = sorted(addrs, key=lambda x: 1 if ":" in x else 0)[0]
    if ":" in primary and primary != "127.0.0.1":
        primary = "::1"
    return primary


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def bounce(host: str, allow: Allowlist) -> str:
    """Re-resolve at every send (anti DNS-rebinding) and re-validate."""
    return canonicalize(host, allow)


def engage(confirm_lab: bool, allow: Allowlist, extra_cidrs: Iterable[str] = ()) -> str:
    for c in extra_cidrs:
        allow.add_cidr(c)
    lab_uuid = uuid.uuid4().hex[:12]
    print(
        "[!] LAB ENGAGEMENT ONLY. Targets must be operator-owned fixtures in scope\n"
        f"[!] allowlist={[str(n) for n in allow.networks]} lab-uuid={lab_uuid}"
    )
    if not confirm_lab:
        print("[!] refusing to run without --confirm-lab")
        sys.exit(2)
    return lab_uuid


def host_banner(host: str, port: int, allow: Allowlist) -> None:
    ip = canonicalize(host, allow)
    print(f"[!] target {host}:{port} -> canonical {ip} (in allowlist)")