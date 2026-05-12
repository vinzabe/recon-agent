"""Scope enforcement.

Every host the agent acts on must pass :meth:`ScopeGuard.check`. The
default allowlist is:

- ``127.0.0.0/8`` (IPv4 loopback)
- ``::1`` (IPv6 loopback)
- ``localhost``
- ``scanme.nmap.org`` — Nmap's official test target.

Pass extra entries via the ``allowlist=`` constructor argument.
:meth:`ScopeGuard.check` raises :class:`ScopeViolation` when a target
is not allowed.

This guard is **defense in depth**: the LLM cannot bypass it because
both the planner and every tool runner consult the same guard.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


_DEFAULT_HOST_ALLOWLIST = (
    "localhost", "scanme.nmap.org",
)
_DEFAULT_NETWORK_ALLOWLIST = (
    "127.0.0.0/8", "::1/128",
)


class ScopeViolation(PermissionError):
    """Raised when a target is rejected by the scope guard."""


@dataclass
class ScopeGuard:
    allow_hosts: tuple[str, ...] = _DEFAULT_HOST_ALLOWLIST
    allow_networks: tuple[str, ...] = _DEFAULT_NETWORK_ALLOWLIST
    extra: tuple[str, ...] = field(default_factory=tuple)
    resolve: bool = False  # If True, attempt DNS resolution checks

    def __post_init__(self):
        self._networks = [ipaddress.ip_network(n)
                          for n in self.allow_networks]
        self._all_hosts = set(h.lower() for h in
                              tuple(self.allow_hosts) + self.extra)

    @staticmethod
    def _normalize(target: str) -> tuple[str, str | None]:
        """Return (host, port_or_none) for various inputs.

        Accepts URLs (https://x:443/path), bare hostnames/IPs,
        ``host:port`` and IPv6 in brackets.
        """
        t = target.strip()
        if t.lower().startswith(("http://", "https://", "ftp://")):
            u = urlparse(t)
            host = u.hostname or ""
            port = str(u.port) if u.port is not None else None
            return host.lower(), port
        # IPv6 in brackets, optional port
        if t.startswith("["):
            end = t.find("]")
            if end > 0:
                host = t[1:end]
                rest = t[end + 1:]
                port = (rest.lstrip(":") if rest.startswith(":")
                        else None)
                return host.lower(), port
        # IPv4 / hostname optional :port
        if t.count(":") == 1 and not t.replace(":", "").replace(
                ".", "").isalpha():
            host, port = t.rsplit(":", 1)
            return host.lower(), port
        return t.lower(), None

    def is_allowed(self, target: str) -> bool:
        try:
            self.check(target)
        except ScopeViolation:
            return False
        return True

    def check(self, target: str) -> str:
        """Return the normalised host part if allowed; raise otherwise."""
        if not target:
            raise ScopeViolation("empty target")
        host, _ = self._normalize(target)
        if not host:
            raise ScopeViolation(f"no host in target: {target!r}")
        if host in self._all_hosts:
            return host
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            for net in self._networks:
                if ip.version == net.version and ip in net:
                    return host
            raise ScopeViolation(
                f"IP {host} not in any allowed network "
                f"(allow={', '.join(self.allow_networks)})")
        if self.resolve:
            try:
                resolved = socket.gethostbyname(host)
                ip = ipaddress.ip_address(resolved)
                for net in self._networks:
                    if ip.version == net.version and ip in net:
                        return host
            except (socket.gaierror, ValueError):
                pass
        raise ScopeViolation(
            f"host {host!r} not in scope allowlist "
            f"(allow={', '.join(sorted(self._all_hosts))})")

    def filter(self, targets: Iterable[str]) -> list[str]:
        return [t for t in targets if self.is_allowed(t)]
