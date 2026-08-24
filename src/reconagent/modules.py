"""Recon modules.

Every module is a pure function of (target, context) -> findings. Modules NEVER
touch the network directly; they receive a `Fetcher` from the executor, which is
the object that has already passed the scope gate. This is the structural
guarantee: a module physically cannot reach an unauthorised host, because the
only network handle it is given is scope-checked.
"""
from __future__ import annotations

import dataclasses
from typing import Protocol


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    target: str
    kind: str
    value: str


class Fetcher(Protocol):
    """A scope-checked network handle. The executor is the only thing that can
    construct one, and it refuses out-of-scope targets before returning."""
    def resolve(self, host: str) -> list[str]: ...
    def http_head(self, host: str) -> dict[str, str]: ...


class Module(Protocol):
    # Read-only: frozen dataclasses expose `name` as a read-only field, and a
    # Protocol with a *mutable* attribute would reject them under strict mypy.
    @property
    def name(self) -> str: ...
    def run(self, target: str, fetch: Fetcher) -> list[Finding]: ...


@dataclasses.dataclass(frozen=True, slots=True)
class DnsModule:
    name: str = "dns"

    def run(self, target: str, fetch: Fetcher) -> list[Finding]:
        return [Finding(target, "dns.a", addr) for addr in fetch.resolve(target)]


@dataclasses.dataclass(frozen=True, slots=True)
class HttpFingerprintModule:
    name: str = "http-fingerprint"

    def run(self, target: str, fetch: Fetcher) -> list[Finding]:
        headers = fetch.http_head(target)
        out: list[Finding] = []
        for h in ("server", "x-powered-by", "via"):
            if h in headers:
                out.append(Finding(target, f"http.{h}", headers[h]))
        return out


@dataclasses.dataclass(frozen=True, slots=True)
class SubdomainModule:
    """Derives candidate subdomains and yields only those that resolve. The
    candidates are checked against scope by the executor before any lookup."""
    name: str = "subdomains"
    wordlist: tuple[str, ...] = ("www", "api", "dev", "staging", "mail", "vpn")

    def run(self, target: str, fetch: Fetcher) -> list[Finding]:
        out: list[Finding] = []
        for sub in self.wordlist:
            candidate = f"{sub}.{target}"
            try:
                addrs = fetch.resolve(candidate)
            except Exception:  # noqa: BLE001 - scope refusal or resolution failure
                continue
            out.extend(Finding(candidate, "subdomain", a) for a in addrs)
        return out


def default_modules() -> tuple[Module, ...]:
    return (DnsModule(), HttpFingerprintModule(), SubdomainModule())
