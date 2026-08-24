"""The scope oracle: the single authority on what may be touched.

Supports exact hosts, wildcard subdomains, CIDR ranges, and explicit exclusions.
Exclusions always win — a target matching both an include and an exclude is out
of scope, because on a real engagement the exclusion is the thing someone asked
for in writing.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import re
from collections.abc import Iterable

_HOSTNAME = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


class ScopeViolation(Exception):
    """Raised when something attempts to act on an out-of-scope target.

    Deliberately not a subclass of ValueError: a scope violation must never be
    swallowed by a generic `except ValueError` somewhere in a module.
    """

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(f"out of scope: {target} ({reason})")
        self.target = target
        self.reason = reason


def normalise(target: str) -> str:
    """Canonical form for comparison. Lowercase, strip port, strip trailing dot."""
    t = target.strip().lower().rstrip(".")
    if t.startswith("http://"):
        t = t[7:]
    elif t.startswith("https://"):
        t = t[8:]
    t = t.split("/", 1)[0]
    # strip :port but keep IPv6 brackets intact
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            return t[: end + 1]
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        if port.isdigit():
            return host
    return t


@dataclasses.dataclass(frozen=True, slots=True)
class Rule:
    raw: str
    kind: str  # "host" | "wildcard" | "cidr"

    @classmethod
    def parse(cls, raw: str) -> Rule:
        r = raw.strip().lower().rstrip(".")
        if not r:
            raise ValueError("empty scope rule")
        if "/" in r:
            ipaddress.ip_network(r, strict=False)  # raises on malformed
            return cls(r, "cidr")
        if r.startswith("*."):
            rest = r[2:]
            if not _HOSTNAME.match(rest):
                raise ValueError(f"invalid wildcard rule: {raw!r}")
            return cls(r, "wildcard")
        try:
            ipaddress.ip_address(r)
        except ValueError:
            if not _HOSTNAME.match(r):
                raise ValueError(f"invalid scope rule: {raw!r}") from None
        return cls(r, "host")

    def matches(self, target: str) -> bool:
        t = normalise(target)
        if self.kind == "host":
            return t == self.raw
        if self.kind == "wildcard":
            # "*.example.com" covers any subdomain but NOT the apex. Bounty and
            # engagement scopes distinguish these, so list the apex explicitly
            # if it is in scope.
            suffix = self.raw[1:]          # ".example.com"
            return t.endswith(suffix)
        try:
            addr = ipaddress.ip_address(t.strip("[]"))
        except ValueError:
            return False
        return addr in ipaddress.ip_network(self.raw, strict=False)


@dataclasses.dataclass(frozen=True, slots=True)
class Scope:
    """An immutable authorisation boundary."""
    include: tuple[Rule, ...]
    exclude: tuple[Rule, ...] = ()
    authorisation_ref: str = ""

    @classmethod
    def build(cls, include: Iterable[str], exclude: Iterable[str] = (),
              authorisation_ref: str = "") -> Scope:
        inc = tuple(Rule.parse(r) for r in include)
        if not inc:
            raise ValueError("scope must include at least one rule")
        if not authorisation_ref:
            raise ValueError(
                "authorisation_ref is required: record the written authorisation "
                "(engagement id, bounty programme, or ticket) this scope derives from")
        return cls(inc, tuple(Rule.parse(r) for r in exclude), authorisation_ref)

    def check(self, target: str) -> None:
        """Raise ScopeViolation unless `target` is authorised."""
        t = normalise(target)
        if not t:
            raise ScopeViolation(target, "empty target")
        for rule in self.exclude:
            if rule.matches(t):
                raise ScopeViolation(t, f"matches exclusion {rule.raw!r}")
        for rule in self.include:
            if rule.matches(t):
                return
        raise ScopeViolation(t, "matches no inclusion rule")

    def permits(self, target: str) -> bool:
        try:
            self.check(target)
        except ScopeViolation:
            return False
        return True

    def describe(self) -> dict[str, object]:
        return {
            "authorisation_ref": self.authorisation_ref,
            "include": [r.raw for r in self.include],
            "exclude": [r.raw for r in self.exclude],
        }
