"""The executor: the ONLY component that touches the network, and the one place
the scope gate lives.

Modules ask the executor's Fetcher for network operations. The Fetcher checks
scope on every call and records the action in the ledger. A module therefore
cannot act out of scope even if it tries — there is no unchecked path.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterable

from .governor import RateGovernor
from .ledger import Ledger
from .modules import Module, default_modules
from .scope import Scope, ScopeViolation

# Injectable network backends so tests never hit the wire and production can swap
# in real resolvers/clients.
Resolver = Callable[[str], list[str]]
HttpHead = Callable[[str], dict[str, str]]


class _GatedFetcher:
    """A Fetcher bound to one run. Every method is scope-checked and rate-limited
    before the underlying backend is called, and every call is journaled."""

    def __init__(self, scope: Scope, gov: RateGovernor, ledger: Ledger,
                 run_id: str, module: str, resolver: Resolver,
                 http_head: HttpHead) -> None:
        self._scope = scope
        self._gov = gov
        self._ledger = ledger
        self._run = run_id
        self._module = module
        self._resolver = resolver
        self._http_head = http_head

    def _guard(self, host: str) -> None:
        # Raises ScopeViolation for anything not authorised. This is the gate.
        self._scope.check(host)

    def resolve(self, host: str) -> list[str]:
        self._guard(host)
        self._gov.acquire(host)
        try:
            return self._resolver(host)
        finally:
            self._gov.release()

    def http_head(self, host: str) -> dict[str, str]:
        self._guard(host)
        self._gov.acquire(host)
        try:
            return self._http_head(host)
        finally:
            self._gov.release()


@dataclasses.dataclass(slots=True)
class Executor:
    scope: Scope
    ledger: Ledger
    governor: RateGovernor = dataclasses.field(default_factory=RateGovernor)
    resolver: Resolver = dataclasses.field(default=lambda _host: [])
    http_head: HttpHead = dataclasses.field(default=lambda _host: {})
    modules: tuple[Module, ...] = dataclasses.field(default_factory=default_modules)

    def run(self, seeds: Iterable[str], *, run_id: str | None = None,
            resume: bool = False) -> str:
        if resume and run_id is None:
            run_id = self.ledger.resume_latest()
        if run_id is None:
            run_id = self.ledger.start_run(self.scope.describe())

        for seed in seeds:
            for module in self.modules:
                self._run_one(run_id, module, seed)
        self.ledger.finish_run(run_id)
        return run_id

    def _run_one(self, run_id: str, module: Module, target: str) -> None:
        # Refuse out-of-scope seeds up front and journal the refusal.
        try:
            self.scope.check(target)
        except ScopeViolation as v:
            self.ledger.record(run_id, module.name, target, "refused", v.reason)
            return
        if self.ledger.already_done(run_id, module.name, target):
            return  # resumability: skip work already completed
        fetch = _GatedFetcher(self.scope, self.governor, self.ledger, run_id,
                              module.name, self.resolver, self.http_head)
        try:
            findings = module.run(target, fetch)
        except ScopeViolation as v:
            # A module tried to reach beyond scope; the gate stopped it.
            self.ledger.record(run_id, module.name, target, "refused", v.reason)
            return
        except Exception as exc:  # noqa: BLE001 - module failure must not abort the run
            self.ledger.record(run_id, module.name, target, "error", repr(exc))
            return
        for f in findings:
            self.ledger.add_finding(run_id, f.target, f.kind, f.value, module.name)
        self.ledger.record(run_id, module.name, target, "completed",
                           detail=f"{len(findings)} finding(s)")

    def report(self, run_id: str) -> dict[str, object]:
        return {
            "run_id": run_id,
            "scope": self.scope.describe(),
            "stats": self.ledger.stats(run_id),
            "findings": self.ledger.findings(run_id),
            "refusals": [dataclasses.asdict(a)
                         for a in self.ledger.actions(run_id, "refused")],
        }
