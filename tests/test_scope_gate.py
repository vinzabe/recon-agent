"""The central guarantee: a module CANNOT act outside scope, even a malicious one.

These are the tests that make the whole design credible. If any of them fail, the
tool is unsafe to run on a real engagement regardless of how nice its output is.
"""
from __future__ import annotations

import dataclasses

import pytest

from reconagent.executor import Executor
from reconagent.ledger import Ledger
from reconagent.modules import Fetcher, Finding
from reconagent.scope import ScopeViolation


@dataclasses.dataclass(frozen=True, slots=True)
class MaliciousModule:
    """A module that deliberately tries to reach an out-of-scope host."""
    name: str = "malicious"
    target_to_hit: str = "victim.evil.com"

    def run(self, target: str, fetch: Fetcher) -> list[Finding]:
        # This is the attack: ignore `target`, go straight for something else.
        addrs = fetch.resolve(self.target_to_hit)
        return [Finding(self.target_to_hit, "pwned", a) for a in addrs]


@dataclasses.dataclass(frozen=True, slots=True)
class ExcludedTargetModule:
    name: str = "hits-excluded"

    def run(self, target: str, fetch: Fetcher) -> list[Finding]:
        # secret.example.com resolves and matches the include wildcard, but is
        # explicitly excluded. The gate must still refuse it.
        fetch.resolve("secret.example.com")
        return []


def _exec(tmp_path, scope, resolver, gov, modules):
    led = Ledger(tmp_path / "l.db")
    return Executor(scope=scope, ledger=led, governor=gov,
                    resolver=resolver, http_head=lambda h: {},
                    modules=modules), led


def test_malicious_module_cannot_escape_scope(tmp_path, scope, resolver,
                                              instant_governor):
    ex, led = _exec(tmp_path, scope, resolver, instant_governor,
                    (MaliciousModule(),))
    reached: list[str] = []
    ex.resolver = lambda h: (reached.append(h), resolver(h))[1]
    ex.run(["example.com"])
    led.close()
    assert "victim.evil.com" not in reached, "GATE BREACH: reached out-of-scope host"


def test_out_of_scope_attempt_is_recorded_as_refused(tmp_path, scope, resolver,
                                                     instant_governor):
    ex, led = _exec(tmp_path, scope, resolver, instant_governor,
                    (MaliciousModule(),))
    rid = ex.run(["example.com"])
    refusals = [a.target for a in led.actions(rid, "refused")]
    led.close()
    assert "example.com" in refusals  # the module raised on victim -> whole action refused


def test_excluded_target_refused_even_though_it_resolves(tmp_path, scope,
                                                        resolver, instant_governor):
    ex, led = _exec(tmp_path, scope, resolver, instant_governor,
                    (ExcludedTargetModule(),))
    reached: list[str] = []
    ex.resolver = lambda h: (reached.append(h), resolver(h))[1]
    ex.run(["example.com"])
    led.close()
    assert "secret.example.com" not in reached


def test_out_of_scope_seed_never_runs_a_module(tmp_path, scope, resolver,
                                               instant_governor):
    from reconagent.modules import DnsModule
    ex, led = _exec(tmp_path, scope, resolver, instant_governor, (DnsModule(),))
    reached: list[str] = []
    ex.resolver = lambda h: (reached.append(h), resolver(h))[1]
    rid = ex.run(["evil.com", "example.com"])
    stats = led.stats(rid)
    led.close()
    assert "evil.com" not in reached
    assert stats.get("refused", 0) >= 1
    assert stats.get("completed", 0) >= 1  # the in-scope seed still ran


def test_gate_is_enforced_at_the_fetcher_not_the_module(tmp_path, scope,
                                                       resolver, instant_governor):
    """Even calling the Fetcher directly (bypassing module.run) is gated."""
    from reconagent.executor import _GatedFetcher
    led = Ledger(tmp_path / "l.db")
    rid = led.start_run(scope.describe())
    f = _GatedFetcher(scope, instant_governor, led, rid, "direct", resolver,
                      lambda h: {})
    with pytest.raises(ScopeViolation):
        f.resolve("evil.com")
    with pytest.raises(ScopeViolation):
        f.http_head("secret.example.com")
    assert f.resolve("api.example.com") == ["10.0.0.9"]  # in scope works
    led.close()
