import pytest

from reconagent.governor import RateGovernor
from reconagent.scope import Scope


@pytest.fixture
def scope():
    return Scope.build(
        include=["*.example.com", "example.com", "10.0.0.0/24", "api.test"],
        exclude=["secret.example.com", "10.0.0.1"],
        authorisation_ref="ENG-2026-TEST")


@pytest.fixture
def instant_governor():
    """A governor that never actually sleeps, for fast tests."""
    ticks = iter(range(10_000_000))
    return RateGovernor(per_target_interval=0.0, max_concurrency=8,
                        clock=lambda: next(ticks), sleep=lambda s: None)


FAKE_DNS = {
    "example.com": ["93.184.216.34"],
    "www.example.com": ["93.184.216.34"],
    "api.example.com": ["10.0.0.9"],
    "dev.example.com": ["10.0.0.10"],
    "secret.example.com": ["10.0.0.99"],  # resolvable but OUT OF SCOPE
    "api.test": ["203.0.113.5"],
}


@pytest.fixture
def resolver():
    return lambda h: FAKE_DNS.get(h, [])


@pytest.fixture
def http_head():
    return lambda _h: {"server": "nginx/1.24", "x-powered-by": "PHP/8.2"}
