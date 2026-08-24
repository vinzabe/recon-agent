import pytest

from reconagent.governor import RateGovernor


def test_enforces_per_target_interval():
    t = [0.0]
    slept = []
    gov = RateGovernor(per_target_interval=5.0, clock=lambda: t[0],
                       sleep=lambda s: slept.append(s))
    gov.acquire("host")
    gov.release()
    t[0] = 1.0                       # only 1s elapsed
    gov.acquire("host")
    gov.release()
    assert slept == [4.0]            # waited the remaining 4s


def test_different_targets_independent():
    slept = []
    gov = RateGovernor(per_target_interval=5.0, clock=lambda: 0.0,
                       sleep=lambda s: slept.append(s))
    gov.acquire("a")
    gov.release()
    gov.acquire("b")  # different host -> no wait
    gov.release()
    assert slept == []


@pytest.mark.parametrize("kw", [{"per_target_interval": -1}, {"max_concurrency": 0}])
def test_invalid_config_rejected(kw):
    with pytest.raises(ValueError):
        RateGovernor(**kw)
