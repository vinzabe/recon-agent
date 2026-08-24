import pytest

from reconagent.scope import Rule, Scope, ScopeViolation, normalise


@pytest.mark.parametrize("raw,expected", [
    ("HTTPS://WWW.Example.COM/path", "www.example.com"),
    ("example.com:8443", "example.com"),
    ("example.com.", "example.com"),
    ("http://api.test/a/b?c=d", "api.test"),
])
def test_normalise(raw, expected):
    assert normalise(raw) == expected


def test_wildcard_covers_subdomains_not_apex():
    r = Rule.parse("*.example.com")
    assert r.matches("www.example.com")
    assert r.matches("a.b.example.com")
    assert not r.matches("example.com")   # apex must be listed separately
    assert not r.matches("notexample.com")


def test_cidr_matching():
    r = Rule.parse("10.0.0.0/24")
    assert r.matches("10.0.0.5")
    assert not r.matches("10.0.1.5")


def test_exclusion_beats_inclusion(scope):
    assert not scope.permits("secret.example.com")   # matches *.example.com but excluded
    assert not scope.permits("10.0.0.1")             # in CIDR but excluded
    assert scope.permits("10.0.0.2")


def test_check_raises_with_reason(scope):
    with pytest.raises(ScopeViolation) as e:
        scope.check("evil.com")
    assert "no inclusion" in e.value.reason
    with pytest.raises(ScopeViolation) as e:
        scope.check("secret.example.com")
    assert "exclusion" in e.value.reason


def test_scope_requires_authorisation_ref():
    with pytest.raises(ValueError, match="authorisation_ref is required"):
        Scope.build(["example.com"], authorisation_ref="")


def test_scope_requires_at_least_one_include():
    with pytest.raises(ValueError, match="at least one"):
        Scope.build([], authorisation_ref="X")


def test_scope_violation_is_not_valueerror():
    """A scope violation must not be swallowed by generic except ValueError."""
    assert not issubclass(ScopeViolation, ValueError)


@pytest.mark.parametrize("bad", ["", "  ", "*.*.com", "not a host", "999.999.0.0/8"])
def test_malformed_rules_rejected(bad):
    with pytest.raises(ValueError):
        Rule.parse(bad)
