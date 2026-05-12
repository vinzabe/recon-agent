"""ScopeGuard tests."""
from __future__ import annotations

import pytest

from recon_agent.scope import ScopeGuard, ScopeViolation


def test_localhost_allowed():
    g = ScopeGuard()
    assert g.is_allowed("localhost")
    assert g.is_allowed("127.0.0.1")
    assert g.is_allowed("127.42.1.1")


def test_ipv6_loopback_allowed():
    g = ScopeGuard()
    assert g.is_allowed("::1")
    assert g.is_allowed("[::1]")
    assert g.is_allowed("[::1]:8080")


def test_scanme_nmap_org_allowed():
    g = ScopeGuard()
    assert g.is_allowed("scanme.nmap.org")
    assert g.is_allowed("http://scanme.nmap.org/")


def test_external_ip_rejected():
    g = ScopeGuard()
    assert not g.is_allowed("8.8.8.8")
    with pytest.raises(ScopeViolation):
        g.check("8.8.8.8")


def test_extra_allowlist():
    g = ScopeGuard(extra=("internal.test.example",))
    assert g.is_allowed("internal.test.example")
    assert not g.is_allowed("evil.example")


def test_url_normalisation():
    g = ScopeGuard()
    assert g.is_allowed("http://localhost:8080/admin")
    assert g.is_allowed("https://scanme.nmap.org:443/")
    assert not g.is_allowed("http://evil.com/path")


def test_host_with_port_normalised():
    g = ScopeGuard()
    assert g.is_allowed("127.0.0.1:22")
    assert g.is_allowed("scanme.nmap.org:80")


def test_empty_target_rejected():
    g = ScopeGuard()
    with pytest.raises(ScopeViolation):
        g.check("")


def test_filter_drops_oos():
    g = ScopeGuard()
    out = g.filter(["127.0.0.1", "8.8.8.8", "scanme.nmap.org"])
    assert out == ["127.0.0.1", "scanme.nmap.org"]


def test_check_returns_normalised_host():
    g = ScopeGuard()
    assert g.check("HTTP://Localhost:80/x") == "localhost"


def test_ip_in_class_a_loopback():
    g = ScopeGuard()
    assert g.is_allowed("127.250.0.99")


def test_invalid_ipv6_rejected():
    g = ScopeGuard()
    assert not g.is_allowed("[fe80::1]")  # not in ::1/128


def test_uppercase_host_canonicalised():
    g = ScopeGuard()
    assert g.is_allowed("LOCALHOST")
    assert g.is_allowed("ScanMe.Nmap.Org")
