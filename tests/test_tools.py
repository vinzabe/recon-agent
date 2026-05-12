"""Tool runner tests (no real network)."""
from __future__ import annotations

import os
from unittest import mock

from recon_agent.scope import ScopeGuard
from recon_agent.tools import (
    HttpProbe,
    NmapRunner,
    UrlFuzzer,
    available_tools,
)


def test_available_tools_returns_three():
    t = available_tools()
    assert set(t) == {"nmap", "http", "ffuf"}


def test_nmap_blocks_out_of_scope():
    res = NmapRunner().run("8.8.8.8")
    assert res["status"] == "scope_violation"
    assert res["tool"] == "nmap"


def test_http_blocks_out_of_scope():
    res = HttpProbe().run("http://evil.example/")
    assert res["status"] == "scope_violation"


def test_ffuf_blocks_out_of_scope():
    res = UrlFuzzer().run("http://evil.example/")
    assert res["status"] == "scope_violation"


def test_nmap_returns_binary_not_found_when_missing():
    runner = NmapRunner()
    with mock.patch("recon_agent.tools.shutil.which",
                    return_value=None):
        res = runner.run("127.0.0.1")
    assert res["status"] == "binary_not_found"


def test_nmap_parse_ports_basic():
    text = (
        "Starting Nmap...\n"
        "PORT     STATE    SERVICE\n"
        "22/tcp   open     ssh\n"
        "80/tcp   open     http     nginx 1.18.0\n"
        "443/tcp  filtered https\n"
    )
    parsed = NmapRunner._parse_ports(text)
    assert {p["port"] for p in parsed} >= {22, 80}
    open_ports = [p for p in parsed if p["state"] == "open"]
    assert len(open_ports) >= 2
    nginx = next((p for p in parsed if p["port"] == 80), None)
    assert nginx and "nginx" in nginx["version"]


def test_nmap_parse_ports_empty():
    assert NmapRunner._parse_ports("") == []


def test_http_probe_runs_against_localhost(monkeypatch):
    """Use a fake urlopen so we don't need a real server."""
    class _Resp:
        status = 200
        headers = {"Content-Type": "text/html"}
        def read(self, n=None):
            return b"<html>ok</html>"
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_urlopen(req, timeout=5.0):
        return _Resp()

    monkeypatch.setattr("recon_agent.tools.urllib.request.urlopen",
                        fake_urlopen)
    res = HttpProbe().run("http://127.0.0.1/")
    assert res["status"] == "ok"
    assert res["data"]["status_code"] == 200


def test_http_probe_handles_404(monkeypatch):
    import urllib.error
    def fake_urlopen(req, timeout=5.0):
        raise urllib.error.HTTPError(
            url=req.full_url, code=404, msg="Not Found",
            hdrs={"X-test": "1"}, fp=None)
    monkeypatch.setattr("recon_agent.tools.urllib.request.urlopen",
                        fake_urlopen)
    res = HttpProbe().run("http://localhost/missing")
    assert res["status"] == "ok"
    assert res["data"]["status_code"] == 404


def test_http_probe_handles_network_error(monkeypatch):
    import urllib.error
    def fake_urlopen(req, timeout=5.0):
        raise urllib.error.URLError("refused")
    monkeypatch.setattr("recon_agent.tools.urllib.request.urlopen",
                        fake_urlopen)
    res = HttpProbe().run("http://localhost:65000/")
    assert res["status"] == "error"


def test_ffuf_fallback_runs_word_probes(monkeypatch):
    """Without ffuf binary, the runner should iterate the wordlist."""
    monkeypatch.setattr("recon_agent.tools.shutil.which",
                        lambda x: None if x == "ffuf" else "/usr/bin/sh")

    class _Resp:
        status = 200
        def read(self, n=None): return b""
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_urlopen(req, timeout=5.0):
        return _Resp()

    monkeypatch.setattr("recon_agent.tools.urllib.request.urlopen",
                        fake_urlopen)
    res = UrlFuzzer(wordlist=("a", "b")).run("http://127.0.0.1/")
    assert res["status"] == "ok"
    assert res["data"]["engine"] == "fallback"
    assert res["data"]["tested"] == 2
    assert len(res["data"]["hits"]) == 2


def test_ffuf_fallback_skips_500_responses(monkeypatch):
    monkeypatch.setattr("recon_agent.tools.shutil.which",
                        lambda x: None)
    import urllib.error
    def fake_urlopen(req, timeout=5.0):
        raise urllib.error.HTTPError(
            url=req.full_url, code=500, msg="x",
            hdrs={}, fp=None)
    monkeypatch.setattr("recon_agent.tools.urllib.request.urlopen",
                        fake_urlopen)
    res = UrlFuzzer(wordlist=("a",)).run("http://127.0.0.1/")
    assert res["data"]["hits"] == []


def test_result_truncates_raw_output():
    from recon_agent.tools import _truncate
    long = "x" * 50000
    out = _truncate(long, n=1000)
    assert len(out) <= 2000
    assert "truncated" in out


def test_runner_uses_injected_scope():
    g = ScopeGuard(extra=("inside.test",))
    runner = HttpProbe(scope=g)
    assert runner.scope is g
