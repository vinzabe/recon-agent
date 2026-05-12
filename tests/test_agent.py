"""ReconAgent orchestrator tests with stubbed runners."""
from __future__ import annotations

import json
from dataclasses import dataclass

from recon_agent.agent import Engagement, ReconAgent, ReconResult
from recon_agent.planner import LLMPlanner, PlanStep, ToolCatalog
from recon_agent.scope import ScopeGuard
from recon_agent.tools import ToolRunner


class _StubRunner(ToolRunner):
    def __init__(self, name, payload, scope=None):
        super().__init__(scope=scope or ScopeGuard(),
                         name=name, binary=None)
        self.payload = payload
        self.calls = []

    def run(self, target, **kw):
        self.calls.append((target, kw))
        return {"tool": self.name, "target": target, "status": "ok",
                "data": self.payload, "raw": "raw", "error": ""}


def _stub_planner(steps):
    """Return a planner that hands out the given steps then None."""
    class _P:
        def __init__(self):
            self.idx = 0
        def plan(self, target, history):
            if self.idx >= len(steps):
                return None
            s = steps[self.idx]
            self.idx += 1
            return s
    return _P()


def test_agent_blocks_oos_target_at_entry():
    a = ReconAgent()
    r = a.run("8.8.8.8")
    assert r.engagement.history == []
    assert r.engagement.rejected_steps
    assert "scope violation" in r.engagement.rejected_steps[0]["reason"]


def test_agent_runs_planned_steps():
    runners = {
        "nmap": _StubRunner("nmap", {"open_ports": [
            {"port": 22, "proto": "tcp", "state": "open",
             "service": "ssh", "version": ""}]}),
        "http": _StubRunner("http", {"url": "http://127.0.0.1/",
                                     "status_code": 200}),
        "ffuf": _StubRunner("ffuf", {"hits": []}),
    }
    planner = _stub_planner([
        PlanStep("http", "127.0.0.1"),
        PlanStep("nmap", "127.0.0.1"),
    ])
    a = ReconAgent(planner=planner, runners=runners, max_steps=5)
    r = a.run("127.0.0.1")
    assert len(r.engagement.history) == 2
    assert runners["http"].calls
    assert runners["nmap"].calls


def test_agent_extracts_findings_from_nmap():
    runners = {"nmap": _StubRunner("nmap", {"open_ports": [
        {"port": 80, "proto": "tcp", "state": "open",
         "service": "http", "version": "nginx 1"}]})}
    planner = _stub_planner([PlanStep("nmap", "127.0.0.1")])
    a = ReconAgent(planner=planner, runners=runners, max_steps=2)
    r = a.run("127.0.0.1")
    assert any(f["kind"] == "open_port" and f["port"] == 80
               for f in r.findings)


def test_agent_extracts_findings_from_http():
    runners = {"http": _StubRunner("http", {
        "url": "http://localhost/", "status_code": 200,
        "headers": {}, "body_preview": ""})}
    planner = _stub_planner([PlanStep("http", "127.0.0.1")])
    r = ReconAgent(planner=planner, runners=runners,
                   max_steps=2).run("127.0.0.1")
    assert any(f["kind"] == "http_response" for f in r.findings)


def test_agent_extracts_findings_from_ffuf():
    runners = {"ffuf": _StubRunner("ffuf", {
        "hits": [{"path": "admin", "url": "http://x/admin",
                  "status": 401}]})}
    planner = _stub_planner([PlanStep("ffuf", "127.0.0.1")])
    r = ReconAgent(planner=planner, runners=runners,
                   max_steps=2).run("127.0.0.1")
    hits = [f for f in r.findings if f["kind"] == "url_hit"]
    assert hits and hits[0]["path"] == "admin"


def test_agent_skips_unknown_tool_step():
    planner = _stub_planner([PlanStep("nuke", "127.0.0.1")])
    a = ReconAgent(planner=planner, max_steps=1)
    r = a.run("127.0.0.1")
    assert r.engagement.history == []
    assert r.engagement.rejected_steps[0]["reason"] == "unknown tool"


def test_agent_skips_oos_step_target():
    """Even mid-engagement, OOS target steps are dropped."""
    planner = _stub_planner([PlanStep("http", "8.8.8.8")])
    a = ReconAgent(planner=planner, max_steps=1)
    r = a.run("127.0.0.1")
    assert r.engagement.history == []
    assert any("out of scope" in s["reason"]
               for s in r.engagement.rejected_steps)


def test_agent_max_steps_enforced():
    runners = {"http": _StubRunner("http", {"url": "x",
                                             "status_code": 200})}
    planner = _stub_planner([
        PlanStep("http", "127.0.0.1"),
        PlanStep("http", "127.0.0.1"),
        PlanStep("http", "127.0.0.1"),
    ])
    r = ReconAgent(planner=planner, runners=runners,
                   max_steps=2).run("127.0.0.1")
    assert len(r.engagement.history) == 2


def test_agent_default_planner_runs_three_tools():
    runners = {
        "nmap": _StubRunner("nmap", {"open_ports": []}),
        "http": _StubRunner("http", {"url": "x", "status_code": 200}),
        "ffuf": _StubRunner("ffuf", {"hits": []}),
    }
    a = ReconAgent(runners=runners, max_steps=5)
    r = a.run("127.0.0.1")
    tools_run = {h["step"]["tool"] for h in r.engagement.history}
    assert tools_run == {"nmap", "http", "ffuf"}


def test_engagement_to_dict():
    e = Engagement(target="127.0.0.1")
    e.reject(None, "x")
    d = e.to_dict()
    assert d["target"] == "127.0.0.1"
    assert d["rejected_steps"]


def test_recon_result_to_dict_serialisable():
    runners = {"http": _StubRunner("http", {"url": "x",
                                             "status_code": 200})}
    r = ReconAgent(planner=_stub_planner([PlanStep("http", "127.0.0.1")]),
                   runners=runners, max_steps=1).run("127.0.0.1")
    d = r.to_dict()
    assert json.dumps(d, default=str)


def test_agent_handles_unknown_kwargs_from_planner():
    runners = {"http": _StubRunner("http", {"url": "x",
                                             "status_code": 200})}
    planner = _stub_planner([PlanStep(
        "http", "127.0.0.1", params=(("oddball", "x"),))])
    r = ReconAgent(planner=planner, runners=runners,
                   max_steps=1).run("127.0.0.1")
    assert len(r.engagement.history) == 1
