"""ReportWriter tests."""
from __future__ import annotations

import json

from recon_agent.agent import Engagement, ReconResult
from recon_agent.planner import PlanStep
from recon_agent.report import ReportWriter


def _result_with_findings():
    eng = Engagement(target="127.0.0.1")
    step = PlanStep("nmap", "127.0.0.1", rationale="r")
    eng.add(step, {
        "tool": "nmap", "target": "127.0.0.1", "status": "ok",
        "data": {"open_ports": []}, "raw": "raw"})
    return ReconResult(engagement=eng, findings=[
        {"kind": "open_port", "host": "127.0.0.1", "port": 22,
         "proto": "tcp", "service": "ssh", "version": ""},
        {"kind": "http_response", "host": "localhost",
         "status_code": 200, "url": "http://localhost/"},
        {"kind": "url_hit", "host": "localhost", "path": "admin",
         "status_code": 401},
    ])


def test_to_json_round_trip():
    r = _result_with_findings()
    obj = json.loads(ReportWriter(r).to_json())
    assert obj["engagement"]["target"] == "127.0.0.1"
    assert len(obj["findings"]) == 3


def test_to_markdown_includes_target_and_findings():
    md = ReportWriter(_result_with_findings()).to_markdown()
    assert "Recon Engagement Report" in md
    assert "127.0.0.1" in md
    assert "open" in md and "22" in md
    assert "HTTP" in md and "200" in md
    assert "url hit" in md.lower()


def test_to_markdown_handles_empty_engagement():
    eng = Engagement(target="127.0.0.1")
    md = ReportWriter(ReconResult(engagement=eng)).to_markdown()
    assert "Recon Engagement Report" in md
    assert "Steps run: **0**" in md


def test_to_markdown_lists_rejected_steps():
    eng = Engagement(target="127.0.0.1")
    eng.reject(PlanStep("nuke", "127.0.0.1"), "unknown tool")
    md = ReportWriter(ReconResult(engagement=eng)).to_markdown()
    assert "Rejected Steps" in md
    assert "unknown tool" in md
