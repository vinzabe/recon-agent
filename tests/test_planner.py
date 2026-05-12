"""LLMPlanner tests with stub LLMs."""
from __future__ import annotations

import json

from recon_agent.planner import LLMPlanner, PlanStep, ToolCatalog


class _StubLLM:
    def __init__(self, payload):
        self.payload = payload
        self.last_prompt = None

    def chat_simple(self, prompt, **kw):
        self.last_prompt = prompt
        return self.payload


def test_default_planner_picks_http_first():
    step = LLMPlanner().plan("127.0.0.1", history=[])
    assert step.tool == "http"


def test_default_planner_picks_nmap_after_http():
    history = [{"step": {"tool": "http"}, "result": {"status": "ok"}}]
    step = LLMPlanner().plan("127.0.0.1", history)
    assert step.tool == "nmap"


def test_default_planner_returns_none_after_all_tools():
    history = [
        {"step": {"tool": "http"}, "result": {}},
        {"step": {"tool": "nmap"}, "result": {}},
        {"step": {"tool": "ffuf"}, "result": {}},
    ]
    assert LLMPlanner().plan("127.0.0.1", history) is None


def test_llm_chooses_known_tool():
    payload = json.dumps({
        "tool": "nmap", "params": {"ports": "22"},
        "rationale": "scan ssh"})
    p = LLMPlanner(llm=_StubLLM(payload))
    step = p.plan("127.0.0.1", history=[])
    assert step.tool == "nmap"
    assert ("ports", "22") in step.params
    assert "scan ssh" in step.rationale


def test_llm_unknown_tool_falls_back_with_warning():
    payload = json.dumps({"tool": "nuke", "rationale": "evil"})
    p = LLMPlanner(llm=_StubLLM(payload))
    step = p.plan("127.0.0.1", history=[])
    assert step.tool == "http"  # default fallback
    assert "nuke" in step.rationale


def test_llm_invalid_json_falls_back():
    p = LLMPlanner(llm=_StubLLM("not json"))
    step = p.plan("127.0.0.1", history=[])
    assert step.tool == "http"


def test_llm_error_falls_back():
    class _Boom:
        def chat_simple(self, *a, **kw):
            raise RuntimeError("nope")
    step = LLMPlanner(llm=_Boom()).plan("127.0.0.1", history=[])
    assert step.tool == "http"


def test_param_filter_drops_unknown_keys():
    cat = ToolCatalog()
    out = cat.filter_params("nmap", {
        "ports": "22", "evil": "$(rm -rf)"})
    assert ("ports", "22") in out
    assert all(k != "evil" for k, _ in out)


def test_param_filter_drops_shell_metas():
    cat = ToolCatalog()
    out = cat.filter_params("nmap", {"ports": "22; rm -rf /"})
    # Value rejected because it has shell metas.
    assert all(k != "ports" or v == "22; rm -rf /" and False
               for k, v in out)
    assert ("ports", "22; rm -rf /") not in out


def test_param_filter_accepts_valid_value():
    cat = ToolCatalog()
    out = cat.filter_params("http", {"method": "HEAD"})
    assert ("method", "HEAD") in out


def test_callable_llm():
    payload = json.dumps({"tool": "ffuf", "rationale": "fuzz"})
    p = LLMPlanner(llm=lambda prompt: payload)
    step = p.plan("127.0.0.1", history=[])
    assert step.tool == "ffuf"


def test_planstep_to_dict():
    s = PlanStep(tool="nmap", target="127.0.0.1",
                 params=(("ports", "22"),),
                 rationale="r")
    d = s.to_dict()
    assert d["tool"] == "nmap"
    assert d["params"] == {"ports": "22"}
    assert d["rationale"] == "r"


def test_catalog_known_tools():
    c = ToolCatalog()
    for t in ("nmap", "http", "ffuf"):
        assert c.is_known(t)
    assert not c.is_known("metasploit")
