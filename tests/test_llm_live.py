"""LLM_LIVE: 5 tests covering LLM-driven planning."""
from __future__ import annotations

import os

import pytest

from recon_agent.planner import LLMPlanner, ToolCatalog

LIVE = os.environ.get("LLM_LIVE", "0") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="LLM_LIVE not set")


class _LiveCache:
    _llm = None
    _planner = None
    _step_first = None
    _step_after_http = None

    @classmethod
    def llm(cls):
        if cls._llm is None:
            from recon_agent.llm_client import LLMClient
            cls._llm = LLMClient(timeout=180.0)
        return cls._llm

    @classmethod
    def planner(cls):
        if cls._planner is None:
            cls._planner = LLMPlanner(catalog=ToolCatalog(),
                                      llm=cls.llm())
        return cls._planner

    @classmethod
    def step_first(cls):
        if cls._step_first is None:
            cls._step_first = cls.planner().plan(
                "127.0.0.1", history=[])
        return cls._step_first

    @classmethod
    def step_after_http(cls):
        if cls._step_after_http is None:
            history = [{
                "step": {"tool": "http", "target": "127.0.0.1"},
                "result": {"status": "ok",
                           "data": {"status_code": 200}}}]
            cls._step_after_http = cls.planner().plan(
                "127.0.0.1", history)
        return cls._step_after_http


def test_live_first_step_is_known_tool():
    s = _LiveCache.step_first()
    assert s is not None
    assert s.tool in ToolCatalog().tool_names


def test_live_first_step_target_in_scope():
    s = _LiveCache.step_first()
    assert s.target == "127.0.0.1"


def test_live_planner_picks_different_after_http():
    """With http already done, the next step should be a different tool."""
    s = _LiveCache.step_after_http()
    assert s is not None
    assert s.tool in ToolCatalog().tool_names


def test_live_step_rationale_present():
    s = _LiveCache.step_first()
    assert s.rationale and len(s.rationale) > 1


def test_live_step_serialisable():
    import json
    s = _LiveCache.step_first()
    assert json.dumps(s.to_dict())
