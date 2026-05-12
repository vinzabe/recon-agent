"""ReconAgent orchestrator.

Drives a small loop:

1. Ask the planner for the next :class:`PlanStep`.
2. Validate the step (tool whitelist + scope guard).
3. Run the corresponding :class:`ToolRunner`.
4. Append the result to the engagement history.
5. Repeat until ``max_steps`` is reached or the planner returns
   ``None``.

The agent **never** runs a tool the planner did not explicitly choose,
and **never** runs against a target outside the scope guard.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .planner import LLMPlanner, PlanStep, ToolCatalog
from .scope import ScopeGuard, ScopeViolation
from .tools import ToolRunner, available_tools


@dataclass
class Engagement:
    target: str
    started_at: float = field(default_factory=time.time)
    history: list[dict] = field(default_factory=list)
    rejected_steps: list[dict] = field(default_factory=list)

    def add(self, step: PlanStep, result: dict) -> None:
        self.history.append({
            "step": step.to_dict(),
            "result": {k: v for k, v in result.items() if k != "raw"},
            "raw_chars": len(result.get("raw", "")),
        })

    def reject(self, step: PlanStep, reason: str) -> None:
        self.rejected_steps.append({
            "step": step.to_dict() if step else None,
            "reason": reason,
        })

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "history": list(self.history),
            "rejected_steps": list(self.rejected_steps),
        }


@dataclass
class ReconResult:
    engagement: Engagement
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "engagement": self.engagement.to_dict(),
            "findings": list(self.findings),
        }


@dataclass
class ReconAgent:
    scope: ScopeGuard = field(default_factory=ScopeGuard)
    catalog: ToolCatalog = field(default_factory=ToolCatalog)
    planner: LLMPlanner | None = None
    runners: dict[str, ToolRunner] | None = None
    max_steps: int = 4

    def __post_init__(self):
        if self.planner is None:
            self.planner = LLMPlanner(catalog=self.catalog)
        if self.runners is None:
            self.runners = available_tools(scope=self.scope)

    def run(self, target: str) -> ReconResult:
        # Hard scope check up-front so we never even plan against an
        # out-of-scope target.
        try:
            self.scope.check(target)
        except ScopeViolation as exc:
            eng = Engagement(target=target)
            eng.reject(None, f"scope violation: {exc}")  # type: ignore[arg-type]
            return ReconResult(engagement=eng)

        eng = Engagement(target=target)
        for _ in range(self.max_steps):
            step = self.planner.plan(target, eng.history)
            if step is None:
                break
            if not self.catalog.is_known(step.tool):
                eng.reject(step, "unknown tool")
                continue
            if not self.scope.is_allowed(step.target):
                eng.reject(step, "target out of scope")
                continue
            runner = self.runners.get(step.tool)
            if runner is None:
                eng.reject(step, "no runner for tool")
                continue
            params = dict(step.params) if step.params else {}
            try:
                result = runner.run(step.target, **params)
            except TypeError:
                # Unknown kwarg from planner — call with no args.
                result = runner.run(step.target)
            eng.add(step, result)
        findings = self._extract_findings(eng)
        return ReconResult(engagement=eng, findings=findings)

    @staticmethod
    def _extract_findings(eng: Engagement) -> list[dict]:
        out: list[dict] = []
        for entry in eng.history:
            res = entry["result"]
            tool = res.get("tool")
            data = res.get("data", {}) or {}
            if tool == "nmap":
                for p in data.get("open_ports", []):
                    if p.get("state") == "open":
                        out.append({
                            "kind": "open_port",
                            "host": res.get("target"),
                            "port": p["port"],
                            "proto": p["proto"],
                            "service": p.get("service", ""),
                            "version": p.get("version", ""),
                        })
            elif tool == "http":
                code = data.get("status_code")
                if code:
                    out.append({
                        "kind": "http_response",
                        "host": res.get("target"),
                        "status_code": code,
                        "url": data.get("url"),
                    })
            elif tool == "ffuf":
                for h in data.get("hits", []):
                    out.append({
                        "kind": "url_hit",
                        "host": res.get("target"),
                        "path": h.get("path"),
                        "status_code": h.get("status"),
                    })
        return out
