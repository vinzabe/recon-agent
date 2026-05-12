"""LLM planner with strict tool/argument whitelist.

The planner asks the LLM, given the current engagement state, to pick
the next tool to run. The model **only** chooses from
``tool_catalog.tool_names`` and may suggest one of a fixed set of
parameter strings per tool. Anything else is dropped.

If no LLM is configured we use a deterministic priority queue:
``http`` -> ``nmap`` -> ``ffuf``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PlanStep:
    tool: str
    target: str
    params: tuple[tuple[str, str], ...] = ()
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"tool": self.tool, "target": self.target,
                "params": dict(self.params),
                "rationale": self.rationale}


@dataclass
class ToolCatalog:
    tool_names: tuple[str, ...] = ("nmap", "http", "ffuf")
    # Allowed param keys per tool — values are validated on use.
    allowed_params: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "nmap": ("ports", "scripts"),
            "http": ("method",),
            "ffuf": (),
        })

    def is_known(self, tool: str) -> bool:
        return tool in self.tool_names

    def filter_params(self, tool: str,
                      params: dict[str, Any]) -> tuple[
                          tuple[str, str], ...]:
        allowed = set(self.allowed_params.get(tool, ()))
        out = []
        for k, v in params.items():
            if k in allowed and isinstance(v, (str, int)):
                # Argument value sanitisation: alphanumerics, dash,
                # comma, dot, slash only — no shell metas.
                vs = str(v)
                if re.fullmatch(r"[A-Za-z0-9._,\-/]+", vs):
                    out.append((k, vs))
        return tuple(out)


@dataclass
class LLMPlanner:
    catalog: ToolCatalog = field(default_factory=ToolCatalog)
    llm: Any = None
    max_steps: int = 5

    SYSTEM = (
        "You are a defensive security analyst planning a recon "
        "engagement. Pick ONE next tool to run from the allowed list. "
        "Reply STRICTLY as JSON: "
        '{{"tool": "<one of: {tools}>", '
        '"params": {{"key": "value", ...}}, '
        '"rationale": "<short>"}}\n'
        "Targets must be the engagement target only. "
        "Do NOT invent tool names; do NOT suggest exploitation.\n\n"
        "Engagement target: {target}\n"
        "Already-completed steps: {history}\n"
    )

    def plan(self, target: str,
             history: list[dict]) -> PlanStep | None:
        if self.llm is None:
            return self._default_next(target, history)
        prompt = self.SYSTEM.format(
            tools=", ".join(self.catalog.tool_names),
            target=target,
            history=json.dumps(history, default=str)[:1500])
        try:
            if hasattr(self.llm, "chat_simple"):
                raw = self.llm.chat_simple(
                    prompt, max_tokens=200, temperature=0.0)
            else:
                raw = str(self.llm(prompt))
        except Exception:
            return self._default_next(target, history)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return self._default_next(target, history)
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return self._default_next(target, history)
        tool = str(obj.get("tool", "")).strip().lower()
        rationale = str(obj.get("rationale", ""))[:300]
        if not self.catalog.is_known(tool):
            return self._default_next(target, history,
                                      rejected=tool)
        params = obj.get("params", {})
        params = self.catalog.filter_params(
            tool, params if isinstance(params, dict) else {})
        return PlanStep(tool=tool, target=target, params=params,
                        rationale=rationale or "(LLM)")

    def _default_next(self, target: str, history: list[dict],
                      rejected: str = "") -> PlanStep | None:
        ran: set[str] = set()
        for h in history:
            # History items may be plain {"tool": ...} or
            # {"step": {"tool": ...}, ...}.
            step = h.get("step") if isinstance(h, dict) else None
            if isinstance(step, dict) and "tool" in step:
                ran.add(step["tool"])
            elif "tool" in h:
                ran.add(h["tool"])
        priority = ("http", "nmap", "ffuf")
        for t in priority:
            if t not in ran:
                rationale = "deterministic priority"
                if rejected:
                    rationale += (
                        f" (LLM suggested unknown tool {rejected!r})")
                return PlanStep(tool=t, target=target,
                                rationale=rationale)
        return None
