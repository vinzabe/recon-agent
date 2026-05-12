"""recon-agent — LLM-driven recon orchestrator (defensive use only).

The agent plans a recon engagement against an explicitly authorised
target and runs a small toolbox of read-only tools (`nmap`,
``ffuf``-style HTTP fuzz, optional ``gobuster``-like dir scan,
``http_probe``). Every action is filtered through a hard
:class:`ScopeGuard` that allows only:

- 127.0.0.0/8, ::1
- ``scanme.nmap.org``
- targets listed in the bundled ``allowlist`` you pass to
  :class:`ReconAgent`.

The LLM picks **which** tool to run next from a fixed catalog; it
never controls argv directly. Anti-hallucination guards reject any
tool name not in the catalog or any target not in scope.

Modules:

- :mod:`recon_agent.scope` — ScopeGuard.
- :mod:`recon_agent.tools` — wrappers around nmap/ffuf/http.
- :mod:`recon_agent.planner` — LLM planner with whitelist enforcement.
- :mod:`recon_agent.agent` — ReconAgent orchestrator + Engagement state.
- :mod:`recon_agent.report` — markdown / json writers.
- :mod:`recon_agent.cli` — `python -m recon_agent.cli scan TARGET`.
"""
from __future__ import annotations

from .agent import Engagement, ReconAgent, ReconResult
from .planner import LLMPlanner, PlanStep, ToolCatalog
from .report import ReportWriter
from .scope import ScopeGuard, ScopeViolation
from .tools import (
    HttpProbe,
    NmapRunner,
    ToolRunner,
    UrlFuzzer,
    available_tools,
)

__all__ = [
    "Engagement",
    "HttpProbe",
    "LLMPlanner",
    "NmapRunner",
    "PlanStep",
    "ReconAgent",
    "ReconResult",
    "ReportWriter",
    "ScopeGuard",
    "ScopeViolation",
    "ToolCatalog",
    "ToolRunner",
    "UrlFuzzer",
    "available_tools",
]
