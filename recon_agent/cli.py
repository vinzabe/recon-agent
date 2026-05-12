"""``python -m recon_agent.cli scan TARGET``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .agent import ReconAgent
from .planner import LLMPlanner, ToolCatalog
from .report import ReportWriter
from .scope import ScopeGuard


def _maybe_llm():
    if not (os.environ.get("LLM_API_KEY")
            and os.environ.get("LLM_BASE_URL")):
        return None
    try:
        from .llm_client import LLMClient
        return LLMClient(timeout=180.0)
    except Exception:
        return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon-agent",
        description="LLM-driven defensive recon orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="run a recon engagement")
    scan.add_argument("target")
    scan.add_argument("--max-steps", type=int, default=4)
    scan.add_argument("--allow", action="append", default=[],
                      help="extra allowed host (repeatable)")
    scan.add_argument("--use-llm", action="store_true")
    scan.add_argument("--format", choices=("text", "json"),
                      default="text")
    sub.add_parser("list-tools", help="list available tools")
    return p


def cmd_scan(args, *, agent: Optional[ReconAgent] = None) -> int:
    if agent is None:
        scope = ScopeGuard(extra=tuple(args.allow))
        catalog = ToolCatalog()
        llm = _maybe_llm() if args.use_llm else None
        planner = LLMPlanner(catalog=catalog, llm=llm)
        agent = ReconAgent(scope=scope, catalog=catalog,
                           planner=planner, max_steps=args.max_steps)
    result = agent.run(args.target)
    writer = ReportWriter(result)
    if args.format == "json":
        sys.stdout.write(writer.to_json() + "\n")
    else:
        sys.stdout.write(writer.to_markdown() + "\n")
    return 0


def cmd_list_tools(args) -> int:
    from .tools import available_tools
    tools = available_tools()
    for name, runner in tools.items():
        sys.stdout.write(
            f"{name}\tavailable={runner.is_available()}\n")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "list-tools":
        return cmd_list_tools(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
