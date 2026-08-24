"""Command-line interface.

Scope is mandatory and must carry an authorisation reference — you cannot run a
recon pass without recording what authorised it. Exit codes: 0 clean, 2 findings
present, 1 error.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import socket
import sys
from pathlib import Path

from . import __version__
from .executor import Executor
from .governor import RateGovernor
from .ledger import Ledger
from .scope import Scope, ScopeViolation

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def _real_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({str(i[4][0]) for i in infos})


def _real_http_head(host: str) -> dict[str, str]:
    # Deliberately minimal and dependency-free: a HEAD via http.client with a
    # short timeout. Network access here has already passed the scope gate.
    import http.client
    for scheme, port in (("https", 443), ("http", 80)):
        conn_cls = (http.client.HTTPSConnection if scheme == "https"
                    else http.client.HTTPConnection)
        try:
            conn = conn_cls(host, port, timeout=5)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            return {k.lower(): v for k, v in resp.getheaders()}
        except OSError:
            continue
        finally:
            with contextlib.suppress(OSError, NameError):
                conn.close()
    return {}


def _load_scope(a: argparse.Namespace) -> Scope:
    include = list(a.scope or [])
    exclude = list(a.exclude or [])
    if a.scope_file:
        data = json.loads(Path(a.scope_file).read_text())
        include += data.get("include", [])
        exclude += data.get("exclude", [])
        a.auth = a.auth or data.get("authorisation_ref", "")
    return Scope.build(include, exclude, a.auth or "")


def cmd_run(a: argparse.Namespace) -> int:
    scope = _load_scope(a)
    led = Ledger(a.state)
    ex = Executor(
        scope=scope, ledger=led,
        governor=RateGovernor(a.rate, a.concurrency),
        resolver=(lambda _host: []) if a.dry_run else _real_resolver,
        http_head=(lambda _host: {}) if a.dry_run else _real_http_head,
    )
    try:
        rid = ex.run(a.targets, resume=a.resume)
        report = ex.report(rid)
    finally:
        led.close()
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report, dry_run=a.dry_run)
    return EXIT_FINDINGS if report["findings"] else EXIT_OK


def _print_report(report: dict[str, object], *, dry_run: bool) -> None:
    s: dict[str, int] = report["stats"]  # type: ignore[assignment]
    scope: dict[str, object] = report["scope"]  # type: ignore[assignment]
    rid: str = report["run_id"]  # type: ignore[assignment]
    tag = "  [DRY RUN]" if dry_run else ""
    print(f"run {rid[:12]}  auth={scope['authorisation_ref']}{tag}")
    print(f"  completed={s.get('completed',0)} refused={s.get('refused',0)} "
          f"errors={s.get('error',0)} findings={s.get('findings',0)}")
    refusals: list[dict[str, str]] = report["refusals"]  # type: ignore[assignment]
    if refusals:
        print("\n  refused (out of scope):")
        for r in refusals:
            print(f"    {r['target']:<32} {r['detail']}")
    findings: list[dict[str, str]] = report["findings"]  # type: ignore[assignment]
    if findings:
        print("\n  findings:")
        for f in findings:
            print(f"    {f['target']:<32} {f['kind']:<16} {f['value']}")


def cmd_check(a: argparse.Namespace) -> int:
    """Test whether targets are in scope WITHOUT touching the network."""
    scope = _load_scope(a)
    rc = EXIT_OK
    for t in a.targets:
        try:
            scope.check(t)
            print(f"IN-SCOPE   {t}")
        except ScopeViolation as v:
            print(f"OUT-SCOPE  {t}  ({v.reason})")
            rc = EXIT_FINDINGS
    return rc


def cmd_report(a: argparse.Namespace) -> int:
    with Ledger(a.state) as led:
        rid = a.run_id or led.resume_latest()
        if not rid:
            print("no run to report", file=sys.stderr)
            return EXIT_ERROR
        out = {"run_id": rid, "stats": led.stats(rid),
               "findings": led.findings(rid),
               "refusals": [vars(x) for x in led.actions(rid, "refused")]}
    print(json.dumps(out, indent=2))
    return EXIT_OK


def _scope_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--scope", action="append", metavar="RULE",
                    help="in-scope rule (host, *.wildcard, or CIDR)")
    sp.add_argument("--exclude", action="append", metavar="RULE")
    sp.add_argument("--scope-file", help="JSON with include/exclude/authorisation_ref")
    sp.add_argument("--auth", help="authorisation reference (required)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconagent", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--state", default="reconagent.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run recon within scope")
    r.add_argument("targets", nargs="+")
    _scope_args(r)
    r.add_argument("--rate", type=float, default=1.0, help="min seconds per target")
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument("--resume", action="store_true", help="resume the latest run")
    r.add_argument("--dry-run", action="store_true",
                   help="enumerate and scope-check without any network calls")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="test targets against scope, no network")
    c.add_argument("targets", nargs="+")
    _scope_args(c)
    c.set_defaults(func=cmd_check)

    rp = sub.add_parser("report", help="print a stored run report")
    rp.add_argument("--run-id")
    rp.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
