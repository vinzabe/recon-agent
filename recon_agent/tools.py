"""Tool wrappers used by the recon agent.

Each runner exposes a uniform interface::

    runner.run(target, **kwargs) -> dict

The dict always contains:

- ``tool``: short name (``"nmap"``, ``"ffuf"``, ``"http"``).
- ``target``: the (normalised) target string.
- ``status``: ``"ok"``, ``"error"``, ``"binary_not_found"``,
  ``"scope_violation"``, or ``"timeout"``.
- ``data``: parsed structured result (port list, status code, etc.).
- ``raw``: raw stdout (truncated to 16 KB) for forensics.

If the underlying binary is missing the runner returns
``status="binary_not_found"`` rather than raising, so the agent can
keep working with the remaining tools.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable

from .scope import ScopeGuard, ScopeViolation


_MAX_RAW = 16 * 1024


def _truncate(s: str, n: int = _MAX_RAW) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... [truncated {len(s) - n} chars]"


def _result(tool: str, target: str, status: str, *,
            data: Any = None, raw: str = "",
            error: str = "") -> dict:
    return {
        "tool": tool, "target": target, "status": status,
        "data": data if data is not None else {},
        "raw": _truncate(raw), "error": error,
        "ts": time.time(),
    }


@dataclass
class ToolRunner:
    scope: ScopeGuard = field(default_factory=ScopeGuard)
    timeout: float = 30.0
    name: str = "tool"
    binary: str | None = None

    def is_available(self) -> bool:
        return self.binary is not None and bool(
            shutil.which(self.binary))

    def _check_scope(self, target: str) -> str:
        try:
            return self.scope.check(target)
        except ScopeViolation as exc:
            raise

    def _run_subprocess(self, argv: list[str]) -> tuple[int, str]:
        try:
            cp = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=self.timeout, check=False)
            return cp.returncode, (cp.stdout or "") + (cp.stderr or "")
        except subprocess.TimeoutExpired:
            return -1, "TIMEOUT"


# ----- nmap ---------------------------------------------------------
class NmapRunner(ToolRunner):
    def __init__(self, scope: ScopeGuard | None = None,
                 timeout: float = 60.0):
        super().__init__(scope=scope or ScopeGuard(),
                         timeout=timeout, name="nmap", binary="nmap")

    def run(self, target: str, *, ports: str = "1-1024",
            extra_args: tuple[str, ...] = (),
            scripts: tuple[str, ...] = ()) -> dict:
        try:
            host = self._check_scope(target)
        except ScopeViolation as exc:
            return _result("nmap", target, "scope_violation",
                           error=str(exc))
        if not self.is_available():
            return _result("nmap", host, "binary_not_found",
                           error="nmap binary not on PATH")
        argv = ["nmap", "-Pn", "--host-timeout",
                f"{int(self.timeout - 5)}s",
                "-p", ports]
        if scripts:
            argv += ["--script", ",".join(scripts)]
        # Whitelist sane args: only flags with leading '-' from a
        # short allowlist may be added.
        for a in extra_args:
            if a in ("-sV", "-sC", "-T2", "-T3", "-T4",
                     "-O", "-A"):
                argv.append(a)
        argv.append(host)
        rc, out = self._run_subprocess(argv)
        if out == "TIMEOUT":
            return _result("nmap", host, "timeout",
                           error="nmap exceeded timeout")
        ports_open = self._parse_ports(out)
        data = {"open_ports": ports_open, "exit_code": rc}
        status = "ok" if rc == 0 else "error"
        return _result("nmap", host, status, data=data, raw=out,
                       error="" if rc == 0 else f"exit {rc}")

    @staticmethod
    def _parse_ports(text: str) -> list[dict]:
        out = []
        for line in text.splitlines():
            line = line.strip()
            m = re.match(
                r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)"
                r"(?:\s+(.*))?$", line)
            if m:
                out.append({
                    "port": int(m.group(1)),
                    "proto": m.group(2),
                    "state": m.group(3),
                    "service": m.group(4),
                    "version": (m.group(5) or "").strip(),
                })
        return out


# ----- HTTP probe ---------------------------------------------------
class HttpProbe(ToolRunner):
    """Tiny HTTP HEAD/GET probe using stdlib (no extra deps)."""

    def __init__(self, scope: ScopeGuard | None = None,
                 timeout: float = 5.0):
        super().__init__(scope=scope or ScopeGuard(),
                         timeout=timeout, name="http", binary=None)

    def is_available(self) -> bool:
        return True

    def run(self, target: str, *, method: str = "GET",
            user_agent: str = "recon-agent/0.1",
            verify: bool = True) -> dict:
        try:
            host = self._check_scope(target)
        except ScopeViolation as exc:
            return _result("http", target, "scope_violation",
                           error=str(exc))
        url = target if target.startswith(
            ("http://", "https://")) else f"http://{host}"
        req = urllib.request.Request(
            url, method=method.upper(),
            headers={"User-Agent": user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(2048)
                data = {
                    "url": url, "status_code": r.status,
                    "headers": dict(r.headers.items()),
                    "body_preview": body.decode(
                        "utf-8", errors="replace")[:500],
                }
                return _result("http", host, "ok", data=data,
                               raw=str(data["body_preview"]))
        except urllib.error.HTTPError as exc:
            return _result("http", host, "ok",
                           data={"url": url,
                                 "status_code": exc.code,
                                 "headers": dict(
                                     exc.headers.items()),
                                 "body_preview": ""},
                           error=str(exc))
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            return _result("http", host, "error",
                           data={"url": url}, error=str(exc))


# ----- ffuf-style URL fuzzer ---------------------------------------
class UrlFuzzer(ToolRunner):
    """ffuf-style HTTP path fuzzer.

    If the ``ffuf`` binary is on PATH it is used; otherwise we fall
    back to a small in-process probe over the bundled wordlist that
    issues HEAD requests.
    """
    DEFAULT_WORDLIST = (
        "admin", "login", "robots.txt", "sitemap.xml",
        ".git/HEAD", ".env", "wp-login.php", "phpmyadmin",
        "console", "actuator/health", "api", "api/v1",
        "api/v2", "swagger.json", "openapi.json", "metrics",
    )

    def __init__(self, scope: ScopeGuard | None = None,
                 timeout: float = 10.0,
                 wordlist: tuple[str, ...] = DEFAULT_WORDLIST):
        super().__init__(scope=scope or ScopeGuard(),
                         timeout=timeout, name="ffuf",
                         binary="ffuf")
        self.wordlist = wordlist

    def is_available(self) -> bool:
        return True  # always usable via fallback

    def run(self, target: str, *, paths: Iterable[str] | None = None,
            user_agent: str = "recon-agent/0.1") -> dict:
        try:
            host = self._check_scope(target)
        except ScopeViolation as exc:
            return _result("ffuf", target, "scope_violation",
                           error=str(exc))
        words = list(paths) if paths else list(self.wordlist)
        base = target if target.startswith(
            ("http://", "https://")) else f"http://{host}"
        if shutil.which("ffuf"):
            return self._run_real_ffuf(base, words, host, user_agent)
        # Fallback: in-process probe.
        hits = []
        for w in words:
            url = f"{base.rstrip('/')}/{w.lstrip('/')}"
            try:
                req = urllib.request.Request(
                    url, method="GET",
                    headers={"User-Agent": user_agent})
                with urllib.request.urlopen(
                        req, timeout=self.timeout) as r:
                    if r.status < 400:
                        hits.append({"path": w, "url": url,
                                     "status": r.status})
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    hits.append({"path": w, "url": url,
                                 "status": exc.code})
            except (urllib.error.URLError, OSError):
                continue
        return _result("ffuf", host, "ok",
                       data={"base": base, "hits": hits,
                             "tested": len(words),
                             "engine": "fallback"},
                       raw=json.dumps(hits))

    def _run_real_ffuf(self, base, words, host, user_agent):
        wl_path = "/tmp/ra_wl_" + str(int(time.time() * 1000))
        with open(wl_path, "w") as fh:
            fh.write("\n".join(words) + "\n")
        argv = ["ffuf", "-u", base.rstrip("/") + "/FUZZ",
                "-w", wl_path, "-mc", "200,301,302,401,403",
                "-of", "json", "-s",
                "-H", f"User-Agent: {user_agent}"]
        rc, out = self._run_subprocess(argv)
        try:
            os.unlink(wl_path)
        except OSError:
            pass
        if out == "TIMEOUT":
            return _result("ffuf", host, "timeout",
                           error="ffuf exceeded timeout")
        hits = []
        try:
            obj = json.loads(out)
            for r in obj.get("results", []):
                hits.append({"path": r.get("input", {}).get("FUZZ"),
                             "url": r.get("url"),
                             "status": r.get("status")})
        except (json.JSONDecodeError, AttributeError):
            pass
        return _result("ffuf", host, "ok" if rc == 0 else "error",
                       data={"base": base, "hits": hits,
                             "tested": len(words),
                             "engine": "ffuf"},
                       raw=out)


def available_tools(scope: ScopeGuard | None = None) -> dict:
    s = scope or ScopeGuard()
    return {
        "nmap": NmapRunner(scope=s),
        "http": HttpProbe(scope=s),
        "ffuf": UrlFuzzer(scope=s),
    }
