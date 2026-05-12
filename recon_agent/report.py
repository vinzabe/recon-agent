"""Report writers."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .agent import ReconResult


@dataclass
class ReportWriter:
    result: ReconResult

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.result.to_dict(), indent=indent,
                          default=str)

    def to_markdown(self) -> str:
        eng = self.result.engagement
        lines = [
            "# Recon Engagement Report",
            "",
            f"- Target: `{eng.target}`",
            f"- Steps run: **{len(eng.history)}**",
            f"- Steps rejected: **{len(eng.rejected_steps)}**",
            f"- Findings: **{len(self.result.findings)}**",
            "",
        ]
        if eng.history:
            lines.append("## Steps")
            for i, h in enumerate(eng.history, 1):
                step = h["step"]
                res = h["result"]
                lines.append(
                    f"{i}. `{step['tool']}` on `{step['target']}` "
                    f"=> {res.get('status')}"
                    + (f" — {step['rationale']}"
                       if step.get('rationale') else ""))
        if self.result.findings:
            lines.append("")
            lines.append("## Findings")
            for f in self.result.findings:
                if f["kind"] == "open_port":
                    lines.append(
                        f"- **open** {f['host']}:{f['port']}/"
                        f"{f['proto']} ({f.get('service', '?')})")
                elif f["kind"] == "http_response":
                    lines.append(
                        f"- HTTP `{f['status_code']}` "
                        f"{f.get('url', '')}")
                elif f["kind"] == "url_hit":
                    lines.append(
                        f"- URL hit `{f['status_code']}` "
                        f"`/{f['path']}`")
        if eng.rejected_steps:
            lines.append("")
            lines.append("## Rejected Steps")
            for r in eng.rejected_steps:
                lines.append(f"- {r['reason']}")
        return "\n".join(lines)
