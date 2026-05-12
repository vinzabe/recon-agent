# recon-agent

LLM-driven defensive recon orchestrator. Wraps a small toolbox
(`nmap`, an HTTP probe, an `ffuf`-style URL fuzzer with in-process
fallback) and uses an LLM to pick which tool to run next, given the
state of the engagement.

The agent is **strictly defensive**:

- A :class:`ScopeGuard` enforces a hard allowlist of targets at the
  agent entrypoint, the planner, and every tool runner. Default scope
  is `127.0.0.0/8`, `::1`, `localhost`, and `scanme.nmap.org`. Add
  more with `--allow`.
- The LLM may only choose a **tool name** from a fixed catalog
  (`nmap`, `http`, `ffuf`). Unknown names are dropped and replaced
  with a deterministic fallback.
- The LLM may only choose **parameter keys** from a per-tool whitelist
  (`nmap.ports`, `http.method`, …) and parameter **values** are
  validated against `[A-Za-z0-9._,-/]+` so no shell metas can survive.
- Exploitation is out of scope. Scripts like `--script vuln` for nmap
  are **not** in the allowed-args list.

## Install

```sh
pip install -r requirements.txt
```

`nmap` is optional; if missing the runner returns
`status="binary_not_found"` and the engagement continues with the HTTP
probe and the in-process URL fuzzer fallback.

## Usage

```sh
python -m recon_agent.cli list-tools
python -m recon_agent.cli scan 127.0.0.1
python -m recon_agent.cli scan scanme.nmap.org --max-steps 3 --use-llm
python -m recon_agent.cli scan http://localhost:8080/ \
    --allow my-internal.test --format json --out report.json
```

## Programmatic use

```python
from recon_agent import ReconAgent, ScopeGuard, ReportWriter
agent = ReconAgent(scope=ScopeGuard(extra=("internal.test",)),
                   max_steps=4)
result = agent.run("127.0.0.1")
print(ReportWriter(result).to_markdown())
```

## Defense-in-depth scope

```
ReconAgent.run(target)        ->  ScopeGuard.check(target)   # (1)
LLMPlanner.plan(target, hist) ->  PlanStep(tool, target, …)
ReconAgent loop body          ->  ScopeGuard.is_allowed(step.target)  # (2)
ToolRunner.run(target, …)     ->  ScopeGuard.check(target)   # (3)
```

The planner is also constrained: tool names must be in
`ToolCatalog.tool_names`, parameter keys must be in
`ToolCatalog.allowed_params[tool]`, and values must match a strict
regex.

## Testing

```sh
pytest -q                                  # mocked
LLM_LIVE=1 pytest tests/test_llm_live.py   # 5 live LLM smoke tests
```

## License

MIT — see [LICENSE](LICENSE).
