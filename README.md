# recon-agent

**Reconnaissance for engagements you are authorised to run — where scope is a gate every action passes through, not a list each module is trusted to remember.**

In most recon tooling, scope is advisory: a list that each module is supposed to consult. That works until one module forgets, and then you have touched a host you had no authorisation to touch. On a real engagement that is a contract breach, not a bug report.

This tool makes out-of-scope access **structurally impossible**. Modules never touch the network directly — they receive a scope-checked `Fetcher` from the executor, and that is the only network handle they get. There is no code path from a module to a target that skips the check, and there is a test that proves it by running a deliberately malicious module.

```
$ reconagent check www.example.com secret.example.com evil.com \
    --scope '*.example.com' --exclude secret.example.com --auth ENG-2026-014
IN-SCOPE   www.example.com
OUT-SCOPE  secret.example.com  (matches exclusion 'secret.example.com')
OUT-SCOPE  evil.com  (matches no inclusion rule)
```

## Authorised use only

This is a defensive/professional tool. It **requires** an authorisation reference on every scope — an engagement id, a bug-bounty programme, a ticket number — and refuses to run without one, because "what authorised this?" is the first question asked when recon touches the wrong host. Only use it against assets you own or have explicit written permission to test. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/recon-agent && cd recon-agent
python -m pip install -e ".[dev]"

# 1. Check scope without touching anything (safe to run anywhere)
reconagent check api.example.com --scope '*.example.com' --auth ENG-2026-014

# 2. Dry run: enumerate and scope-check, still no network
reconagent run example.com --scope '*.example.com' --scope example.com \
    --auth ENG-2026-014 --dry-run

# 3. Real run against your own infrastructure
reconagent run example.com --scope-file scope.json
```

`scope.json`:
```json
{
  "include": ["*.example.com", "example.com", "10.0.0.0/24"],
  "exclude": ["secret.example.com", "10.0.0.1"],
  "authorisation_ref": "ENG-2026-014"
}
```

## The scope model

| Rule form | Example | Matches |
|---|---|---|
| Host | `api.example.com` | exactly that host |
| Wildcard | `*.example.com` | any subdomain, **not** the apex |
| CIDR | `10.0.0.0/24` | any address in the range |
| Exclusion | `exclude: [secret.example.com]` | removes from scope — **exclusions always win** |

Exclusions beating inclusions is deliberate: on an engagement the exclusion is the thing someone put in writing. A target matching both an include wildcard and an exclude is out of scope, and `secret.example.com` stays untouched even though it resolves and matches `*.example.com`.

## Why the gate is credible

The guarantee is only worth as much as its test. `tests/test_scope_gate.py` runs a `MaliciousModule` that ignores its assigned target and tries to resolve `victim.evil.com` directly:

```python
def test_malicious_module_cannot_escape_scope(...):
    ex.resolver = lambda h: (reached.append(h), resolver(h))[1]
    ex.run(["example.com"])
    assert "victim.evil.com" not in reached   # GATE held
```

The out-of-scope attempt never reaches the resolver, and it is journaled as `refused`. A second test calls the `Fetcher` directly, bypassing `module.run` entirely, and the gate still refuses.

## Resumability and evidence

Every action — and every refusal — is written to a SQLite ledger. Two consequences:

- **Resume** an interrupted engagement with `--resume`; completed work is skipped, so you never re-scan.
- **Prove a negative.** "We did not touch that host" is a claim you may need to defend, and the ledger's `refused` records are the evidence. `reconagent report` prints the full run including refusals.

## Rate governance

A per-target minimum interval and a global concurrency cap (`--rate`, `--concurrency`) keep a run from hammering one host — which is both rude and self-defeating, since it gets you rate-limited or blocked. The governor is monotonic-clock based and injectable, so the test suite verifies backoff timing without ever sleeping.

## Commands

| Command | Purpose |
|---|---|
| `reconagent check` | Test targets against scope. **No network.** Exit 2 if any are out of scope. |
| `reconagent run` | Run recon within scope. `--dry-run`, `--resume`, `--rate`, `--concurrency`, `--json`. |
| `reconagent report` | Print a stored run: stats, findings, and refusals. |

## Extending it

A module is a pure function `(target, Fetcher) -> [Finding]`. It receives only the scope-checked `Fetcher`, so a new module is safe by construction — it *cannot* be written in a way that escapes scope. Bundled: DNS resolution, HTTP fingerprinting, and subdomain discovery.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=reconagent      # 35 tests, ~89% coverage
mypy --strict src/reconagent # clean
ruff check src tests         # clean
```

## License

MIT © vinzabe
