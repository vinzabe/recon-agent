# Security Policy

## Reporting a Vulnerability

Report privately to **g@abejar.net**. Do not open a public issue.

## Authorised Targets

`recon-agent` is for **defensive use against systems you own or are
explicitly authorised to test.** The bundled scope guard allows only:

- `127.0.0.0/8` (IPv4 loopback)
- `::1` (IPv6 loopback)
- `localhost`
- `scanme.nmap.org` — Nmap's official test target
- any host(s) you explicitly pass via `--allow` / `extra=`

The agent rejects any out-of-scope target at three layers (entry,
planner, runner). Reports demonstrating a way to bypass any of these
layers are in scope.

## What's Out of Scope

- Findings that require modifying the action whitelist or scope guard.
- Generic LLM jailbreak topics that do not relate to the tool/scope
  whitelists.
- Exploitation tooling (this project is recon only).
