# Threat model & authorised-use statement

## Intended use
Professional reconnaissance during **authorised** engagements: penetration tests
with a signed scope, bug-bounty programmes with a published scope, and inventory
of infrastructure you own. The tool refuses to run without an authorisation
reference precisely to keep this front-of-mind.

## Not for
Scanning, enumerating, or probing systems you do not own and are not authorised
to test. That is illegal in most jurisdictions regardless of intent. This tool
provides no capability that assumes otherwise, and its scope gate is designed to
*prevent* accidental over-reach, not to be worked around.

## The core security property
**A module cannot act on a target the scope oracle does not authorise.** Modules
receive only a scope-checked `Fetcher`; there is no unchecked network path. This
is enforced at the executor, not delegated to module authors, and is verified by
adversarial tests (`test_scope_gate.py`).

## Trust boundaries
- **The scope and its authorisation reference are operator-supplied and trusted.**
  Garbage in, garbage out: an operator who lists `*.` everything gets what they
  asked for. The tool validates rule syntax and requires an auth ref; it cannot
  validate that the authorisation is genuine.
- **The ledger is trusted and unencrypted.** It is engagement evidence; protect
  it as such. Anyone who can write it can forge history.
- **DNS and HTTP responses are untrusted data.** Findings are recorded verbatim
  and never executed or interpreted as commands.

## Explicit non-goals
- **Active exploitation.** This is reconnaissance only — resolution, fingerprint
  headers, subdomain discovery. It does not attack, fuzz, or send payloads.
- **Evasion.** It makes no attempt to bypass rate limits, WAFs, or detection. The
  rate governor exists to be a *good citizen*, not to fly under a radar.
- **Authorisation verification.** It records the reference you supply; it cannot
  confirm the engagement is real. That responsibility is yours.
- **Exhaustive scope parsing.** IDN/punycode edge cases and overlapping CIDR/host
  rules resolve by the documented precedence (exclude > include); exotic inputs
  should be checked with `reconagent check` before a live run.

## What could still go wrong
- A scope that is too broad. Mitigation: `check` and `--dry-run` let you verify
  the boundary before any packet is sent.
- A resolver or corporate proxy that redirects lookups. The gate checks the
  *target name*, not where the OS ultimately routes it; run from a network you
  control.
- Rate limits below the governor's floor. Tune `--rate` per engagement.

## Reporting
Scope-gate escapes — any case where an out-of-scope target is reached — to
**gabejar@usa.com**. This is treated as a critical security bug.
