# 2. Scope is a gate at the executor, not a list modules consult

Date: 2026-08-24
Status: Accepted

## Context
Recon tooling touches hosts. Touching a host outside the authorised scope is,
on a real engagement, a contract breach with legal weight — not a defect to fix
next sprint. The design question is therefore: how do we make out-of-scope access
*impossible*, not merely *discouraged*?

## Options considered
- **A. Each module checks scope.** The common pattern. Rejected: correctness
  depends on every module author remembering, forever, in every code path. One
  omission is a breach. New contributors will get it wrong.
- **B. A decorator modules must apply.** Better, but still opt-in — a module that
  forgets the decorator, or calls the network by another route, escapes.
- **C. Modules cannot touch the network at all; the executor owns a
  scope-checked Fetcher and hands it in (chosen).**

## Decision
- Modules are `(target, Fetcher) -> [Finding]`. They have no socket, no resolver,
  no HTTP client of their own.
- The executor constructs a `_GatedFetcher` bound to the run. Every method calls
  `scope.check()` before the backend and records the action in the ledger.
- `ScopeViolation` is **not** a subclass of `ValueError`, so a generic
  `except ValueError` in a module cannot accidentally swallow it.
- Exclusions beat inclusions, always. The exclusion is the thing someone
  authorised in writing.

## Consequences
- A new module is safe by construction. There is no way to write one that escapes
  scope, because the only network handle it receives is already gated.
- The guarantee is tested adversarially: `test_scope_gate.py` runs a
  `MaliciousModule` that deliberately targets an out-of-scope host and asserts the
  resolver is never reached; another test drives the `Fetcher` directly.
- Scope requires an `authorisation_ref`, enforced at construction. You cannot
  start a run without recording what authorised it.
- Cost: modules cannot do anything clever with raw sockets. That is the point.
