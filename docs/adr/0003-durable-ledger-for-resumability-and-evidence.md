# 3. A durable ledger, for resumability AND for proving a negative

Date: 2026-08-24
Status: Accepted

## Context
Two needs that turn out to be the same feature:

1. An engagement interrupted at hour six must resume without re-scanning.
2. "We did not touch host X" is a claim an engagement may have to defend, and a
   claim needs evidence.

## Decision
Journal every action and every refusal to SQLite (WAL) before/as it happens:

- `actions(run_id, module, target, outcome)` with `outcome ∈ {completed, refused,
  error}`, uniquely keyed on `(run_id, module, target)`.
- `findings`, deduplicated on `(run_id, target, kind, value)`.
- Runs carry the full scope description including the authorisation reference.

Resumability: `already_done()` treats only `completed` as done. A `refused` or
`error` action is retried on resume — a refusal may have been a transient scope
edit, and an error is worth another attempt.

## Consequences
- `--resume` skips completed work; a re-run is idempotent.
- `report` emits refusals as first-class output, so the evidence that
  out-of-scope hosts were *not* touched is a query, not a reconstruction.
- Schema is versioned; a mismatch fails loudly rather than misreading an old
  ledger from a prior engagement.
