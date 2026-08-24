"""reconagent — reconnaissance for engagements you are authorised to run.

The design premise: **scope is a gate, not a guideline.** In most recon tooling,
scope is a list each module is trusted to consult. That works until one module
forgets, and then you have scanned something you had no authorisation to touch —
which on a real engagement is a contract breach, not a bug report.

Here the executor owns the scope oracle. A module cannot reach the network except
by asking the executor, and the executor refuses anything the oracle does not
authorise. There is no code path from a module to a target that skips the check.
"""
__version__ = "1.0.0"
