"""Durable run ledger.

An engagement interrupted at hour six must resume without re-scanning, and must
produce a complete evidence chain for the report. Every action — and every
refusal — is journaled, because "we did not touch that host" is a claim you may
need to prove.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import sqlite3
import uuid
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    TEXT NOT NULL REFERENCES runs(id),
    module    TEXT NOT NULL,
    target    TEXT NOT NULL,
    outcome   TEXT NOT NULL,     -- completed | refused | error
    detail    TEXT,
    result    TEXT,
    at        TEXT NOT NULL,
    UNIQUE(run_id, module, target)
);
CREATE TABLE IF NOT EXISTS findings (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  TEXT NOT NULL REFERENCES runs(id),
    target  TEXT NOT NULL,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    module  TEXT NOT NULL,
    at      TEXT NOT NULL,
    UNIQUE(run_id, target, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id, outcome);
"""


@dataclasses.dataclass(frozen=True, slots=True)
class Action:
    module: str
    target: str
    outcome: str
    detail: str | None
    at: str


class Ledger:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._c = sqlite3.connect(self.path, isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.execute("PRAGMA foreign_keys=ON")
        self._c.executescript(_SCHEMA)
        row = self._c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._c.execute(
                "INSERT INTO meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),))
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(
                f"ledger schema {row['value']} != engine {SCHEMA_VERSION}")

    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.UTC).isoformat()

    def start_run(self, scope_desc: dict[str, object]) -> str:
        rid = uuid.uuid4().hex
        self._c.execute("INSERT INTO runs(id,scope,started_at) VALUES(?,?,?)",
                        (rid, json.dumps(scope_desc, sort_keys=True), self._now()))
        return rid

    def finish_run(self, run_id: str) -> None:
        self._c.execute("UPDATE runs SET finished_at=? WHERE id=?",
                        (self._now(), run_id))

    def resume_latest(self) -> str | None:
        row = self._c.execute(
            "SELECT id FROM runs WHERE finished_at IS NULL"
            " ORDER BY started_at DESC LIMIT 1").fetchone()
        return None if row is None else row["id"]

    def already_done(self, run_id: str, module: str, target: str) -> bool:
        row = self._c.execute(
            "SELECT 1 FROM actions WHERE run_id=? AND module=? AND target=?"
            " AND outcome='completed'", (run_id, module, target)).fetchone()
        return row is not None

    def record(self, run_id: str, module: str, target: str, outcome: str,
               detail: str | None = None, result: object = None) -> None:
        self._c.execute(
            "INSERT INTO actions(run_id,module,target,outcome,detail,result,at)"
            " VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(run_id,module,target) DO UPDATE SET"
            " outcome=excluded.outcome, detail=excluded.detail,"
            " result=excluded.result, at=excluded.at",
            (run_id, module, target, outcome, detail,
             json.dumps(result) if result is not None else None, self._now()))

    def add_finding(self, run_id: str, target: str, kind: str, value: str,
                    module: str) -> None:
        self._c.execute(
            "INSERT OR IGNORE INTO findings(run_id,target,kind,value,module,at)"
            " VALUES(?,?,?,?,?,?)",
            (run_id, target, kind, value, module, self._now()))

    def findings(self, run_id: str) -> list[dict[str, str]]:
        return [dict(r) for r in self._c.execute(
            "SELECT target,kind,value,module,at FROM findings WHERE run_id=?"
            " ORDER BY target,kind", (run_id,))]

    def actions(self, run_id: str, outcome: str | None = None) -> list[Action]:
        q = "SELECT module,target,outcome,detail,at FROM actions WHERE run_id=?"
        args: tuple[object, ...] = (run_id,)
        if outcome:
            q += " AND outcome=?"
            args += (outcome,)
        return [Action(r["module"], r["target"], r["outcome"], r["detail"], r["at"])
                for r in self._c.execute(q + " ORDER BY id", args)]

    def stats(self, run_id: str) -> dict[str, int]:
        base = {r["outcome"]: r["n"] for r in self._c.execute(
            "SELECT outcome, COUNT(*) AS n FROM actions WHERE run_id=?"
            " GROUP BY outcome", (run_id,))}
        base["findings"] = self._c.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE run_id=?",
            (run_id,)).fetchone()["n"]
        return base
