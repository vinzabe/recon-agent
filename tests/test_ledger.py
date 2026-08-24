from reconagent.ledger import Ledger
from reconagent.scope import Scope


def _scope():
    return Scope.build(["example.com"], authorisation_ref="X").describe()


def test_run_lifecycle(tmp_path):
    with Ledger(tmp_path / "l.db") as led:
        rid = led.start_run(_scope())
        assert led.resume_latest() == rid   # unfinished => resumable
        led.finish_run(rid)
        assert led.resume_latest() is None  # finished => nothing to resume


def test_resumability_skips_completed_work(tmp_path):
    with Ledger(tmp_path / "l.db") as led:
        rid = led.start_run(_scope())
        assert not led.already_done(rid, "dns", "example.com")
        led.record(rid, "dns", "example.com", "completed", "1 finding")
        assert led.already_done(rid, "dns", "example.com")
        # a refused action does NOT count as done -> will be retried
        led.record(rid, "http", "example.com", "refused", "scope")
        assert not led.already_done(rid, "http", "example.com")


def test_findings_dedupe(tmp_path):
    with Ledger(tmp_path / "l.db") as led:
        rid = led.start_run(_scope())
        led.add_finding(rid, "example.com", "dns.a", "1.2.3.4", "dns")
        led.add_finding(rid, "example.com", "dns.a", "1.2.3.4", "dns")  # dup
        led.add_finding(rid, "example.com", "dns.a", "5.6.7.8", "dns")
        assert len(led.findings(rid)) == 2


def test_stats(tmp_path):
    with Ledger(tmp_path / "l.db") as led:
        rid = led.start_run(_scope())
        led.record(rid, "dns", "a.com", "completed")
        led.record(rid, "dns", "b.com", "refused", "scope")
        led.add_finding(rid, "a.com", "dns.a", "1.1.1.1", "dns")
        s = led.stats(rid)
        assert s["completed"] == 1 and s["refused"] == 1 and s["findings"] == 1


def test_schema_mismatch_fails_loudly(tmp_path):
    import sqlite3
    db = tmp_path / "l.db"
    with Ledger(db):
        pass
    c = sqlite3.connect(db)
    c.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    c.commit()
    c.close()
    import pytest
    with pytest.raises(RuntimeError, match="schema"):
        Ledger(db)
