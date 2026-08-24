import json

import pytest

from reconagent.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def _scope_args(tmp_path):
    sf = tmp_path / "scope.json"
    sf.write_text(json.dumps({
        "include": ["*.example.com", "example.com"],
        "exclude": ["secret.example.com"],
        "authorisation_ref": "ENG-CLI-TEST"}))
    return ["--scope-file", str(sf)]


def test_check_in_and_out_of_scope(tmp_path, capsys):
    rc = main(["check", "www.example.com", "evil.com", *_scope_args(tmp_path)])
    out = capsys.readouterr().out
    assert "IN-SCOPE   www.example.com" in out
    assert "OUT-SCOPE  evil.com" in out
    assert rc == EXIT_FINDINGS  # something was out of scope


def test_run_requires_authorisation(tmp_path, capsys):
    rc = main(["run", "example.com", "--scope", "example.com"])  # no --auth
    assert rc == EXIT_ERROR
    assert "authorisation_ref is required" in capsys.readouterr().err


def test_dry_run_touches_no_network(tmp_path, capsys):
    rc = main(["--state", str(tmp_path / "s.db"), "run", "example.com",
               "--dry-run", *_scope_args(tmp_path)])
    # dry-run resolves nothing, so no findings
    assert rc == EXIT_OK
    assert "DRY RUN" in capsys.readouterr().out


def test_out_of_scope_seed_refused_in_run(tmp_path, capsys):
    rc = main(["--state", str(tmp_path / "s.db"), "run", "evil.com",
               "--dry-run", "--json", *_scope_args(tmp_path)])
    report = json.loads(capsys.readouterr().out)
    assert report["stats"].get("refused", 0) >= 1


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
