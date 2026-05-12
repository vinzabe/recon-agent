"""CLI tests."""
from __future__ import annotations

import json

import pytest

from recon_agent.agent import ReconAgent
from recon_agent.cli import build_parser, cmd_list_tools, cmd_scan, main


def test_list_tools_prints_status(capsys):
    rc = main(["list-tools"])
    out = capsys.readouterr().out
    assert rc == 0
    for name in ("nmap", "http", "ffuf"):
        assert name in out


def test_scan_text_output(capsys):
    args = build_parser().parse_args(["scan", "127.0.0.1",
                                       "--max-steps", "0"])
    agent = ReconAgent(max_steps=0)
    rc = cmd_scan(args, agent=agent)
    out = capsys.readouterr().out
    assert rc == 0
    assert "Recon Engagement Report" in out


def test_scan_json_output(capsys):
    args = build_parser().parse_args(["scan", "127.0.0.1",
                                       "--max-steps", "0",
                                       "--format", "json"])
    rc = cmd_scan(args, agent=ReconAgent(max_steps=0))
    out = capsys.readouterr().out
    obj = json.loads(out)
    assert obj["engagement"]["target"] == "127.0.0.1"
    assert rc == 0


def test_scan_oos_target_recorded(capsys):
    args = build_parser().parse_args(["scan", "8.8.8.8",
                                       "--max-steps", "0",
                                       "--format", "json"])
    cmd_scan(args, agent=ReconAgent(max_steps=0))
    obj = json.loads(capsys.readouterr().out)
    assert obj["engagement"]["rejected_steps"]


def test_main_unknown_command():
    with pytest.raises(SystemExit):
        main(["nonsense"])


def test_main_requires_subcommand():
    with pytest.raises(SystemExit):
        main([])
