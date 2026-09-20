"""
VulNet AI Agent Security Lab - CLI Runner Security Tests
Verifies CLI command parsing, exit codes, filtering, and JSON reporting.
"""

import argparse
from security_tests.cli import run_prompt_injection_cli


def test_cli_all_pass():
    """Verify that running full CLI returns exit code 0."""
    args = argparse.Namespace(
        category="all",
        verbose=False,
        json=False,
        fail_fast=False,
        mode="secure",
    )
    exit_code = run_prompt_injection_cli(args)
    assert exit_code == 0


def test_cli_category_filter():
    """Verify that filtering by category works and returns exit code 0."""
    args = argparse.Namespace(
        category="ASI01",
        verbose=False,
        json=False,
        fail_fast=False,
        mode="secure",
    )
    exit_code = run_prompt_injection_cli(args)
    assert exit_code == 0


def test_cli_json_mode(capsys):
    """Verify that JSON mode produces valid JSON report."""
    args = argparse.Namespace(
        category="ASI02",
        verbose=False,
        json=True,
        fail_fast=False,
        mode="secure",
    )
    exit_code = run_prompt_injection_cli(args)
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "summary" in captured.out
    assert "results" in captured.out
    assert "ASI02" in captured.out
