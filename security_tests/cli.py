"""
VulNet AI Agent Security Lab - Prompt Injection Security CLI Runner
Enables executing automated security evaluations from the command line.

Usage:
    python -m security_tests prompt-injection
    python -m security_tests prompt-injection --verbose
    python -m security_tests prompt-injection --category ASI01
    python -m security_tests prompt-injection --json
    python -m security_tests prompt-injection --fail-fast
"""

import argparse
import json
import sys
import time
from typing import List

from security_tests.engine import SecurityTestEngine
from security_tests.models import SecurityTestCase, SecurityTestResult, TestResultStatus
from security_tests.suites.owasp_asi import get_all_security_test_cases, get_test_cases_by_category


def run_prompt_injection_cli(args: argparse.Namespace) -> int:
    """Executes prompt injection evaluation suite via CLI arguments."""
    category = getattr(args, "category", None) or "all"
    verbose = getattr(args, "verbose", False)
    output_json = getattr(args, "json", False)
    fail_fast = getattr(args, "fail_fast", False)
    mode = getattr(args, "mode", "secure")

    test_cases: List[SecurityTestCase] = get_test_cases_by_category(category)

    if not test_cases:
        if output_json:
            print(json.dumps({"error": f"No test cases found matching category '{category}'"}))
        else:
            print(f"[-] No test cases found matching category: '{category}'")
        return 1

    engine = SecurityTestEngine(mode=mode)
    results: List[SecurityTestResult] = []

    if not output_json:
        print("=" * 80)
        print("  VULNET AI AGENT - PROMPT INJECTION SECURITY TEST SUITE")
        print("=" * 80)
        print(f"[*] Target Mode: {mode.upper()}")
        print(f"[*] Filter Category: {category.upper()}")
        print(f"[*] Total Test Cases: {len(test_cases)}")
        print(f"[*] Fail-Fast: {fail_fast}")
        print("=" * 80)

    t0 = time.time()
    total_passed = 0
    total_failed = 0
    total_canary_leaks = 0
    total_unauth_tools = 0

    for idx, tc in enumerate(test_cases, 1):
        res = engine.run_test(tc)
        results.append(res)

        if res.result == TestResultStatus.PASS.value:
            total_passed += 1
        else:
            total_failed += 1

        if res.secret_exposed:
            total_canary_leaks += 1
        if res.unauthorized_tool_called:
            total_unauth_tools += 1

        if not output_json:
            status_symbol = "[PASS]" if res.result == "PASS" else "[FAIL]"
            print(f"{status_symbol} ({idx:02d}/{len(test_cases):02d}) [{res.test_id}] {tc.name} ({res.execution_time_ms:.1f}ms)")
            if verbose or res.result == "FAIL":
                print(f"       Attack: {res.attack}")
                print(f"       Verdict: Blocked={res.blocked} | Secret Leaked={res.secret_exposed} | Unauth Tool={res.unauthorized_tool_called}")
                print(f"       Evidence: {res.evidence}")
                print(f"       Details: {res.details}")
                print("-" * 80)

        if fail_fast and res.result == TestResultStatus.FAIL.value:
            if not output_json:
                print(f"[!] Fail-Fast triggered on test {res.test_id}. Aborting remaining tests.")
            break

    total_time_ms = round((time.time() - t0) * 1000, 2)

    if output_json:
        report = {
            "summary": {
                "total_tests": len(results),
                "passed": total_passed,
                "failed": total_failed,
                "canary_leaks": total_canary_leaks,
                "unauthorized_tool_calls": total_unauth_tools,
                "mode": mode,
                "category": category,
                "total_duration_ms": total_time_ms,
                "status": "PASSED" if total_failed == 0 else "FAILED",
            },
            "results": [r.to_dict() for r in results]
        }
        print(json.dumps(report, indent=2))
    else:
        print("=" * 80)
        print("  SECURITY EVALUATION SUMMARY")
        print("=" * 80)
        print(f"  Total Tests Run:           {len(results)}")
        print(f"  Passed:                    {total_passed}")
        print(f"  Failed:                    {total_failed}")
        print(f"  Synthetic Canary Leaks:    {total_canary_leaks}")
        print(f"  Unauthorized Tool Calls:   {total_unauth_tools}")
        print(f"  Total Duration:            {total_time_ms:.2f}ms")
        print("=" * 80)
        if total_failed == 0:
            print("  >>> VERDICT: ALL SECURITY EVALUATIONS PASSED (100% INVARIANTS PRESERVED) <<<")
        else:
            print(f"  >>> VERDICT: {total_failed} SECURITY EVALUATIONS FAILED <<<")
        print("=" * 80)

    return 0 if total_failed == 0 else 1


def run_owasp_cli(args: argparse.Namespace) -> int:
    """Run the executable OWASP Agentic lab tests and print a status table."""
    from lab.runner import run_all, summarize
    cat = None if args.category.lower() == "all" else args.category
    records = run_all(cat, use_llm=getattr(args, "llm", False))
    if getattr(args, "json", False):
        print(json.dumps({"summary": summarize(records), "tests": [r.to_dict() for r in records]}, indent=2, default=str))
    else:
        for r in records:
            print(f"{r.status:10} {r.test_id:36} control={r.security_control}  trace={r.trace_id}")
        print(json.dumps(summarize(records)))
    return 0 if records and all(r.status in ("PASS", "SIMULATED") for r in records) else 1


def main() -> None:
    """Main CLI entrypoint."""
    # Ensure UTF-8 stdout encoding on Windows
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="security_tests",
        description="VulNet AI Agent - Automated Prompt Injection & Security Testing Suite"
    )

    subparsers = parser.add_subparsers(dest="command", help="Security test commands")

    # Command: prompt-injection
    pi_parser = subparsers.add_parser(
        "prompt-injection",
        help="Run prompt injection, context manipulation, and canary protection test suite"
    )
    pi_parser.add_argument(
        "--category", "-c",
        type=str,
        default="all",
        help="Filter by category (e.g. ASI01, ASI02, direct, rag, tool, secret, all)"
    )
    pi_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed execution traces and evidence for all test cases"
    )
    pi_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results in structured JSON format"
    )
    pi_parser.add_argument(
        "--fail-fast", "-f",
        action="store_true",
        help="Stop test execution immediately upon first failure"
    )
    pi_parser.add_argument(
        "--mode", "-m",
        type=str,
        choices=["secure", "vulnerable"],
        default="secure",
        help="Security mode for testing (default: secure)"
    )

    ow = subparsers.add_parser("owasp", help="Run the executable OWASP Agentic Top 10 lab tests (vulnerable vs secure)")
    ow.add_argument("--category", "-c", default="all", help="ASI01..ASI10 or all")
    ow.add_argument("--json", "-j", action="store_true", help="Structured JSON output")
    ow.add_argument("--llm", action="store_true", help="Let the real local Ollama model make the agent's decisions")

    args = parser.parse_args()

    if args.command == "owasp":
        sys.exit(run_owasp_cli(args))
    if args.command in ("prompt-injection", None):
        exit_code = run_prompt_injection_cli(args)
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
