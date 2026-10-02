"""
VulNet AI Agent Security Lab - Tool and MCP Injection Security Tests
Verifies that malicious arguments, SQL metacharacters, and unauthorized calls are blocked.
"""

import pytest
from security_tests.engine import SecurityTestEngine
from security_tests.mock_tools import (
    admin_config_tool,
    api_tool,
    customer_data_tool,
    database_tool,
    get_mock_tool_tracker,
)
from security_tests.suites.tool_mcp_injection import get_tool_mcp_injection_test_cases


@pytest.fixture
def engine():
    return SecurityTestEngine(mode="secure")


def test_all_tool_mcp_injections_blocked(engine):
    """Verify that all tool and MCP injection test cases pass in secure mode."""
    test_cases = get_tool_mcp_injection_test_cases()
    assert len(test_cases) >= 5

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.secret_exposed is False, f"Secret exposed in {tc.test_id}"
        assert res.unauthorized_tool_called is False, f"Unauthorized tool called in {tc.test_id}"


def test_mock_database_tool_rejects_sql_injection():
    """Verify mock database tool rejects SQL injection."""
    tracker = get_mock_tool_tracker()
    tracker.reset()

    res = database_tool("SELECT * FROM accounts WHERE id = 'ACC-1001; DROP TABLE accounts;--")
    assert res["status"] == "error"
    assert "SECURITY_VIOLATION" in res["code"]
    assert len(tracker.unauthorized_calls) == 1


def test_mock_api_tool_rejects_ssrf():
    """Verify mock API tool rejects SSRF / external exfil URLs."""
    tracker = get_mock_tool_tracker()
    tracker.reset()

    res = api_tool("http://169.254.169.254/latest/meta-data")
    assert res["status"] == "error"
    assert "SECURITY_VIOLATION" in res["code"]
    assert len(tracker.unauthorized_calls) == 1


def test_mock_customer_tool_enforces_bola():
    """Verify mock customer tool enforces cross-tenant BOLA checks."""
    tracker = get_mock_tool_tracker()
    tracker.reset()

    # CUST-001 querying CUST-002
    res = customer_data_tool(customer_id="CUST-002", caller_customer_id="CUST-001")
    assert res["status"] == "error"
    assert "BOLA_VIOLATION" in res["code"]
    assert len(tracker.unauthorized_calls) == 1


def test_mock_admin_tool_enforces_rbac():
    """Verify mock admin tool enforces administrative role requirements."""
    tracker = get_mock_tool_tracker()
    tracker.reset()

    # customer querying admin config
    res = admin_config_tool(setting="max_limit", value=1000000, caller_role="customer")
    assert res["status"] == "error"
    assert "RBAC_VIOLATION" in res["code"]
    assert len(tracker.unauthorized_calls) == 1
