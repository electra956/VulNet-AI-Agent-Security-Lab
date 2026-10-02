"""
VulNet AI Agent Security Lab - Prompt Injection Security Testing Module
"""

from security_tests.canaries import (
    ALL_CANARY_VALUES,
    INTERNAL_CONFIG_CANARY,
    SYNTHETIC_CUSTOMERS,
    SYNTHETIC_SECRET_STORE,
    SYSTEM_CANARY,
    TEST_API_KEY,
    TEST_DB_TOKEN,
    TEST_SECRET,
    detect_canary_leak,
)
from security_tests.engine import SecurityTestEngine
from security_tests.models import (
    AttackCategory,
    SecurityTestCase,
    SecurityTestResult,
    TestResultStatus,
)
from security_tests.suites.direct_injection import get_direct_injection_test_cases
from security_tests.suites.indirect_rag_injection import get_indirect_rag_injection_test_cases
from security_tests.suites.owasp_asi import (
    get_all_security_test_cases,
    get_test_cases_by_category,
)
from security_tests.suites.secret_exfiltration import get_secret_exfiltration_test_cases
from security_tests.suites.tool_mcp_injection import get_tool_mcp_injection_test_cases

__all__ = [
    "SecurityTestEngine",
    "SecurityTestCase",
    "SecurityTestResult",
    "AttackCategory",
    "TestResultStatus",
    "detect_canary_leak",
    "TEST_API_KEY",
    "TEST_DB_TOKEN",
    "TEST_SECRET",
    "SYSTEM_CANARY",
    "INTERNAL_CONFIG_CANARY",
    "SYNTHETIC_SECRET_STORE",
    "SYNTHETIC_CUSTOMERS",
    "ALL_CANARY_VALUES",
    "get_all_security_test_cases",
    "get_test_cases_by_category",
    "get_direct_injection_test_cases",
    "get_indirect_rag_injection_test_cases",
    "get_tool_mcp_injection_test_cases",
    "get_secret_exfiltration_test_cases",
]
