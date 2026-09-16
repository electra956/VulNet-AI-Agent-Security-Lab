"""
VulNet FinTech AI Agent Security Lab - Agent Orchestrator & Specialized Agents Tests
Tests for Level 2 Step 8:
- Intent Classification & Task Planning
- Agent Routing (CustomerAgent, FraudAgent, TransactionAgent, ComplianceAgent, SupportAgent, FinancialResearchAgent)
- Main Agent tool execution boundary (Main Agent does not directly execute tools)
- Structured agent output contracts
- Financial safety invariant (no real financial execution, requires_tool / requires_approval status)
- Graceful handling of invalid agent requests
- End-to-end orchestrator pipeline coordination
"""

import pytest
from agents.main_agent import MainAgent
from agents.orchestrator import AgentOrchestrator
from agents.specialized_agents import (
    CustomerAgent,
    FinancialResearchAgent,
    TransactionAgent,
    FraudAgent,
    ComplianceAgent,
    SupportAgent,
)
from chatbot.sessions.session_manager import SessionContext


@pytest.fixture
def main_agent():
    return MainAgent()


@pytest.fixture
def orchestrator():
    return AgentOrchestrator(mode="secure")


@pytest.fixture
def sample_context():
    return {
        "user_id": "CUST-001",
        "account_ids": ["ACC-1001", "ACC-1002"],
        "role": "CUSTOMER",
        "session_id": "SESSION-TEST-001",
        "request_id": "REQ-TEST-001"
    }


# =====================================================================
# 1. INTENT CLASSIFICATION & TASK PLANNING TESTS
# =====================================================================

def test_intent_classification_balance(main_agent):
    """Verify 'What is my balance?' is classified as BALANCE_INQUIRY."""
    intent = main_agent.classify_intent("What is my balance?")
    assert intent == "BALANCE_INQUIRY"


def test_intent_classification_fraud(main_agent):
    """Verify 'Why was my transaction flagged?' is classified as FRAUD_DISPUTE."""
    intent = main_agent.classify_intent("Why was my transaction flagged?")
    assert intent == "FRAUD_DISPUTE"


def test_intent_classification_payment(main_agent):
    """Verify 'Transfer ₹5,000' is classified as PAYMENT_REQUEST."""
    intent = main_agent.classify_intent("Transfer ₹5,000 to ACC-1002")
    assert intent == "PAYMENT_REQUEST"


def test_intent_classification_compliance(main_agent):
    """Verify 'What are the KYC requirements?' is classified as COMPLIANCE_INQUIRY."""
    intent = main_agent.classify_intent("What are the KYC requirements?")
    assert intent == "COMPLIANCE_INQUIRY"


def test_intent_classification_support(main_agent):
    """Verify customer assistance query is classified as SUPPORT_REQUEST."""
    intent = main_agent.classify_intent("I need help to freeze my debit card")
    assert intent == "SUPPORT_REQUEST"


def test_main_agent_does_not_execute_tools_directly(main_agent):
    """Verify MainAgent produces task plans with can_execute_tools_directly=False."""
    plan = main_agent.create_plan("PAYMENT_REQUEST", "Transfer ₹5,000")
    assert plan["can_execute_tools_directly"] is False
    assert plan["requires_tool"] is True
    assert plan["tool_candidate"] == "create_payment"
    assert len(plan["steps"]) > 0


# =====================================================================
# 2. AGENT ROUTING TESTS
# =====================================================================

def test_routing_balance_to_customer_agent(main_agent):
    """Verify 'What is my balance?' routes to CustomerAgent."""
    routing = main_agent.plan_and_route("What is my balance?")
    assert routing["intent"] == "BALANCE_INQUIRY"
    assert routing["routed_agent"] == "CustomerAgent"


def test_routing_fraud_to_fraud_agent(main_agent):
    """Verify 'Why was my transaction flagged?' routes to FraudAgent."""
    routing = main_agent.plan_and_route("Why was my transaction flagged?")
    assert routing["intent"] == "FRAUD_DISPUTE"
    assert routing["routed_agent"] == "FraudAgent"


def test_routing_transfer_to_transaction_agent(main_agent):
    """Verify 'Transfer ₹5,000' routes to TransactionAgent."""
    routing = main_agent.plan_and_route("Transfer ₹5,000")
    assert routing["intent"] == "PAYMENT_REQUEST"
    assert routing["routed_agent"] == "TransactionAgent"


def test_routing_kyc_to_compliance_agent(main_agent):
    """Verify 'What are the KYC requirements?' routes to ComplianceAgent."""
    routing = main_agent.plan_and_route("What are the KYC requirements?")
    assert routing["intent"] == "COMPLIANCE_INQUIRY"
    assert routing["routed_agent"] == "ComplianceAgent"


def test_routing_support_to_support_agent(main_agent):
    """Verify 'I need help with my account' routes to SupportAgent."""
    routing = main_agent.plan_and_route("I need help with my account")
    assert routing["intent"] == "SUPPORT_REQUEST"
    assert routing["routed_agent"] == "SupportAgent"


# =====================================================================
# 3. STRUCTURED AGENT OUTPUT CONTRACTS
# =====================================================================

def test_customer_agent_structured_output(sample_context):
    """Verify CustomerAgent returns standard structured contract."""
    agent = CustomerAgent()
    plan = {"intent": "BALANCE_INQUIRY"}
    result = agent.process("What is my balance?", plan=plan, session_context=sample_context)

    assert result["agent"] == "CustomerAgent"
    assert result["intent"] == "BALANCE_INQUIRY"
    assert result["status"] == "completed"
    assert result["requested_action"] == "get_balance"
    assert "Customer Account Overview" in result["response"]
    assert result["metadata"]["customer_id"] == "CUST-001"


def test_fraud_agent_structured_output(sample_context):
    """Verify FraudAgent returns standard structured contract."""
    agent = FraudAgent()
    plan = {"intent": "FRAUD_DISPUTE"}
    result = agent.process("Why was my transaction flagged?", plan=plan, session_context=sample_context)

    assert result["agent"] == "FraudAgent"
    assert result["intent"] == "FRAUD_DISPUTE"
    assert result["status"] == "completed"
    assert result["requested_action"] == "review_flagged_transaction"
    assert "Fraud & Risk Operations Review" in result["response"]
    assert result["metadata"]["customer_id"] == "CUST-001"


def test_transaction_agent_simulated_payment_requires_tool(sample_context):
    """
    Verify TransactionAgent enforces financial safety:
    - Never executes real financial actions
    - Yields status='requires_tool'
    - Requested action='create_payment'
    """
    agent = TransactionAgent()
    plan = {"intent": "PAYMENT_REQUEST"}
    result = agent.process("Transfer ₹5,000 to ACC-1002", plan=plan, session_context=sample_context)

    assert result["agent"] == "TransactionAgent"
    assert result["intent"] == "PAYMENT_REQUEST"
    assert result["status"] == "requires_tool"
    assert result["requested_action"] == "create_payment"
    assert result["metadata"]["is_real_execution"] is False
    assert result["metadata"]["amount"] == 5000.0
    assert result["metadata"]["currency"] == "₹"


def test_transaction_agent_high_value_requires_approval(sample_context):
    """Verify transfer >= 10,000 yields status='requires_approval'."""
    agent = TransactionAgent()
    plan = {"intent": "PAYMENT_REQUEST"}
    result = agent.process("Transfer $15,000 to ACC-1002", plan=plan, session_context=sample_context)

    assert result["status"] == "requires_approval"
    assert result["metadata"]["amount"] == 15000.0
    assert "Approval Required" in result["response"]


def test_compliance_agent_structured_output(sample_context):
    """Verify ComplianceAgent returns standard structured contract."""
    agent = ComplianceAgent()
    plan = {"intent": "COMPLIANCE_INQUIRY"}
    result = agent.process("What are the KYC requirements?", plan=plan, session_context=sample_context)

    assert result["agent"] == "ComplianceAgent"
    assert result["intent"] == "COMPLIANCE_INQUIRY"
    assert result["status"] == "completed"
    assert result["requested_action"] == "get_kyc_requirements"
    assert "KYC" in result["response"]


def test_support_agent_structured_output(sample_context):
    """Verify SupportAgent returns standard structured contract."""
    agent = SupportAgent()
    plan = {"intent": "SUPPORT_REQUEST"}
    result = agent.process("Please freeze my debit card", plan=plan, session_context=sample_context)

    assert result["agent"] == "SupportAgent"
    assert result["intent"] == "SUPPORT_REQUEST"
    assert result["status"] == "completed"
    assert result["requested_action"] == "freeze_card"


# =====================================================================
# 4. ORCHESTRATOR CONTROL & INVALID REQUEST HANDLING
# =====================================================================

def test_orchestrator_handles_invalid_agent_request(orchestrator, sample_context):
    """Verify orchestrator gracefully rejects requests routed to nonexistent agents."""
    result = orchestrator.execute_agent(
        target_agent_name="NonExistentPaymentAgent",
        request="Transfer funds",
        session_context=sample_context
    )
    assert result["status"] == "invalid_request"
    assert result["agent"] == "NonExistentPaymentAgent"
    assert "Unrecognized Agent" in result["response"]
    assert result["metadata"]["error"] == "unrecognized_agent"


def test_orchestrator_end_to_end_process_routing(orchestrator):
    """Verify complete end-to-end pipeline dispatches to specialized agent under orchestrator control."""
    session_ctx = SessionContext(
        session_id="SESS-ORCH-001",
        request_id="REQ-ORCH-001",
        user_id="CUST-001",
        role="CUSTOMER",
        account_ids=["ACC-1001"],
        created_at="2026-09-16T12:00:00Z",
        conversation_id="CONV-ORCH-001"
    )
    result = orchestrator.process("What is my balance?", session_context=session_ctx)

    assert result["pipeline_status"] == "completed"
    assert result["intent"] == "BALANCE_INQUIRY"
    assert result["routed_agent"] == "CustomerAgent"
    assert result["specialized_agent_result"]["agent"] == "CustomerAgent"
    assert result["specialized_agent_result"]["status"] == "completed"
    assert "Customer Account Overview" in result["final_response"]
    assert any("Dispatching to CustomerAgent" in stage for stage in result["stages"])
