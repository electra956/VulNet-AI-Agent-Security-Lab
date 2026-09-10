from agents.orchestrator import AgentOrchestrator


def test_orchestrator_initialization():
    orch = AgentOrchestrator(mode="secure")
    assert orch.get_mode() == "secure"
    orch.set_mode("vulnerable")
    assert orch.get_mode() == "vulnerable"


def test_orchestrator_process_flow():
    orch = AgentOrchestrator(mode="secure")
    user_request = "What are the rules for AI agent tools?"
    result = orch.process(user_request)

    assert result["pipeline_status"] == "completed"
    assert result["user_request"] == user_request
    assert len(result["retrieved_documents"]) > 0
    assert result["main_agent"]["status"] == "completed"
    assert result["research_agent"]["status"] == "completed"
    assert result["action_agent"]["status"] == "completed"
    assert result["mcp_security_status"]["status"] == "success"
    assert result["mcp_audit_log"]["status"] == "success"
    assert "execution_time_ms" in result
    assert len(result["stages"]) > 0


if __name__ == "__main__":
    test_orchestrator_initialization()
    test_orchestrator_process_flow()
    print("Orchestrator tests passed successfully!")