from agents.action_agent import ActionAgent


def test_action_agent_basic_execution():
    agent = ActionAgent()
    user_request = "What are the rules for AI agent tools?"
    research_result = {
        "status": "completed",
        "summary": "The Research Agent analyzed relevant security documents.",
        "documents_analyzed": 2
    }
    result = agent.execute(user_request, research_result, mode="secure")

    assert result["status"] == "completed"
    assert "approved" in result["decision"].lower()
    assert result["documents_analyzed"] == 2
    assert "Action Agent Result" in result["action"]


def test_action_agent_no_documents():
    agent = ActionAgent()
    result = agent.execute("Test request", {"documents_analyzed": 0}, mode="secure")
    assert result["status"] == "completed"
    assert result["documents_analyzed"] == 0


def test_action_agent_high_risk_authorization():
    agent = ActionAgent()
    # High risk action without authorization in Secure mode should be pending authorization
    result = agent.execute("Please delete all customer records", {"documents_analyzed": 1}, mode="secure", user_authorized=False)
    assert result["status"] == "pending_authorization"
    assert result["risk_tier"] == "HIGH"


if __name__ == "__main__":
    test_action_agent_basic_execution()
    test_action_agent_no_documents()
    test_action_agent_high_risk_authorization()
    print("Action Agent tests passed successfully!")
