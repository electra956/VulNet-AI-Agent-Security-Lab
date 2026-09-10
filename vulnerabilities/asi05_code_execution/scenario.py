"""
ASI05 - Unexpected Code Execution Simulation Module
Simulates dynamic code execution risks and AST-based safe evaluation defenses.
"""

import ast
from typing import Any, Dict, Optional
from security.security_controller import SecurityController


class ScenarioASI05:
    SCENARIO_ID = "ASI05"
    NAME = "Unexpected Code Execution"
    DESCRIPTION = (
        "Occurs when an agent autonomously generates and executes code without adequate sandboxing, "
        "enabling arbitrary code execution, file system access, or system compromise."
    )
    PRECONDITIONS = (
        "Agent has code execution capabilities (e.g. data science calculator or script runner) "
        "using raw eval/exec without AST validation or containerization."
    )
    DEFAULT_ATTACK_INPUT = "import os; os.system('whoami')"
    MITIGATION = (
        "Parse code using an AST validator, restrict execution to pure mathematical expressions, "
        "disallow imports/system calls, and execute untrusted logic within ephemeral sandboxes."
    )

    @classmethod
    def _validate_ast_safety(cls, code_str: str) -> Dict[str, Any]:
        """Inspect AST to detect prohibited syntax nodes (Imports, System calls)."""
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return {"safe": False, "reason": f"Syntax error: {str(e)}"}

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                return {"safe": False, "reason": "Import statements are strictly prohibited."}
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ["eval", "exec", "compile", "__import__", "open"]:
                    return {"safe": False, "reason": f"Forbidden built-in call: '{func.id}'"}
                if isinstance(func, ast.Attribute) and func.attr in ["system", "popen", "spawn", "exec"]:
                    return {"safe": False, "reason": f"Forbidden system invocation: '{func.attr}'"}

        return {"safe": True, "reason": "AST contains no forbidden constructs."}

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[str] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (unsafe execution simulated)."""
        code = attack_input or cls.DEFAULT_ATTACK_INPUT
        sec = SecurityController(mode="vulnerable")

        sec.log_event(
            event_type="UNSAFE_CODE_EXECUTION_SIMULATED",
            message=f"Raw dynamic code submitted and allowed for simulation: '{code}'",
            severity="HIGH",
            scenario=cls.SCENARIO_ID,
            component="CODE_SANDBOX",
            decision="ALLOW",
            metadata={"code": code, "simulation": True}
        )

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "submitted_code": code,
            "ast_validated": False,
            "execution_status": "SIMULATED_UNSAFE_EXECUTION_COMPLETED",
            "vulnerability_demonstrated": True,
            "outcome": (
                "⚠️ VULNERABLE: The raw code string was executed in the simulated runtime without AST validation. "
                "In real production, this enables full Remote Code Execution (RCE)."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[str] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (AST validation blocks dangerous constructs)."""
        code = attack_input or cls.DEFAULT_ATTACK_INPUT
        sec = SecurityController(mode="secure")

        validation = cls._validate_ast_safety(code)

        if not validation["safe"]:
            sec.log_event(
                event_type="UNEXPECTED_CODE_EXECUTION_BLOCKED",
                message=f"Dangerous code blocked by AST validator: {validation['reason']}",
                severity="CRITICAL",
                scenario=cls.SCENARIO_ID,
                component="CODE_SANDBOX",
                decision="BLOCK",
                metadata={"code": code, "reason": validation["reason"]}
            )
            status = "BLOCKED_BY_AST_VALIDATOR"
        else:
            status = "APPROVED_SAFE_EXECUTION"

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "submitted_code": code,
            "ast_validated": True,
            "validation_reason": validation["reason"],
            "execution_status": status,
            "vulnerability_demonstrated": False,
            "outcome": (
                f"🛡️ SECURE: AST validation detected hazardous code structure ({validation['reason']}). "
                "Execution was aborted safely."
            ),
            "telemetry_events": sec.get_events()
        }
