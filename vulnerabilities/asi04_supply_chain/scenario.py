"""
ASI04 - Agentic Supply Chain Vulnerabilities Simulation Module
Simulates third-party tool/plugin integrity checks and tampered dependency detection.
"""

import hashlib
from typing import Any, Dict, Optional
from security.security_controller import SecurityController


class ScenarioASI04:
    SCENARIO_ID = "ASI04"
    NAME = "Agentic Supply Chain Vulnerabilities"
    DESCRIPTION = (
        "Risks arising from incorporating third-party prompt templates, external MCP tools, "
        "unverified dependencies, or compromised model weights into the agent ecosystem without integrity verification."
    )
    PRECONDITIONS = (
        "Agent or orchestrator dynamically loads third-party plugins or dependencies without "
        "signature verification or hash pinning."
    )
    DEFAULT_ATTACK_INPUT = {
        "package_name": "community_data_parser_v2",
        "vendor": "unverified_community_repo",
        "expected_sha256": "4a7d1ed414474e4033ac29ccb8653d9b",
        "payload_content": "# Injected backdoor telemetry probe\ndef execute(): return 'EXFILTRATED_DATA'"
    }
    MITIGATION = (
        "Enforce cryptographic hash pinning, signature validation, vendor provenance checks, "
        "and sandboxing for all third-party agent tools and dependencies."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (unverified package loaded)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        pkg_name = data.get("package_name")
        vendor = data.get("vendor")

        sec = SecurityController(mode="vulnerable")
        sec.log_event(
            event_type="UNVERIFIED_PACKAGE_LOADED",
            message=f"Third-party tool package '{pkg_name}' loaded without integrity check in Vulnerable Mode.",
            severity="WARNING",
            scenario=cls.SCENARIO_ID,
            component="SUPPLY_CHAIN",
            decision="ALLOW",
            metadata={"package": pkg_name, "vendor": vendor, "simulation": True}
        )

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "package_name": pkg_name,
            "vendor": vendor,
            "integrity_verified": False,
            "loaded_status": "SUCCESSFULLY_LOADED_IN_SIMULATION",
            "vulnerability_demonstrated": True,
            "outcome": (
                f"⚠️ VULNERABLE: Package '{pkg_name}' from unverified vendor '{vendor}' was loaded without verification. "
                "In an unhardened environment, a malicious dependency could compromise the host runtime."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (tampered/unverified package blocked)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        pkg_name = data.get("package_name")
        vendor = data.get("vendor")
        payload = data.get("payload_content", "")
        expected_hash = data.get("expected_sha256", "")

        actual_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        hash_matched = (actual_hash == expected_hash)
        vendor_trusted = (vendor == "official_vulnet_verified")

        sec = SecurityController(mode="secure")

        if not hash_matched or not vendor_trusted:
            sec.log_event(
                event_type="SUPPLY_CHAIN_INTEGRITY_FAILURE",
                message=f"Package '{pkg_name}' failed integrity/provenance check: Untrusted vendor '{vendor}'.",
                severity="CRITICAL",
                scenario=cls.SCENARIO_ID,
                component="SUPPLY_CHAIN",
                decision="BLOCK",
                metadata={"package": pkg_name, "actual_hash": actual_hash, "vendor": vendor}
            )
            loaded_status = "BLOCKED_INTEGRITY_VIOLATION"
        else:
            loaded_status = "VERIFIED_AND_LOADED"

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "package_name": pkg_name,
            "vendor": vendor,
            "integrity_verified": False,
            "loaded_status": loaded_status,
            "vulnerability_demonstrated": False,
            "outcome": (
                f"🛡️ SECURE: Package '{pkg_name}' from vendor '{vendor}' was blocked. "
                "Cryptographic signature check and vendor provenance validation rejected the untrusted component."
            ),
            "telemetry_events": sec.get_events()
        }
