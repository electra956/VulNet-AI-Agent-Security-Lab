"""Documentation must describe what is actually implemented."""

from pathlib import Path

from lab.runner import all_test_cases

ROOT = Path(__file__).resolve().parents[2]


def test_every_test_id_is_documented():
    doc = (ROOT / "docs" / "owasp-agentic-top10.md").read_text(encoding="utf-8")
    missing = [t["test_id"] for t in all_test_cases() if f"`{t['test_id']}`" not in doc]
    assert not missing, f"docs/owasp-agentic-top10.md is missing: {missing}"


def test_required_docs_exist_and_are_not_stubs():
    for name in ("architecture", "demo-guide", "testing", "threat-model", "vulnerabilities", "owasp-agentic-top10",
                 "project-status", "development", "security-model"):
        p = ROOT / "docs" / f"{name}.md"
        assert p.exists() and len(p.read_text(encoding="utf-8")) > 1500, name


def test_project_status_has_the_required_sections():
    txt = (ROOT / "docs" / "project-status.md").read_text(encoding="utf-8").upper()
    for h in ("CURRENT VERSION", "CURRENT ARCHITECTURE", "IMPLEMENTED", "PARTIAL", "SIMULATED", "PLANNED", "KNOWN LIMITATIONS",
              "OWASP STATUS", "TEST STATUS", "RUN COMMANDS", "CONFIGURATION", "CURRENT GAPS", "NEXT STEP"):
        assert h in txt, h


def test_docs_do_not_use_the_wrong_owasp_taxonomy():
    for p in (ROOT / "docs").glob("*.md"):
        t = p.read_text(encoding="utf-8")
        assert "ASI08 - Excessive Agency" not in t and "ASI06 - Sensitive Information" not in t, p.name
