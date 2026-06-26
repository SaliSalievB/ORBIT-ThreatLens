from pathlib import Path


def test_dashboard_contains_production_console_controls() -> None:
    html = Path("orbit/static/index.html").read_text(encoding="utf-8")

    assert "Local dashboard session" in html
    assert "Authorized use only" in html
    assert "Optional AI brief" in html
    assert "Reports redacted before gateway" in html
    assert "I am authorized to assess this target and accept responsibility for this scan." in html
    assert "id=\"ai-fields\" class=\"ai-fields\" hidden" in html
    assert "data-export=\"copy-json\"" in html
    assert "data-export=\"download-markdown\"" in html
    assert "scrollIntoView" in html
    assert "apiTokenInput.value = \"\";" in html
    assert "Always verify report details, risk context, and AI-generated guidance before making security decisions." in html
