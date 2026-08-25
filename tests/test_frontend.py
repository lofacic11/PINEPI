from pathlib import Path


ROOT = Path(__file__).parents[1]
JAVASCRIPT = (ROOT / "app/static/js/app.js").read_text()
TEMPLATE = (ROOT / "app/templates/index.html").read_text()


def test_application_shell_and_accessibility_contract():
    for section in ("Dashboard", "Recon", "Audits", "Captures", "Training", "Reports", "Settings"):
        assert f">{section}<" in TEMPLATE
    assert 'class="skip"' in TEMPLATE
    assert 'aria-live="polite"' in TEMPLATE
    assert 'role="switch"' in TEMPLATE


def test_untrusted_recon_fields_are_escaped_before_html_rendering():
    assert "const $=id=>document.getElementById(id),esc=v=>" in JAVASCRIPT
    for field in ("a.vendor", "a.bssid", "ap.vendor", "c.vendor", "c.station_mac"):
        assert f"esc({field}" in JAVASCRIPT
    assert 'esc(a.hidden?"Hidden SSID":a.ssid)' in JAVASCRIPT
    assert 'esc(ap.hidden?"Hidden SSID":ap.ssid)' in JAVASCRIPT
    assert "eval(" not in JAVASCRIPT
    assert "document.write" not in JAVASCRIPT
