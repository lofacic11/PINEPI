from pathlib import Path


ROOT = Path(__file__).parents[1]
JAVASCRIPT = (ROOT / "app/static/js/app.js").read_text()
TEMPLATE = (ROOT / "app/templates/index.html").read_text()
CSS = (ROOT / "app/static/css/app.css").read_text()


def test_appliance_shell_sidebar_and_accessibility_contract():
    pages = (
        "Dashboard", "Campaigns / Audits", "Access Point", "Recon", "Logging", "Modules",
        "Captures", "Wireless Tools", "Security Analysis", "Packet Capture", "Diagnostics / Console", "Reports", "Settings",
    )
    for page in pages:
        assert page in TEMPLATE
    assert 'class="skip-link"' in TEMPLATE
    assert 'aria-live="polite"' in TEMPLATE
    assert 'aria-label="Primary navigation"' in TEMPLATE
    assert 'id="details-drawer"' in TEMPLATE
    assert 'id="mobile-menu"' in TEMPLATE
    assert "@media(max-width:900px)" in CSS


def test_recon_workflow_and_safe_wireless_rendering():
    assert 'data-recon-tab="scanning"' in TEMPLATE
    assert 'data-recon-tab="handshakes"' in TEMPLATE
    assert 'id="landscape-donut"' in TEMPLATE
    assert 'id="channel-chart"' in TEMPLATE
    assert 'id="recon-session"' in TEMPLATE
    assert 'id="ap-table-body"' in TEMPLATE
    assert 'id="client-table-body"' in TEMPLATE
    assert ".innerHTML" not in JAVASCRIPT
    assert "textContent" in JAVASCRIPT
    assert "eval(" not in JAVASCRIPT
    assert "document.write" not in JAVASCRIPT
    assert "Stop Recon to restore the adapter" in JAVASCRIPT
    assert 'session?.status === "running"' in JAVASCRIPT


def test_lab_password_is_visible_and_copy_has_http_fallback():
    assert 'id="lab-password" class="monospace" type="text"' in TEMPLATE
    assert 'id="copy-lab-password"' in TEMPLATE
    assert "navigator.clipboard?.writeText" in JAVASCRIPT
    assert 'document.execCommand("copy")' in JAVASCRIPT
    assert "fallback.select()" in JAVASCRIPT
    assert "console.log" not in JAVASCRIPT
    assert "this is not the original network password" in TEMPLATE


def test_active_test_ux_is_explicit_targeted_and_stoppable():
    assert 'id="active-authorized" type="checkbox" required' in TEMPLATE
    assert 'id="start-deauth"' in TEMPLATE
    assert 'id="start-mdk4"' in TEMPLATE
    assert 'id="stop-active"' in TEMPLATE
    assert "ACTIVE WIRELESS TEST" in JAVASCRIPT
    assert "Entire selected BSSID" in JAVASCRIPT
    assert 'headers["X-PinePi-Action"] = "confirmed"' in JAVASCRIPT
    assert "Custom aireplay" not in TEMPLATE
    assert "command" not in TEMPLATE.lower() or "arbitrary commands" in TEMPLATE.lower()


def test_capture_analysis_and_security_pages_are_present():
    for text in ("Frame Explorer", "Suricata IDS", "Zeek traffic summary", "Aircrack compatibility", "Rogue AP detection"):
        assert text in TEMPLATE or text in JAVASCRIPT
