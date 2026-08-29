from pathlib import Path


INSTALLER = (Path(__file__).parents[1] / "scripts" / "install.sh").read_text()


def test_installer_manages_services_without_persisting_run_directory():
    assert "systemctl disable --now dnsmasq.service" in INSTALLER
    assert "systemctl enable pinepi-management-ap.service pinepi.service" in INSTALLER
    assert "systemctl restart pinepi-management-ap.service" in INSTALLER
    assert "systemctl restart pinepi.service" in INSTALLER
    assert "install -d /run/pinepi" not in INSTALLER


def test_installer_separates_required_and_optional_tool_packages():
    assert "REQUIRED_PACKAGES=" in INSTALLER
    assert "OPTIONAL_PACKAGES=" in INSTALLER
    assert "apt-cache show" in INSTALLER
    assert "optional module package" in INSTALLER.lower()
    for package in ("aircrack-ng", "kismet", "hcxdumptool", "hcxtools", "python3-scapy", "mdk4", "suricata", "zeek"):
        assert package in INSTALLER
    assert "curl | bash" not in INSTALLER
