from pathlib import Path


INSTALLER = (Path(__file__).parents[1] / "scripts" / "install.sh").read_text()


def test_installer_manages_services_without_persisting_run_directory():
    assert "systemctl disable --now dnsmasq.service" in INSTALLER
    assert "systemctl enable pinepi-management-ap.service pinepi.service" in INSTALLER
    assert "systemctl restart pinepi-management-ap.service" in INSTALLER
    assert "systemctl restart pinepi.service" in INSTALLER
    assert "install -d /run/pinepi" not in INSTALLER
