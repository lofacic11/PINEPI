from app.config import load_config


def test_load_config(tmp_path):
    path = tmp_path / "pinepi.toml"
    path.write_text('[storage]\nmax_capture_mb=500\n[adapters]\naudit_usb_ids=["1234:abcd"]\n')
    value = load_config(path)
    assert value.storage.max_capture_mb == 500
    assert value.adapters.audit_usb_ids == ("1234:abcd",)


def test_management_ap_configuration(tmp_path):
    path = tmp_path / "pinepi.toml"
    path.write_text(
        '[management_ap]\nenabled=true\nssid="Lab Admin"\npassword="safe-lab-password"\n'
        'address="10.55.0.1/24"\ndhcp_start="10.55.0.20"\ndhcp_end="10.55.0.80"\n'
        'channel=6\ncountry_code="at"\n'
    )
    value = load_config(path)
    assert value.management_ap.ssid == "Lab Admin"
    assert value.management_ap.password == "safe-lab-password"
    assert value.management_ap.address == "10.55.0.1/24"
    assert value.management_ap.country_code == "AT"


def test_management_and_training_subnets_must_differ(tmp_path):
    path = tmp_path / "pinepi.toml"
    path.write_text('[management_ap]\naddress="10.42.0.2/24"\n')
    try:
        load_config(path)
    except ValueError as exc:
        assert "must not overlap" in str(exc)
    else:
        raise AssertionError("overlapping AP subnets were accepted")
