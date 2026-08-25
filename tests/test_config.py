from app.config import load_config


def test_load_config(tmp_path):
    path = tmp_path / "pinepi.toml"
    path.write_text('[storage]\nmax_capture_mb=500\n[adapters]\naudit_usb_ids=["1234:abcd"]\n')
    value = load_config(path)
    assert value.storage.max_capture_mb == 500
    assert value.adapters.audit_usb_ids == ("1234:abcd",)

