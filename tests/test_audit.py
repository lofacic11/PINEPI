from app.services.audit import score_security


def test_wpa3_is_strong():
    result = score_security({"privacy": "WPA3", "authentication": "SAE"})
    assert result["score"] == 95
    assert result["rating"] == "Strong"


def test_open_is_unsafe():
    result = score_security({"privacy": "OPN", "authentication": ""})
    assert result["score"] == 0
    assert result["rating"] == "Unsafe"


def test_tkip_penalty():
    assert score_security({"privacy": "WPA2 TKIP"})["score"] == 65

