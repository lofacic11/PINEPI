from app.services.audit import classify_security, score_security


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


def test_security_classification_is_conservative_and_supports_mixed_modes():
    assert classify_security("", "", "")["mode"] == "Unknown"
    assert classify_security("WPA WPA2", "PSK", "TKIP CCMP")["mode"] == "WPA/WPA2 mixed"
    result = classify_security("WPA2 WPA3", "SAE", "CCMP")
    assert result["mode"] == "WPA2/WPA3 mixed"
    assert "password strength" not in " ".join(result.values()).lower()
