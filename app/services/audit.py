from __future__ import annotations


def score_security(target: dict) -> dict:
    privacy = f"{target.get('privacy', '')} {target.get('authentication', '')}".upper()
    findings: list[str] = []
    if "WPA3" in privacy or "SAE" in privacy:
        score, rating = 95, "Strong"
        findings.append("WPA3/SAE is advertised.")
    elif "WPA2" in privacy:
        score, rating = 80, "Good"
        findings.append("WPA2 protection is advertised.")
    elif "WPA" in privacy:
        score, rating = 40, "Weak"
        findings.append("Legacy WPA is advertised and should be upgraded.")
    elif "WEP" in privacy:
        score, rating = 10, "Unsafe"
        findings.append("WEP is obsolete and readily breakable.")
    else:
        score, rating = 0, "Unsafe"
        findings.append("The network appears open and provides no link-layer encryption.")
    if "TKIP" in privacy:
        score = max(0, score - 15)
        findings.append("TKIP is a legacy cipher and should be disabled.")
    findings.append("This rating is based only on passively advertised capabilities.")
    return {"score": score, "rating": rating, "findings": findings}

