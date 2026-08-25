from __future__ import annotations

import re


def classify_security(privacy: str, authentication: str = "", cipher: str = "") -> dict:
    evidence = f"{privacy} {authentication} {cipher}".upper().strip()
    if not evidence or evidence in {"UNKNOWN", "?"}:
        return _security("Unknown", "info", "Insufficient advertised security evidence.", "Inspect router configuration directly.")
    if "WEP" in evidence:
        return _security("WEP", "critical", "WEP is obsolete and insecure.", "Replace WEP with WPA2-CCMP or WPA3.")
    if "WPA3" in evidence or "SAE" in evidence:
        if "WPA2" in evidence:
            return _security("WPA2/WPA3 mixed", "low", "WPA3 transition mode is advertised.", "Prefer WPA3-only when all clients support it.")
        return _security("WPA3", "low", "Modern WPA3 protection is advertised.", "Keep firmware current and use a strong passphrase.")
    if "WPA2" in evidence:
        if re.search(r"\bWPA\b", evidence):
            return _security("WPA/WPA2 mixed", "medium", "A legacy WPA compatibility mode is advertised alongside WPA2.", "Disable WPA/TKIP compatibility and require WPA2-CCMP or WPA3.")
        enterprise = "EAP" in evidence or "MGT" in evidence
        mode = "WPA2 Enterprise" if enterprise else "WPA2"
        if "TKIP" in evidence:
            return _security(mode, "medium", "WPA2 is advertised with legacy TKIP.", "Disable TKIP and require CCMP/AES.")
        return _security(mode, "low", "WPA2 protection is advertised.", "Use CCMP, enable PMF where supported, and consider WPA3.")
    if "WPA" in evidence:
        return _security("WPA", "high", "Legacy WPA protection is advertised.", "Upgrade to WPA2-CCMP or WPA3.")
    if "OPN" in evidence or "OPEN" in evidence or "NONE" in evidence:
        return _security("Open", "high", "Traffic is not protected by Wi-Fi link encryption.", "Enable WPA2-CCMP or WPA3.")
    return _security("Unknown", "info", "The advertised flags could not be classified reliably.", "Inspect router configuration directly.")


def _security(mode: str, severity: str, explanation: str, recommendation: str) -> dict:
    return {"mode": mode, "severity": severity, "explanation": explanation, "recommendation": recommendation}


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
