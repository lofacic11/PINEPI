from __future__ import annotations

from app.services.database import Database


SECURITY_RANK = {"Open": 0, "WEP": 1, "WPA": 2, "WPA/WPA2 mixed": 3, "WPA2": 4, "WPA2 Enterprise": 4, "WPA2/WPA3 mixed": 5, "WPA3": 6}


class RogueDetectionService:
    def __init__(self, database: Database):
        self.database = database

    def analyze(self, session_id: str) -> dict:
        if not self.database.one("SELECT id FROM scan_sessions WHERE id=?", (session_id,)):
            raise FileNotFoundError(session_id)
        profiles = self.database.query("SELECT * FROM trusted_profiles ORDER BY ssid")
        findings = []
        for profile in profiles:
            approved = {
                row["bssid"]
                for row in self.database.query("SELECT bssid FROM trusted_bssids WHERE profile_id=?", (profile["id"],))
            }
            observed = self.database.query(
                "SELECT * FROM access_points WHERE session_id=? AND ssid=? ORDER BY signal DESC",
                (session_id, profile["ssid"]),
            )
            for ap in observed:
                score, reasons = 0, []
                if approved and ap["bssid"] not in approved:
                    score += 30
                    reasons.append({"weight": 30, "type": "unexpected_bssid", "message": "BSSID is not approved by the trusted profile."})
                expected_security = profile["expected_security"]
                if expected_security and ap["security"] != expected_security:
                    downgrade = SECURITY_RANK.get(ap["security"], -1) < SECURITY_RANK.get(expected_security, -1)
                    weight = 40 if downgrade else 20
                    score += weight
                    reasons.append({"weight": weight, "type": "security_mismatch", "message": f"Advertised security differs from expected {expected_security}."})
                expected_channels = {int(item) for item in profile["expected_channels"].split(",") if item.isdigit()}
                if expected_channels and ap.get("channel") not in expected_channels:
                    score += 10
                    reasons.append({"weight": 10, "type": "unexpected_channel", "message": "Channel is outside the trusted profile."})
                if profile["expected_vendor"] and ap["vendor"] != profile["expected_vendor"]:
                    score += 15
                    reasons.append({"weight": 15, "type": "unexpected_vendor", "message": "Vendor differs from the trusted profile."})
                if len(observed) > max(1, len(approved)):
                    score += 10
                    reasons.append({"weight": 10, "type": "duplicate_cluster", "message": "More BSSIDs advertise this SSID than the trusted profile expects."})
                if reasons:
                    findings.append({
                        "ssid": ap["ssid"],
                        "bssid": ap["bssid"],
                        "score": min(score, 100),
                        "risk": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW",
                        "classification": "Potential anomaly",
                        "reasons": reasons,
                        "disclaimer": "This weighted configuration mismatch is an investigation indicator, not proof of impersonation.",
                    })
        findings.sort(key=lambda item: item["score"], reverse=True)
        return {"session_id": session_id, "items": findings, "total": len(findings), "model": "explainable-weighted-v1"}
