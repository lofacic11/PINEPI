from __future__ import annotations

from app.services.capture import CaptureService
from app.services.database import Database
from app.services.recon import ReconService
from app.services.rogue_detection import RogueDetectionService


class ReportingService:
    def __init__(
        self,
        database: Database,
        recon: ReconService,
        rogue: RogueDetectionService,
        captures: CaptureService,
    ):
        self.database = database
        self.recon = recon
        self.rogue = rogue
        self.captures = captures

    def session_report(self, session_id: str) -> dict:
        session = self.recon.session(session_id)
        if not session:
            raise FileNotFoundError(session_id)
        security = self.database.query(
            "SELECT security,COUNT(*) count FROM access_points WHERE session_id=? GROUP BY security ORDER BY count DESC",
            (session_id,),
        )
        relationships = self.database.query(
            "SELECT relationship,COUNT(*) count FROM clients WHERE session_id=? GROUP BY relationship ORDER BY count DESC",
            (session_id,),
        )
        active_history = self.database.query(
            "SELECT id,type,status,started_at,finished_at,adapter,target_json,exit_code,error_code "
            "FROM operations WHERE type IN ('INJECTION_TEST','DEAUTH_TEST','MDK4_TEST') ORDER BY started_at DESC LIMIT 100"
        )
        return {
            "title": "PinePi authorized WLAN assessment summary",
            "session_id": session_id,
            "sections": {
                "observed_facts": {
                    "classification": "Observed fact",
                    "session": session,
                    "security_distribution": security,
                    "client_relationships": relationships,
                    "channels": self.recon.channels(session_id),
                    "captures": self.captures.list_captures()[:100],
                },
                "calculated_indicators": {
                    "classification": "Calculated indicator",
                    "rogue_analysis": self.rogue.analyze(session_id),
                },
                "operator_active_tests": {
                    "classification": "Operator-run active test",
                    "items": active_history,
                },
            },
            "limitations": [
                "Advertised WLAN properties and weighted indicators do not prove compromise.",
                "EAPOL counts are not equivalent to complete-message validation unless HCX results are attached.",
                "Sensitive keys, candidate passwords, and packet payloads are excluded.",
            ],
        }
