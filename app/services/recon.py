from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.audit import classify_security
from app.services.database import Database
from app.services.helper import HelperClient
from app.services.mock_data import MOCK_APS, MOCK_CLIENTS
from app.services.process_manager import ProcessManager
from app.services.recon_parser import normalize_mac, parse_airodump, signal_quality
from app.services.vendor import VendorLookup

SESSION_STATES = {"preparing", "running", "stopping", "completed", "failed", "interrupted"}
SORT_FIELDS = {
    "signal_desc": "ap.signal DESC", "signal_asc": "ap.signal ASC", "ssid": "ap.ssid COLLATE NOCASE ASC",
    "channel": "ap.channel ASC", "security": "ap.security ASC", "clients": "client_count DESC",
    "first_seen": "ap.first_seen ASC", "last_seen": "ap.last_seen DESC",
}


class ReconService:
    def __init__(self, config: AppConfig, helper: HelperClient, database: Database, operations: ProcessManager):
        self.config, self.helper, self.db, self.operations = config, helper, database, operations
        self.vendors = VendorLookup(config.recon.oui_paths)
        self._mock_tick = 0

    async def start(self) -> dict:
        adapters = await detect_adapters(self.config)
        interface = "mock-audit0" if self.config.recon.mock_mode else interface_for_role(adapters, "audit")
        operation_id = await self.operations.acquire("recon", "audit_adapter")
        session_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface,operation_id,mock) VALUES(?,?,?,?,?,?,?)",
            (session_id, now, "preparing", interface, interface, operation_id, int(self.config.recon.mock_mode)),
        )
        try:
            if self.config.recon.mock_mode:
                scenario = self.config.recon.mock_scenario
                if scenario == "missing_adapter":
                    raise RuntimeError("Required audit adapter is missing (simulated)")
                if scenario == "failure":
                    raise RuntimeError("Scanner failed to enter monitor mode (simulated)")
                self._ingest(session_id, [] if scenario == "empty" else MOCK_APS, [] if scenario == "empty" else MOCK_CLIENTS)
                if scenario == "normal" and not self.db.one("SELECT id FROM trusted_profiles WHERE ssid='PinePi Lab'"):
                    self.add_trusted("PinePi Lab", ["00:11:22:33:44:55"], "WPA3", [1], "Example Networks")
                result = {"running": True, "pid": None, "interface": interface}
            else:
                result = await self.helper.call("scan-start", interface)
            self.db.execute(
                "UPDATE scan_sessions SET status='running',runtime_pid=? WHERE id=?",
                (result.get("pid"), session_id),
            )
            self.operations.attach_pid(operation_id, result.get("pid"))
            return self.session(session_id) or {}
        except Exception as exc:
            self.db.execute("UPDATE scan_sessions SET status='failed',stopped_at=?,error=? WHERE id=?", (datetime.now(UTC).isoformat(), str(exc)[:1000], session_id))
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def stop(self, session_id: str) -> dict:
        session = self.session(session_id)
        if not session:
            raise FileNotFoundError(session_id)
        if session["status"] in {"completed", "failed", "interrupted"}:
            return session
        self.db.execute("UPDATE scan_sessions SET status='stopping' WHERE id=?", (session_id,))
        try:
            if not session["mock"]:
                await self.helper.call("scan-stop")
                self.ingest_current(session_id)
            self.db.execute("UPDATE scan_sessions SET status='completed',stopped_at=? WHERE id=?", (datetime.now(UTC).isoformat(), session_id))
            if session.get("operation_id"):
                self.operations.finish(session["operation_id"])
            self.apply_retention()
        except Exception as exc:
            self.db.execute("UPDATE scan_sessions SET status='failed',stopped_at=?,error=? WHERE id=?", (datetime.now(UTC).isoformat(), str(exc)[:1000], session_id))
            if session.get("operation_id"):
                self.operations.finish(session["operation_id"], "failed", str(exc))
            raise
        return self.session(session_id) or {}

    async def live_status(self) -> dict:
        session = self.current_session()
        if not session:
            return {"running": False, "session": None, "networks": [], "clients": [], "mock": self.config.recon.mock_mode}
        if session["status"] in {"preparing", "running", "stopping"}:
            if session["mock"] and self.config.recon.mock_scenario == "normal":
                self._mock_tick += 1
                aps = deepcopy(MOCK_APS)
                aps[0]["signal"] += self._mock_tick % 5 - 2
                self._ingest(session["id"], aps, MOCK_CLIENTS)
            elif not session["mock"]:
                helper_status = await self.helper.call("scan-status")
                if helper_status.get("running"):
                    self.ingest_current(session["id"])
                elif session["status"] == "running":
                    self.db.execute("UPDATE scan_sessions SET status='interrupted',stopped_at=?,error='Scanner process exited' WHERE id=?", (datetime.now(UTC).isoformat(), session["id"]))
                    if session.get("operation_id"):
                        self.operations.finish(session["operation_id"], "interrupted", "Scanner process exited")
            session = self.session(session["id"])
        aps = self.access_points(session_id=session["id"], limit=100, offset=0)["items"]
        clients = self.clients(session["id"], 100, 0)["items"]
        return {"running": session["status"] == "running", "session": session, "networks": aps, "clients": clients, "mock": bool(session["mock"])}

    async def reconcile(self) -> None:
        active = self.db.query("SELECT * FROM scan_sessions WHERE status IN ('preparing','running','stopping') ORDER BY started_at DESC")
        if not active:
            return
        helper_status = {"running": False}
        if not self.config.recon.mock_mode:
            try:
                helper_status = await self.helper.call("scan-status")
            except Exception:
                pass
        for index, session in enumerate(active):
            genuine = index == 0 and helper_status.get("running") and helper_status.get("pid") == session.get("runtime_pid")
            if genuine and session.get("operation_id"):
                self.operations.restore(session["operation_id"], "audit_adapter")
            if not genuine:
                self.db.execute("UPDATE scan_sessions SET status='interrupted',stopped_at=?,error='Application restarted while operation state was active' WHERE id=?", (datetime.now(UTC).isoformat(), session["id"]))

    def ingest_current(self, session_id: str) -> None:
        aps, clients = parse_airodump(self.config.storage.scans / "current-01.csv", self.vendors)
        self._ingest(session_id, aps, clients)

    def _ingest(self, session_id: str, aps: list[dict], clients: list[dict]) -> None:
        now = datetime.now(UTC).isoformat()
        self.db.execute("UPDATE access_points SET visible=0 WHERE session_id=?", (session_id,))
        for ap in aps:
            self.db.execute(
                """INSERT INTO access_points(session_id,bssid,ssid,hidden,channel,frequency,band,signal,security,privacy,cipher,authentication,pmf,beacons,data_packets,first_seen,last_seen,vendor,visible)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id,bssid) DO UPDATE SET ssid=excluded.ssid,hidden=excluded.hidden,channel=excluded.channel,frequency=excluded.frequency,band=excluded.band,signal=excluded.signal,security=excluded.security,privacy=excluded.privacy,cipher=excluded.cipher,authentication=excluded.authentication,pmf=excluded.pmf,beacons=excluded.beacons,data_packets=excluded.data_packets,last_seen=excluded.last_seen,vendor=excluded.vendor,visible=1""",
                (session_id, ap["bssid"], ap["ssid"], int(ap["hidden"]), ap["channel"], ap["frequency"], ap["band"], ap["signal"], ap["security"], ap["privacy"], ap["cipher"], ap["authentication"], ap["pmf"], ap["beacons"], ap["data_packets"], ap["first_seen"], ap["last_seen"], ap["vendor"], 1),
            )
            if ap.get("signal") is not None:
                self.db.execute("INSERT INTO signal_samples(session_id,bssid,observed_at,signal) VALUES(?,?,?,?)", (session_id, ap["bssid"], now, ap["signal"]))
                self.db.execute("DELETE FROM signal_samples WHERE id IN (SELECT id FROM signal_samples WHERE session_id=? AND bssid=? ORDER BY id DESC LIMIT -1 OFFSET ?)", (session_id, ap["bssid"], self.config.recon.max_signal_samples_per_ap))
        for client in clients:
            self.db.execute(
                """INSERT INTO clients(session_id,station_mac,bssid,relationship,probed_ssids,signal,packet_count,first_seen,last_seen,vendor) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id,station_mac) DO UPDATE SET bssid=excluded.bssid,relationship=excluded.relationship,probed_ssids=excluded.probed_ssids,signal=excluded.signal,packet_count=excluded.packet_count,last_seen=excluded.last_seen,vendor=excluded.vendor""",
                (session_id, client["station_mac"], client["bssid"], client["relationship"], client["probed_ssids"], client["signal"], client["packet_count"], client["first_seen"], client["last_seen"], client["vendor"]),
            )
        self.db.execute("UPDATE scan_sessions SET ap_count=(SELECT COUNT(*) FROM access_points WHERE session_id=?),client_count=(SELECT COUNT(*) FROM clients WHERE session_id=?) WHERE id=?", (session_id, session_id, session_id))

    def sessions(self, limit: int = 20, offset: int = 0) -> dict:
        return {"items": self.db.query("SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ? OFFSET ?", (limit, offset)), "limit": limit, "offset": offset}

    def session(self, session_id: str) -> dict | None:
        return self.db.one("SELECT * FROM scan_sessions WHERE id=?", (session_id,))

    def current_session(self) -> dict | None:
        return self.db.one("SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT 1")

    def access_points(self, session_id: str | None = None, search: str = "", band: str | None = None, security: str | None = None, pmf: str | None = None, hidden: bool | None = None, visible: bool | None = None, has_clients: bool | None = None, min_signal: int | None = None, max_signal: int | None = None, sort: str = "signal_desc", limit: int = 50, offset: int = 0) -> dict:
        order = SORT_FIELDS.get(sort)
        if not order:
            raise ValueError("Invalid sort field")
        clauses, params = [], []
        if session_id:
            clauses.append("ap.session_id=?"); params.append(session_id)
        if search:
            clauses.append("(ap.ssid LIKE ? ESCAPE '\\' OR ap.bssid LIKE ? OR ap.vendor LIKE ? ESCAPE '\\')")
            escaped = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params.extend((escaped, f"%{search.upper()}%", escaped))
        for value, column in ((band, "ap.band"), (pmf, "ap.pmf")):
            if value:
                clauses.append(f"{column}=?"); params.append(value)
        if security:
            if security == "WPA":
                clauses.append("ap.security IN ('WPA','WPA/WPA2 mixed')")
            elif security in {"WPA2", "WPA3"}:
                clauses.append("ap.security LIKE ?"); params.append(f"%{security}%")
            else:
                clauses.append("ap.security=?"); params.append(security)
        if hidden is not None: clauses.append("ap.hidden=?"); params.append(int(hidden))
        if visible is not None: clauses.append("ap.visible=?"); params.append(int(visible))
        if has_clients is not None: clauses.append("COALESCE(c.client_count,0)>0" if has_clients else "COALESCE(c.client_count,0)=0")
        if min_signal is not None: clauses.append("ap.signal>=?"); params.append(min_signal)
        if max_signal is not None: clauses.append("ap.signal<=?"); params.append(max_signal)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        base = f"FROM access_points ap LEFT JOIN (SELECT session_id,bssid,COUNT(*) client_count FROM clients GROUP BY session_id,bssid) c ON c.session_id=ap.session_id AND c.bssid=ap.bssid {where}"
        items = self.db.query(f"SELECT ap.*,COALESCE(c.client_count,0) client_count {base} ORDER BY {order} LIMIT ? OFFSET ?", tuple(params + [limit, offset]))
        total = self.db.one(f"SELECT COUNT(*) total FROM (SELECT ap.session_id,ap.bssid,COALESCE(c.client_count,0) client_count {base})", tuple(params))["total"]
        for item in items:
            item["signal_quality"] = signal_quality(item["signal"])
            item["indicators"] = self.indicators(item)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def access_point(self, bssid: str, session_id: str) -> dict:
        normalized = normalize_mac(bssid)
        if not normalized:
            raise ValueError("Invalid BSSID")
        ap = self.db.one("SELECT * FROM access_points WHERE session_id=? AND bssid=?", (session_id, normalized))
        if not ap: raise FileNotFoundError(bssid)
        ap["clients"] = self.db.query("SELECT * FROM clients WHERE session_id=? AND bssid=? ORDER BY signal DESC", (session_id, normalized))
        ap["related_bssids"] = self.db.query("SELECT bssid,channel,security,signal FROM access_points WHERE session_id=? AND ssid=? AND bssid<>?", (session_id, ap["ssid"], normalized)) if ap["ssid"] else []
        ap["signal_history"] = self.db.query("SELECT observed_at,signal FROM signal_samples WHERE session_id=? AND bssid=? ORDER BY id", (session_id, normalized))
        ap["indicators"] = self.indicators(ap)
        ap["signal_quality"] = signal_quality(ap["signal"])
        ap["security_detail"] = classify_security(ap["privacy"], ap["authentication"], ap["cipher"])
        return ap

    def clients(self, session_id: str, limit: int = 50, offset: int = 0) -> dict:
        return {"items": self.db.query("SELECT c.*,ap.ssid associated_ssid FROM clients c LEFT JOIN access_points ap ON ap.session_id=c.session_id AND ap.bssid=c.bssid WHERE c.session_id=? ORDER BY c.signal DESC LIMIT ? OFFSET ?", (session_id, limit, offset)), "limit": limit, "offset": offset}

    def client(self, station_mac: str, session_id: str) -> dict:
        normalized = normalize_mac(station_mac)
        if not normalized:
            raise ValueError("Invalid station MAC")
        client = self.db.one("SELECT c.*,ap.ssid associated_ssid,ap.security associated_security FROM clients c LEFT JOIN access_points ap ON ap.session_id=c.session_id AND ap.bssid=c.bssid WHERE c.session_id=? AND c.station_mac=?", (session_id, normalized))
        if not client:
            raise FileNotFoundError(station_mac)
        client["observation_history"] = [{"first_seen": client["first_seen"], "last_seen": client["last_seen"], "signal": client["signal"]}]
        return client

    def channels(self, session_id: str) -> list[dict]:
        rows = self.db.query("SELECT channel,band,COUNT(*) observed_networks,MAX(signal) strongest_signal FROM access_points WHERE session_id=? AND channel IS NOT NULL GROUP BY channel,band ORDER BY band,channel", (session_id,))
        counts = {row["channel"]: row["observed_networks"] for row in rows if row["band"] == "2.4 GHz"}
        for row in rows:
            row["overlapping_networks"] = sum(counts.get(ch, 0) for ch in range(max(1, row["channel"] - 4), min(13, row["channel"] + 4) + 1)) - row["observed_networks"] if row["band"] == "2.4 GHz" else 0
        candidates = [1, 6, 11]
        recommended = min(candidates, key=lambda ch: sum(counts.get(other, 0) for other in range(max(1, ch - 4), min(13, ch + 4) + 1)))
        for row in rows:
            row["recommended_for_owned_ap"] = row["channel"] == recommended
        return rows

    def trusted(self) -> list[dict]:
        profiles = self.db.query("SELECT * FROM trusted_profiles ORDER BY ssid")
        for profile in profiles: profile["approved_bssids"] = [row["bssid"] for row in self.db.query("SELECT bssid FROM trusted_bssids WHERE profile_id=?", (profile["id"],))]
        return profiles

    def add_trusted(self, ssid: str, bssids: list[str], security: str = "", channels: list[int] | None = None, vendor: str = "") -> dict:
        ssid = ssid.strip()[:128]
        if not ssid: raise ValueError("Trusted SSID is required")
        normalized = [normalize_mac(item) for item in bssids]
        if any(item is None for item in normalized): raise ValueError("Invalid approved BSSID")
        self.db.execute("INSERT INTO trusted_profiles(ssid,expected_security,expected_channels,expected_vendor,created_at) VALUES(?,?,?,?,?)", (ssid, security[:80], ",".join(str(item) for item in (channels or [])), vendor[:160], datetime.now(UTC).isoformat()))
        profile = self.db.one("SELECT * FROM trusted_profiles WHERE ssid=?", (ssid,))
        for bssid in normalized: self.db.execute("INSERT INTO trusted_bssids(profile_id,bssid) VALUES(?,?)", (profile["id"], bssid))
        return self.trusted_profile(profile["id"])

    def trusted_profile(self, profile_id: int) -> dict:
        profile = self.db.one("SELECT * FROM trusted_profiles WHERE id=?", (profile_id,))
        if not profile: raise FileNotFoundError(str(profile_id))
        profile["approved_bssids"] = [row["bssid"] for row in self.db.query("SELECT bssid FROM trusted_bssids WHERE profile_id=?", (profile_id,))]
        return profile

    def delete_trusted(self, profile_id: int) -> None:
        if not self.db.one("SELECT id FROM trusted_profiles WHERE id=?", (profile_id,)): raise FileNotFoundError(str(profile_id))
        self.db.execute("DELETE FROM trusted_profiles WHERE id=?", (profile_id,))

    def indicators(self, ap: dict) -> list[dict]:
        profile = self.db.one("SELECT * FROM trusted_profiles WHERE ssid=?", (ap.get("ssid", ""),))
        if not profile: return []
        approved = {row["bssid"] for row in self.db.query("SELECT bssid FROM trusted_bssids WHERE profile_id=?", (profile["id"],))}
        indicators = []
        if approved and ap["bssid"] not in approved: indicators.append({"type":"unexpected_bssid","severity":"warning","message":"Same trusted SSID observed from an unapproved BSSID; investigate before drawing conclusions."})
        if profile["expected_security"] and ap["security"] != profile["expected_security"]: indicators.append({"type":"security_change","severity":"warning","message":"Security differs from the trusted profile and requires investigation."})
        expected_channels = {int(value) for value in profile["expected_channels"].split(",") if value.isdigit()}
        if expected_channels and ap.get("channel") not in expected_channels: indicators.append({"type":"channel_change","severity":"info","message":"Channel differs from the trusted profile; investigate whether this change is expected."})
        if profile["expected_vendor"] and ap["vendor"] != profile["expected_vendor"]: indicators.append({"type":"vendor_change","severity":"info","message":"Vendor differs from the trusted profile; this is an indicator, not proof of an evil twin."})
        return indicators

    def delete_session(self, session_id: str) -> None:
        session = self.session(session_id)
        if not session: raise FileNotFoundError(session_id)
        if session["status"] in {"preparing", "running", "stopping"}:
            raise RuntimeError("Stop the active Recon session before deleting it")
        self.db.execute("DELETE FROM scan_sessions WHERE id=?", (session_id,))

    def clear_history(self) -> None:
        if self.db.one("SELECT id FROM scan_sessions WHERE status IN ('preparing','running','stopping') LIMIT 1"):
            raise RuntimeError("Stop the active Recon session before clearing history")
        self.db.execute("DELETE FROM scan_sessions")

    def apply_retention(self) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=self.config.recon.max_age_days)).isoformat()
        self.db.execute("DELETE FROM scan_sessions WHERE started_at<?", (cutoff,))
        self.db.execute("DELETE FROM scan_sessions WHERE id IN (SELECT id FROM scan_sessions ORDER BY started_at DESC LIMIT -1 OFFSET ?)", (self.config.recon.max_sessions,))
