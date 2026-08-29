from __future__ import annotations

import json
import re
import shutil
import tempfile
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.config import AppConfig
from app.services.capture import CaptureService
from app.services.command import CommandError, run_command
from app.services.database import Database
from app.services.process_manager import ProcessManager


SUBTYPES = {
    0x00: "association",
    0x01: "association",
    0x02: "reassociation",
    0x03: "reassociation",
    0x04: "probe_request",
    0x05: "probe_response",
    0x08: "beacon",
    0x0A: "disassociation",
    0x0B: "authentication",
    0x0C: "deauthentication",
}
NETWORK_PROTOCOLS = ("eapol", "arp", "dhcp", "dns", "tcp", "udp", "tls")


def _integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def parse_tshark_rows(text: str, max_rows: int) -> dict:
    totals = Counter(packets=0, management=0, control=0, data=0)
    subtypes: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    bssids: Counter[str] = Counter()
    stations: Counter[str] = Counter()
    for raw in text.splitlines()[:max_rows]:
        columns = (raw.split("\t") + [""] * 6)[:6]
        protocol_text, subtype_text, bssid, source, destination, _ssid = columns
        totals["packets"] += 1
        subtype = _integer(subtype_text.split(",", 1)[0])
        if subtype is not None:
            frame_type = subtype & 0x30
            totals["management" if frame_type == 0 else "control" if frame_type == 0x10 else "data"] += 1
            if subtype in SUBTYPES:
                subtypes[SUBTYPES[subtype]] += 1
        names = {item.lower() for item in re.split(r"[:,]", protocol_text) if item}
        for name in NETWORK_PROTOCOLS:
            if name in names or (name == "dhcp" and {"bootp", "dhcpv6"} & names):
                protocols[name] += 1
        if re.fullmatch(r"(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}", bssid):
            bssids[bssid.upper()] += 1
        for address in (source, destination):
            if re.fullmatch(r"(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}", address) and address.lower() != "ff:ff:ff:ff:ff:ff":
                stations[address.upper()] += 1
    return {
        "packets": totals["packets"],
        "frame_types": {key: totals[key] for key in ("management", "control", "data")},
        "management_subtypes": {name: subtypes[name] for name in SUBTYPES.values()},
        "protocols": {name: protocols[name] for name in NETWORK_PROTOCOLS},
        "bssids": [item for item, _count in bssids.most_common(50)],
        "stations": [item for item, _count in stations.most_common(100)],
        "truncated": len(text.splitlines()) > max_rows,
    }


def parse_hcx_summary(output: str, hash_lines: list[str] | None = None) -> dict:
    lines = hash_lines or []
    pmkid = sum(1 for line in lines if line.startswith("WPA*01*"))
    eapol_pairs = sum(1 for line in lines if line.startswith("WPA*02*"))
    if not lines:
        for pattern, key in (
            (r"(?i)PMKID[^:\n]*:\s*(\d+)", "pmkid"),
            (r"(?i)EAPOL[^:\n]*(?:pair|written)[^:\n]*:\s*(\d+)", "eapol"),
        ):
            matches = [int(value) for value in re.findall(pattern, output)]
            if key == "pmkid" and matches:
                pmkid = max(matches)
            elif key == "eapol" and matches:
                eapol_pairs = max(matches)
    if eapol_pairs:
        validation = "Validated EAPOL message pair"
    elif pmkid:
        validation = "PMKID present"
    else:
        validation = "No HCX-validated WPA material"
    return {
        "available": True,
        "pmkid_count": pmkid,
        "eapol_pair_count": eapol_pairs,
        "validation": validation,
        "aircrack_compatible": bool(eapol_pairs),
        "note": "HCX message-pair validation is stronger than raw EAPOL frame counting; it does not reveal a password.",
    }


def parse_aircrack_summary(output: str) -> dict:
    bssids = sorted(set(re.findall(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", output)))[:100]
    handshake_matches = re.findall(r"(?i)(\d+)\s+(?:WPA\s+)?handshake", output)
    pmkid_matches = re.findall(r"(?i)(\d+)\s+PMKID", output)
    return {
        "bssids": [value.upper() for value in bssids],
        "handshake_indicators": sum(int(value) for value in handshake_matches),
        "pmkid_indicators": sum(int(value) for value in pmkid_matches),
        "compatible": bool(handshake_matches or pmkid_matches or bssids),
        "note": "Aircrack compatibility is an offline format/record indicator and does not reveal or verify a password.",
    }


class CaptureAnalysisService:
    def __init__(
        self,
        config: AppConfig,
        captures: CaptureService,
        database: Database,
        operations: ProcessManager,
    ):
        self.config = config
        self.captures = captures
        self.database = database
        self.operations = operations

    def checked_capture(self, filename: str) -> Path:
        path = self.captures.resolve(filename)
        if path.stat().st_size > self.config.analysis.max_input_mb * 1024 * 1024:
            raise ValueError("ANALYSIS_LIMIT: capture exceeds the configured offline-analysis size limit")
        return path

    async def overview(self, filename: str) -> dict:
        path = self.checked_capture(filename)
        operation_id = await self.operations.acquire(
            "CAPTURE_ANALYSIS", "analysis_cpu", 120, target={"filename": filename}
        )
        try:
            if not shutil.which("tshark"):
                result = {
                    "filename": filename,
                    "size": path.stat().st_size,
                    "engine": "tshark",
                    "available": False,
                    "status": "TOOL_MISSING",
                    "explanation": "Install tshark to calculate protocol and 802.11 frame statistics.",
                }
            else:
                command = (
                    "tshark", "-n", "-r", str(path), "-c", str(self.config.analysis.max_packets),
                    "-T", "fields", "-E", "separator=\t", "-e", "frame.protocols",
                    "-e", "wlan.fc.type_subtype", "-e", "wlan.bssid", "-e", "wlan.sa",
                    "-e", "wlan.da", "-e", "wlan.ssid",
                )
                raw = await run_command(*command, timeout=120, check=False)
                parsed = parse_tshark_rows(raw.stdout, self.config.analysis.max_packets)
                result = {
                    "filename": filename,
                    "size": path.stat().st_size,
                    "engine": "tshark",
                    "available": True,
                    "status": "OK" if raw.returncode == 0 else "OUTPUT_PARSE_FAILED",
                    **parsed,
                }
            self._store(filename, "tshark", result)
            self.operations.finish(operation_id)
            return result
        except Exception as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def hcx_validate(self, filename: str) -> dict:
        path = self.checked_capture(filename)
        operation_id = await self.operations.acquire(
            "HCX_VALIDATION", "analysis_cpu", 120, target={"filename": filename}
        )
        try:
            executable = shutil.which("hcxpcapngtool")
            if not executable:
                result = {
                    "available": False,
                    "status": "TOOL_MISSING",
                    "validation": "HCX validation unavailable",
                    "pmkid_count": 0,
                    "eapol_pair_count": 0,
                    "aircrack_compatible": False,
                }
            else:
                with tempfile.TemporaryDirectory(prefix="pinepi-hcx-") as directory:
                    output_path = Path(directory) / "validation.hc22000"
                    raw = await run_command(executable, "-o", str(output_path), str(path), timeout=120, check=False)
                    hash_lines = output_path.read_text(errors="replace").splitlines()[: self.config.analysis.max_result_rows] if output_path.is_file() else []
                    result = parse_hcx_summary((raw.stdout or "") + "\n" + (raw.stderr or ""), hash_lines)
                    result["status"] = "OK" if raw.returncode == 0 else "OUTPUT_PARSE_FAILED"
            result["filename"] = filename
            result["engine"] = "hcxpcapngtool"
            self._store(filename, "hcxpcapngtool", result)
            self.operations.finish(operation_id)
            return result
        except (CommandError, OSError) as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise RuntimeError(f"HCX validation failed: {exc}") from exc

    async def aircrack_summary(self, filename: str) -> dict:
        path = self.checked_capture(filename)
        operation_id = await self.operations.acquire(
            "AIRCRACK_AUDIT", "analysis_cpu", 30, target={"filename": filename}
        )
        try:
            executable = shutil.which("aircrack-ng")
            if not executable:
                result = {
                    "available": False,
                    "status": "TOOL_MISSING",
                    "compatible": False,
                    "filename": filename,
                    "engine": "aircrack-ng",
                }
            else:
                raw = await run_command(executable, str(path), timeout=30, check=False, input_text="")
                result = {
                    "available": True,
                    "status": "OK" if raw.returncode in (0, 1) else "OUTPUT_PARSE_FAILED",
                    "filename": filename,
                    "engine": "aircrack-ng",
                    **parse_aircrack_summary((raw.stdout or "") + "\n" + (raw.stderr or "")),
                }
            self._store(filename, "aircrack-ng", result)
            self.operations.finish(operation_id)
            return result
        except CommandError as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise RuntimeError(f"Aircrack offline analysis failed: {exc}") from exc

    def frame_explorer(self, filename: str, limit: int = 100, offset: int = 0) -> dict:
        path = self.checked_capture(filename)
        limit = min(max(1, limit), 200)
        offset = max(0, offset)
        try:
            from scapy.all import Dot11, Dot11Elt, PcapReader  # type: ignore[import-not-found]
        except ImportError:
            return {"available": False, "status": "TOOL_MISSING", "items": [], "limit": limit, "offset": offset}
        items = []
        parsed = 0
        with PcapReader(str(path)) as packets:
            for index, packet in enumerate(packets):
                if index >= self.config.analysis.max_packets or len(items) >= limit:
                    break
                if index < offset or not packet.haslayer(Dot11):
                    continue
                dot11 = packet[Dot11]
                item = {
                    "number": index + 1,
                    "type": int(dot11.type),
                    "subtype": int(dot11.subtype),
                    "destination": str(dot11.addr1 or ""),
                    "source": str(dot11.addr2 or ""),
                    "bssid": str(dot11.addr3 or ""),
                    "sequence": int(getattr(dot11, "SC", 0)) >> 4,
                    "information_elements": [],
                }
                layer = packet.getlayer(Dot11Elt)
                element_count = 0
                while layer is not None and element_count < 32:
                    raw_info = bytes(getattr(layer, "info", b""))[:256]
                    text = raw_info.decode("utf-8", errors="replace") if int(getattr(layer, "ID", -1)) == 0 else raw_info.hex()
                    item["information_elements"].append({"id": int(getattr(layer, "ID", -1)), "value": text})
                    layer = layer.payload.getlayer(Dot11Elt)
                    element_count += 1
                items.append(item)
                parsed += 1
        return {
            "available": True,
            "status": "OK",
            "items": items,
            "limit": limit,
            "offset": offset,
            "parsed": parsed,
            "payloads_included": False,
            "note": "Frame Explorer shows bounded 802.11 headers and information elements only.",
        }

    def _store(self, filename: str, engine: str, result: dict) -> None:
        bounded = json.dumps(result, separators=(",", ":"))[:100000]
        self.database.execute(
            "INSERT INTO analysis_results(id,filename,engine,created_at,status,result_json) VALUES(?,?,?,?,?,?)",
            (str(uuid.uuid4()), filename, engine, datetime.now(UTC).isoformat(), str(result.get("status", "OK")), bounded),
        )
