from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from app.config import AppConfig
from app.services.capture_analysis import CaptureAnalysisService
from app.services.command import CommandError, run_command
from app.services.process_manager import ProcessManager


def bounded_json_lines(path: Path, limit: int) -> tuple[list[dict], bool]:
    if not path.is_file() or path.is_symlink():
        return [], False
    items, truncated = [], False
    with path.open(errors="replace") as handle:
        for line in handle:
            if len(items) >= limit:
                truncated = True
                break
            try:
                value = json.loads(line[:100000])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                items.append(value)
    return items, truncated


def normalize_suricata(events: list[dict], limit: int) -> list[dict]:
    results = []
    for event in events:
        if event.get("event_type") != "alert":
            continue
        alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
        results.append({
            "timestamp": str(event.get("timestamp", ""))[:80],
            "severity": int(alert.get("severity", 0) or 0),
            "signature": str(alert.get("signature", "Unknown alert"))[:500],
            "category": str(alert.get("category", ""))[:160],
            "protocol": str(event.get("proto", ""))[:20],
            "source": str(event.get("src_ip", ""))[:64],
            "source_port": event.get("src_port"),
            "destination": str(event.get("dest_ip", ""))[:64],
            "destination_port": event.get("dest_port"),
        })
        if len(results) >= limit:
            break
    return results


def normalize_zeek(records: dict[str, list[dict]], limit: int) -> dict:
    allowed = {
        "conn": ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration"),
        "dns": ("ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "answers"),
        "http": ("ts", "uid", "id.orig_h", "id.resp_h", "method", "host", "uri", "status_code"),
        "ssl": ("ts", "uid", "id.orig_h", "id.resp_h", "server_name", "version", "cipher", "established"),
        "dhcp": ("ts", "uids", "client_addr", "server_addr", "host_name", "domain"),
        "notice": ("ts", "uid", "note", "msg", "src", "dst"),
        "files": ("ts", "fuid", "source", "mime_type", "filename", "seen_bytes"),
    }
    result = {}
    for name, fields in allowed.items():
        result[name] = [
            {field: row.get(field) for field in fields if field in row}
            for row in records.get(name, [])[:limit]
        ]
    return result


class OfflineEngineService:
    def __init__(self, config: AppConfig, analysis: CaptureAnalysisService, operations: ProcessManager):
        self.config = config
        self.analysis = analysis
        self.operations = operations

    async def suricata(self, filename: str) -> dict:
        path = self.analysis.checked_capture(filename)
        operation_id = await self.operations.acquire("SURICATA_ANALYSIS", "analysis_cpu", 300, target={"filename": filename})
        try:
            executable = shutil.which("suricata")
            if not executable:
                result = {"available": False, "status": "TOOL_MISSING", "alerts": [], "filename": filename}
            else:
                with tempfile.TemporaryDirectory(prefix="pinepi-suricata-") as directory:
                    raw = await run_command(
                        executable, "-r", str(path), "-l", directory, "--runmode", "single",
                        timeout=300, check=False,
                    )
                    events, truncated = bounded_json_lines(Path(directory) / "eve.json", self.config.analysis.max_result_rows * 5)
                    alerts = normalize_suricata(events, self.config.analysis.max_result_rows)
                    result = {
                        "available": True,
                        "status": "OK" if raw.returncode == 0 else "PROCESS_EXITED",
                        "filename": filename,
                        "alerts": alerts,
                        "total": len(alerts),
                        "truncated": truncated or len(alerts) >= self.config.analysis.max_result_rows,
                    }
            self.operations.finish(operation_id)
            return result
        except (CommandError, OSError) as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise RuntimeError(f"Suricata offline analysis failed: {exc}") from exc

    async def zeek(self, filename: str) -> dict:
        path = self.analysis.checked_capture(filename)
        operation_id = await self.operations.acquire("ZEEK_ANALYSIS", "analysis_cpu", 300, target={"filename": filename})
        try:
            executable = shutil.which("zeek")
            if not executable:
                result = {"available": False, "status": "TOOL_MISSING", "views": {}, "filename": filename}
            else:
                with tempfile.TemporaryDirectory(prefix="pinepi-zeek-") as directory:
                    raw = await run_command(
                        executable, "-Cr", str(path), "LogAscii::use_json=T",
                        timeout=300, check=False, cwd=directory,
                    )
                    records, truncated = {}, False
                    for name in ("conn", "dns", "http", "ssl", "dhcp", "notice", "files"):
                        rows, was_truncated = bounded_json_lines(Path(directory) / f"{name}.log", self.config.analysis.max_result_rows)
                        records[name] = rows
                        truncated = truncated or was_truncated
                    result = {
                        "available": True,
                        "status": "OK" if raw.returncode == 0 else "PROCESS_EXITED",
                        "filename": filename,
                        "views": normalize_zeek(records, self.config.analysis.max_result_rows),
                        "truncated": truncated,
                    }
            self.operations.finish(operation_id)
            return result
        except (CommandError, OSError) as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise RuntimeError(f"Zeek offline analysis failed: {exc}") from exc
