from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import audit, capture, diagnostics, management_ap, operations, recon, reports, scan, security_analysis, system, training_ap, wireless_tools
from app.config import load_config
from app.services.capture import CaptureService
from app.services.capture_analysis import CaptureAnalysisService
from app.services.capabilities import CapabilityRegistry
from app.services.active_wireless import ActiveWirelessService
from app.services.database import Database
from app.services.command import CommandError
from app.services.helper import HelperClient
from app.services.management_ap import ManagementAPService
from app.services.kismet import KismetService
from app.services.offline_engines import OfflineEngineService
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.recon import ReconService
from app.services.reporting import ReportingService
from app.services.rogue_detection import RogueDetectionService
from app.services.state import AppState
from app.services.training_ap import TrainingAPService
from app.services.wifi import SystemService
from app.version import VERSION

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
logger = logging.getLogger("pinepi")
ERROR_CODES = {
    "ADAPTER_MISSING", "ADAPTER_BUSY", "MONITOR_MODE_FAILED", "CHANNEL_UNSUPPORTED",
    "REGULATORY_RESTRICTION", "INJECTION_UNSUPPORTED", "PROCESS_START_FAILED", "PROCESS_EXITED",
    "CAPTURE_FULL", "NO_TARGET", "INVALID_BSSID", "TOOL_MISSING", "TOOL_VERSION_UNSUPPORTED",
    "PERMISSION_FAILED", "OUTPUT_PARSE_FAILED", "ACTIVE_LIMIT", "TARGET_MISMATCH", "ANALYSIS_LIMIT",
}


def error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"detail": message, "error": {"code": code, "message": message}}, status_code=status_code)


def normalized_error(message: str, default: str) -> tuple[str, str]:
    prefix, separator, remainder = message.partition(":")
    if separator and prefix in ERROR_CODES:
        return prefix, remainder.strip()
    lowered = message.lower()
    if "owned by another operation" in lowered or "adapter is busy" in lowered:
        return "ADAPTER_BUSY", message
    if "required executable not found" in lowered:
        return "TOOL_MISSING", message
    if "permission" in lowered or "sudo" in lowered:
        return "PERMISSION_FAILED", message
    if "monitor" in lowered:
        return "MONITOR_MODE_FAILED", message
    return default, message


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    database = Database(config.storage.database)
    database.initialize()
    helper = HelperClient(config)
    processes = ProcessManager(database)
    processes.recover()
    app.state.config = config
    app.state.capabilities = CapabilityRegistry()
    app.state.helper = helper
    app.state.app_state = AppState()
    app.state.system_service = SystemService(config)
    app.state.database = database
    app.state.processes = processes
    app.state.recon = ReconService(config, helper, database, processes)
    app.state.capture = CaptureService(config, helper, processes, database)
    app.state.capture_analysis = CaptureAnalysisService(config, app.state.capture, database, processes)
    app.state.offline_engines = OfflineEngineService(config, app.state.capture_analysis, processes)
    app.state.active_wireless = ActiveWirelessService(config, helper, processes)
    app.state.training_ap = TrainingAPService(config, helper, processes)
    app.state.management_ap = ManagementAPService(config, helper)
    app.state.kismet = KismetService(app.state.capabilities)
    app.state.rogue_detection = RogueDetectionService(database)
    app.state.reporting = ReportingService(database, app.state.recon, app.state.rogue_detection, app.state.capture)
    await app.state.recon.reconcile()
    await app.state.capture.reconcile()
    await app.state.training_ap.reconcile()
    await app.state.active_wireless.reconcile()
    yield
    # Transient operations are stopped to keep files valid on a clean web-service shutdown.
    async def stop_recon():
        current = app.state.recon.current_session()
        if current and current["status"] in {"preparing", "running", "stopping"}:
            await app.state.recon.stop(current["id"])

    for operation in (
        stop_recon,
        app.state.capture.stop,
        app.state.active_wireless.stop,
        app.state.active_wireless.monitor_disable,
    ):
        with suppress(Exception):
            await asyncio.wait_for(operation(), timeout=8)


class SecurityHeadersMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message["headers"].extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'"),
                ])
            await send(message)

        await self.asgi_app(scope, receive, send_with_headers)


app = FastAPI(title="PinePi", version=VERSION, lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
for api_router in (system.router, diagnostics.router, scan.router, recon.router, operations.router, audit.router, capture.router, training_ap.router, management_ap.router, wireless_tools.router, security_analysis.router, reports.router):
    app.include_router(api_router)


@app.exception_handler(CommandError)
async def command_error(_: Request, exc: CommandError) -> JSONResponse:
    code, message = normalized_error(str(exc), "PROCESS_START_FAILED")
    return error_response(code, message, 503)


@app.exception_handler(OperationBusy)
async def busy_error(_: Request, exc: OperationBusy) -> JSONResponse:
    return error_response("ADAPTER_BUSY", str(exc), 409)


@app.exception_handler(ValueError)
async def value_error(_: Request, exc: ValueError) -> JSONResponse:
    code, message = normalized_error(str(exc), "INVALID_REQUEST")
    return error_response(code, message, 400)


@app.exception_handler(FileNotFoundError)
async def not_found(_: Request, exc: FileNotFoundError) -> JSONResponse:
    return error_response("not_found", f"Not found: {exc}", 404)


@app.exception_handler(RuntimeError)
async def runtime_error(_: Request, exc: RuntimeError) -> JSONResponse:
    logger.warning("Runtime operation failed: %s", exc)
    code, message = normalized_error(str(exc), "PROCESS_EXITED")
    return error_response(code, message, 409)


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
