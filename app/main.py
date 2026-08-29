from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import audit, capture, diagnostics, management_ap, operations, recon, scan, system, training_ap
from app.config import load_config
from app.services.capture import CaptureService
from app.services.database import Database
from app.services.command import CommandError
from app.services.helper import HelperClient
from app.services.management_ap import ManagementAPService
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.recon import ReconService
from app.services.state import AppState
from app.services.training_ap import TrainingAPService
from app.services.wifi import SystemService
from app.version import VERSION

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
logger = logging.getLogger("pinepi")


def error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"detail": message, "error": {"code": code, "message": message}}, status_code=status_code)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    database = Database(config.storage.database)
    database.initialize()
    helper = HelperClient(config)
    processes = ProcessManager(database)
    processes.recover()
    app.state.config = config
    app.state.helper = helper
    app.state.app_state = AppState()
    app.state.system_service = SystemService(config)
    app.state.database = database
    app.state.processes = processes
    app.state.recon = ReconService(config, helper, database, processes)
    app.state.capture = CaptureService(config, helper, processes)
    app.state.training_ap = TrainingAPService(config, helper, processes)
    app.state.management_ap = ManagementAPService(config, helper)
    await app.state.recon.reconcile()
    await app.state.capture.reconcile()
    await app.state.training_ap.reconcile()
    yield
    # Transient operations are stopped to keep files valid on a clean web-service shutdown.
    async def stop_recon():
        current = app.state.recon.current_session()
        if current and current["status"] in {"preparing", "running", "stopping"}:
            await app.state.recon.stop(current["id"])

    for operation in (stop_recon, app.state.capture.stop):
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
for api_router in (system.router, diagnostics.router, scan.router, recon.router, operations.router, audit.router, capture.router, training_ap.router, management_ap.router):
    app.include_router(api_router)


@app.exception_handler(CommandError)
async def command_error(_: Request, exc: CommandError) -> JSONResponse:
    return error_response("helper_unavailable", str(exc), 503)


@app.exception_handler(OperationBusy)
async def busy_error(_: Request, exc: OperationBusy) -> JSONResponse:
    return error_response("resource_busy", str(exc), 409)


@app.exception_handler(ValueError)
async def value_error(_: Request, exc: ValueError) -> JSONResponse:
    return error_response("invalid_request", str(exc), 400)


@app.exception_handler(FileNotFoundError)
async def not_found(_: Request, exc: FileNotFoundError) -> JSONResponse:
    return error_response("not_found", f"Not found: {exc}", 404)


@app.exception_handler(RuntimeError)
async def runtime_error(_: Request, exc: RuntimeError) -> JSONResponse:
    logger.warning("Runtime operation failed: %s", exc)
    return error_response("operation_failed", str(exc), 409)


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
