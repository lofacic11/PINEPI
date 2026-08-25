from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import audit, capture, management_ap, scan, system, training_ap
from app.config import load_config
from app.services.capture import CaptureService
from app.services.command import CommandError
from app.services.helper import HelperClient
from app.services.management_ap import ManagementAPService
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.scanner import ScannerService
from app.services.state import AppState
from app.services.training_ap import TrainingAPService
from app.services.wifi import SystemService

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
logger = logging.getLogger("pinepi")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    helper = HelperClient(config)
    processes = ProcessManager()
    app.state.config = config
    app.state.app_state = AppState()
    app.state.system_service = SystemService(config)
    app.state.scanner = ScannerService(config, helper, processes)
    app.state.capture = CaptureService(config, helper, processes)
    app.state.training_ap = TrainingAPService(config, helper, processes)
    app.state.management_ap = ManagementAPService(config, helper)
    yield
    # Transient operations are stopped to keep files valid on a clean web-service shutdown.
    for operation in (app.state.scanner.stop, app.state.capture.stop):
        with suppress(Exception):
            await asyncio.wait_for(operation(), timeout=8)


app = FastAPI(title="PinePi", version="0.7.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
for api_router in (system.router, scan.router, audit.router, capture.router, training_ap.router, management_ap.router):
    app.include_router(api_router)


@app.exception_handler(CommandError)
async def command_error(_: Request, exc: CommandError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=503)


@app.exception_handler(OperationBusy)
async def busy_error(_: Request, exc: OperationBusy) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.exception_handler(ValueError)
async def value_error(_: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(FileNotFoundError)
async def not_found(_: Request, exc: FileNotFoundError) -> JSONResponse:
    return JSONResponse({"detail": f"Not found: {exc}"}, status_code=404)


@app.exception_handler(RuntimeError)
async def runtime_error(_: Request, exc: RuntimeError) -> JSONResponse:
    logger.warning("Runtime operation failed: %s", exc)
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
