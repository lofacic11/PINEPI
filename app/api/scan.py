from fastapi import APIRouter, Request

from app.models import TargetRequest

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/start")
async def start_scan(request: Request) -> dict:
    return await request.app.state.scanner.start()


@router.post("/stop")
async def stop_scan(request: Request) -> dict:
    return await request.app.state.scanner.stop()


@router.get("/status")
async def scan_status(request: Request) -> dict:
    result = await request.app.state.scanner.status()
    result["selected_target"] = await request.app.state.app_state.target()
    return result


@router.post("/target")
async def select_target(body: TargetRequest, request: Request) -> dict:
    return {"selected_target": await request.app.state.app_state.set_target(body.target.model_dump())}

