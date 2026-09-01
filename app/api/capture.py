from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from app.api.access_control import require_privileged_action

router = APIRouter(prefix="/api/captures", tags=["capture"])


@router.post("/start")
async def start_capture(request: Request) -> dict:
    require_privileged_action(request)
    target = await request.app.state.app_state.target()
    if not target:
        raise HTTPException(409, "Select a WLAN first")
    return await request.app.state.capture.start(int(target["channel"]), target)


@router.post("/stop")
async def stop_capture(request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.capture.stop()


@router.get("/status")
async def capture_status(request: Request) -> dict:
    return await request.app.state.capture.status()


@router.get("")
async def list_captures(request: Request) -> dict:
    return {"captures": request.app.state.capture.list_captures()}


@router.get("/{filename}/download")
async def download_capture(filename: str, request: Request) -> FileResponse:
    return FileResponse(request.app.state.capture.resolve(filename), filename=filename, media_type="application/vnd.tcpdump.pcap")


@router.get("/{filename}/analysis")
async def analyze_capture(filename: str, request: Request) -> dict:
    return await request.app.state.capture_analysis.overview(filename)


@router.post("/{filename}/validate-hcx")
async def validate_hcx(filename: str, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.capture_analysis.hcx_validate(filename)


@router.post("/{filename}/analyze-aircrack")
async def analyze_aircrack(filename: str, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.capture_analysis.aircrack_summary(filename)


@router.post("/{filename}/analyze-suricata")
async def analyze_suricata(filename: str, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.offline_engines.suricata(filename)


@router.post("/{filename}/analyze-zeek")
async def analyze_zeek(filename: str, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.offline_engines.zeek(filename)


@router.get("/{filename}/frames")
async def frame_explorer(filename: str, request: Request, limit: int = 100, offset: int = 0) -> dict:
    return request.app.state.capture_analysis.frame_explorer(filename, limit, offset)


@router.delete("/{filename}")
async def delete_capture(filename: str, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.capture.delete(filename)
