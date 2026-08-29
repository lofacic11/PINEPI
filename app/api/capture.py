from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/captures", tags=["capture"])


@router.post("/start")
async def start_capture(request: Request) -> dict:
    target = await request.app.state.app_state.target()
    if not target:
        raise HTTPException(409, "Select a WLAN first")
    return await request.app.state.capture.start(int(target["channel"]), target)


@router.post("/stop")
async def stop_capture(request: Request) -> dict:
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


@router.delete("/{filename}")
async def delete_capture(filename: str, request: Request) -> dict:
    return await request.app.state.capture.delete(filename)
