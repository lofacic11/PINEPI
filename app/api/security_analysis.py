from uuid import UUID

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/security-analysis", tags=["security-analysis"])


@router.get("/rogue-access-points")
async def rogue_access_points(session_id: UUID, request: Request) -> dict:
    return request.app.state.rogue_detection.analyze(str(session_id))


@router.get("/kismet/status")
async def kismet_status(request: Request) -> dict:
    return await request.app.state.kismet.status()
