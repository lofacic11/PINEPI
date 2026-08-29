from uuid import UUID

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/recon/{session_id}")
async def recon_report(session_id: UUID, request: Request) -> dict:
    return request.app.state.reporting.session_report(str(session_id))
