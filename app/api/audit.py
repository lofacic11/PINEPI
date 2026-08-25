from fastapi import APIRouter, HTTPException, Request

from app.services.audit import score_security

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def passive_audit(request: Request) -> dict:
    target = await request.app.state.app_state.target()
    if not target:
        raise HTTPException(409, "Select a WLAN first")
    return {"target": target, **score_security(target)}

