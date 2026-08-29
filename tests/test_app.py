import httpx
import pytest

from app.main import app, normalized_error


def test_application_version_is_v090():
    assert app.version == "0.9.0"


def test_common_operation_errors_have_stable_codes():
    assert normalized_error("NO_TARGET: select an AP", "INVALID_REQUEST") == ("NO_TARGET", "select an AP")
    assert normalized_error("audit_adapter is owned by another operation", "X")[0] == "ADAPTER_BUSY"
    assert normalized_error("Required executable not found: mdk4", "X")[0] == "TOOL_MISSING"


@pytest.mark.asyncio
async def test_health_and_index():
    # Do not enter the lifespan here: hardware/helper shutdown is integration behavior.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        page = await client.get("/")
        assert page.status_code == 200
        assert "PinePi" in page.text
