import httpx
import pytest

from app.main import app


def test_application_version_remains_v070():
    assert app.version == "0.7.0"


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
