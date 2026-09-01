from dataclasses import replace

import httpx
import pytest

from app.config import AppConfig, ReconConfig, StorageConfig
from app.main import app
from app.services.database import Database
from app.services.process_manager import ProcessManager
from app.services.recon import ReconService


class NoHelper:
    async def call(self, *_args):
        raise AssertionError("mock API must not invoke the root helper")


@pytest.mark.asyncio
async def test_recon_api_validation_pagination_privacy_and_static_assets(tmp_path):
    base = AppConfig()
    config = replace(
        base,
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"),
        recon=ReconConfig(mock_mode=True),
    )
    database = Database(config.storage.database)
    database.initialize()
    operations = ProcessManager(database)
    app.state.recon = ReconService(config, NoHelper(), database, operations)
    app.state.processes = operations
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    headers = {"X-PinePi-Action": "confirmed"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        started = await client.post("/api/recon/sessions", headers=headers)
        assert started.status_code == 201
        session_id = started.json()["id"]
        result = await client.get("/api/recon/access-points", params={"session_id": session_id, "limit": 2})
        assert result.status_code == 200
        assert len(result.json()["items"]) == 2
        assert result.json()["total"] == 4
        assert await _status(client, "/api/recon/access-points?limit=101") == 422
        assert await _status(client, "/api/recon/access-points?sort=ssid%3BDROP%20TABLE") == 422
        assert await _status(client, "/api/recon/access-points?pmf=required") == 422
        assert await _status(client, "/api/recon/clients/../../etc/passwd", session_id=session_id) == 404
        page = await client.get("/")
        assert page.status_code == 200
        assert page.headers["x-frame-options"] == "DENY"
        assert "CHANGE-ME" not in page.text
        await client.post(f"/api/recon/sessions/{session_id}/stop", headers=headers)


async def _status(client, path, **params):
    return (await client.get(path, params=params or None)).status_code
