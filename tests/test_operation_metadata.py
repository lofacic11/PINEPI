import json

import pytest

from app.services.database import Database, SCHEMA_VERSION
from app.services.process_manager import ProcessManager


@pytest.mark.asyncio
async def test_operation_metadata_error_code_exit_and_artifact_are_persisted(tmp_path):
    database = Database(tmp_path / "pinepi.db")
    database.initialize()
    operations = ProcessManager(database)
    operation_id = await operations.acquire(
        "DEAUTH_TEST",
        "audit_adapter",
        15,
        adapter="wlan9",
        target={"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6},
    )
    operations.attach_pid(operation_id, 123)
    operations.attach_artifact(operation_id, "capture-safe-id.pcapng")
    operations.finish(operation_id, "failed", "PROCESS_EXITED: test process stopped", 2)
    row = database.one("SELECT * FROM operations WHERE id=?", (operation_id,))
    assert row["adapter"] == "wlan9"
    assert json.loads(row["target_json"])["channel"] == 6
    assert json.loads(row["artifacts_json"]) == ["capture-safe-id.pcapng"]
    assert row["error_code"] == "PROCESS_EXITED"
    assert row["exit_code"] == 2
    assert database.one("SELECT version FROM schema_meta")["version"] == SCHEMA_VERSION
