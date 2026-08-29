import json

import pytest

from app.config import AppConfig, ReconConfig, StorageConfig
from app.services.capture import CaptureService
from app.services.database import Database
from app.services.mock_data import MOCK_APS, MOCK_CLIENTS
from app.services.process_manager import ProcessManager
from app.services.recon import ReconService
from app.services.reporting import ReportingService
from app.services.rogue_detection import RogueDetectionService


class NoHelper:
    async def call(self, *_args):
        raise AssertionError("mock service must not invoke helper")


@pytest.mark.asyncio
async def test_report_distinguishes_evidence_types_and_excludes_secrets(tmp_path):
    config = AppConfig(
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "data.db"),
        recon=ReconConfig(mock_mode=True),
    )
    database = Database(config.storage.database)
    database.initialize()
    operations = ProcessManager(database)
    recon = ReconService(config, NoHelper(), database, operations)
    session = await recon.start()
    captures = CaptureService(config, NoHelper(), operations, database)
    rogue = RogueDetectionService(database)
    report = ReportingService(database, recon, rogue, captures).session_report(session["id"])
    assert report["sections"]["observed_facts"]["classification"] == "Observed fact"
    assert report["sections"]["calculated_indicators"]["classification"] == "Calculated indicator"
    assert report["sections"]["operator_active_tests"]["classification"] == "Operator-run active test"
    serialized = json.dumps(report).lower()
    assert "wpa_passphrase" not in serialized
    assert "change-me-before-use" not in serialized
