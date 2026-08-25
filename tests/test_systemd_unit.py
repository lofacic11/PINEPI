from pathlib import Path


UNIT_PATH = Path(__file__).parents[1] / "config" / "pinepi.service"


def directives() -> list[str]:
    return [
        line.strip()
        for line in UNIT_PATH.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def test_runtime_directory_is_declared_once():
    unit = directives()
    assert unit.count("RuntimeDirectory=pinepi") == 1
    assert unit.count("RuntimeDirectoryMode=0755") == 1


def test_runtime_directory_remains_writable_in_sandbox():
    writable_paths = [line for line in directives() if line.startswith("ReadWritePaths=")]
    assert len(writable_paths) == 1
    assert "/var/lib/pinepi" in writable_paths[0].split("=", 1)[1].split()
    assert "/run/pinepi" in writable_paths[0].split("=", 1)[1].split()


def test_production_working_directory_and_virtualenv_are_preserved():
    unit = directives()
    assert "User=pinepi" in unit
    assert "Group=pinepi" in unit
    assert "WorkingDirectory=/opt/pinepi" in unit
    assert any(
        line.startswith("ExecStart=/opt/pinepi/.venv/bin/uvicorn ")
        for line in unit
    )
