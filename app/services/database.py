from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path


SCHEMA_VERSION = 3


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._lock, self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
                INSERT INTO schema_meta(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);

                CREATE TABLE IF NOT EXISTS scan_sessions(
                    id TEXT PRIMARY KEY, started_at TEXT NOT NULL, stopped_at TEXT,
                    status TEXT NOT NULL, audit_interface TEXT NOT NULL, monitor_interface TEXT NOT NULL,
                    bands TEXT NOT NULL DEFAULT '', channels TEXT NOT NULL DEFAULT '',
                    ap_count INTEGER NOT NULL DEFAULT 0, client_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '', runtime_pid INTEGER, operation_id TEXT, mock INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_started ON scan_sessions(started_at DESC);

                CREATE TABLE IF NOT EXISTS access_points(
                    session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL, ssid TEXT NOT NULL DEFAULT '', hidden INTEGER NOT NULL DEFAULT 0,
                    channel INTEGER, frequency INTEGER, band TEXT NOT NULL DEFAULT 'unknown', signal INTEGER,
                    security TEXT NOT NULL DEFAULT 'Unknown', privacy TEXT NOT NULL DEFAULT '',
                    cipher TEXT NOT NULL DEFAULT '', authentication TEXT NOT NULL DEFAULT '',
                    pmf TEXT NOT NULL DEFAULT 'unknown', beacons INTEGER NOT NULL DEFAULT 0,
                    data_packets INTEGER NOT NULL DEFAULT 0, first_seen TEXT, last_seen TEXT,
                    vendor TEXT NOT NULL DEFAULT 'Unknown', visible INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(session_id,bssid)
                );
                CREATE INDEX IF NOT EXISTS idx_ap_bssid ON access_points(bssid);
                CREATE INDEX IF NOT EXISTS idx_ap_ssid ON access_points(ssid);

                CREATE TABLE IF NOT EXISTS clients(
                    session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
                    station_mac TEXT NOT NULL, bssid TEXT, relationship TEXT NOT NULL DEFAULT 'unknown',
                    probed_ssids TEXT NOT NULL DEFAULT '', signal INTEGER, packet_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT, last_seen TEXT, vendor TEXT NOT NULL DEFAULT 'Unknown',
                    PRIMARY KEY(session_id,station_mac)
                );
                CREATE INDEX IF NOT EXISTS idx_clients_bssid ON clients(session_id,bssid);

                CREATE TABLE IF NOT EXISTS signal_samples(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, bssid TEXT NOT NULL,
                    observed_at TEXT NOT NULL, signal INTEGER NOT NULL,
                    FOREIGN KEY(session_id,bssid) REFERENCES access_points(session_id,bssid) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS trusted_profiles(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ssid TEXT NOT NULL UNIQUE,
                    expected_security TEXT NOT NULL DEFAULT '', expected_channels TEXT NOT NULL DEFAULT '',
                    expected_vendor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trusted_bssids(
                    profile_id INTEGER NOT NULL REFERENCES trusted_profiles(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL, PRIMARY KEY(profile_id,bssid)
                );

                CREATE TABLE IF NOT EXISTS operations(
                    id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, resource TEXT NOT NULL,
                    started_at TEXT NOT NULL, finished_at TEXT, timeout_seconds INTEGER,
                    pid INTEGER, error_code TEXT NOT NULL DEFAULT '', error_message TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_operations_started ON operations(started_at DESC);

                CREATE TABLE IF NOT EXISTS capture_metadata(
                    filename TEXT PRIMARY KEY, created_at REAL NOT NULL, engine TEXT NOT NULL DEFAULT 'dumpcap',
                    ssid TEXT NOT NULL DEFAULT '', bssid TEXT NOT NULL DEFAULT '', client TEXT NOT NULL DEFAULT '',
                    channel INTEGER, operation_id TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS analysis_results(
                    id TEXT PRIMARY KEY, filename TEXT NOT NULL, engine TEXT NOT NULL,
                    created_at TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_analysis_capture ON analysis_results(filename,created_at DESC);
                """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
            for name, declaration in (
                ("owner", "TEXT NOT NULL DEFAULT 'pinepi-web'"),
                ("adapter", "TEXT NOT NULL DEFAULT ''"),
                ("target_json", "TEXT NOT NULL DEFAULT '{}'"),
                ("exit_code", "INTEGER"),
                ("artifacts_json", "TEXT NOT NULL DEFAULT '[]'"),
            ):
                if name not in columns:
                    db.execute(f"ALTER TABLE operations ADD COLUMN {name} {declaration}")
            db.execute("UPDATE schema_meta SET version=?", (SCHEMA_VERSION,))

    def execute(self, sql: str, parameters: tuple = ()) -> None:
        with self._lock, self.connect() as db:
            db.execute(sql, parameters)

    def query(self, sql: str, parameters: tuple = ()) -> list[dict]:
        with self._lock, self.connect() as db:
            return [dict(row) for row in db.execute(sql, parameters).fetchall()]

    def one(self, sql: str, parameters: tuple = ()) -> dict | None:
        rows = self.query(sql, parameters)
        return rows[0] if rows else None
