"""SQLite persistence for encrypted mappings, sanitized requests, and audit metadata."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken

from app.config import Settings
from app.privacy.masking import MappingEntry

logger = logging.getLogger(__name__)


class MappingNotFoundError(LookupError):
    """Raised when a request or placeholder mapping is not present locally."""


class MappingStore:
    def __init__(self, settings: Settings) -> None:
        self.database_path = settings.database_path
        self._retention_days = settings.retention_days
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_key(settings.encryption_key, settings.data_dir))
        self._initialize()

    @staticmethod
    def _load_key(configured_key: str | None, data_dir: Path) -> bytes:
        if configured_key:
            try:
                Fernet(configured_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError("PRIVACYSHIELD_ENCRYPTION_KEY must be a valid Fernet key.") from exc
            return configured_key.encode("ascii")

        data_dir.mkdir(parents=True, exist_ok=True)
        key_path = data_dir / ".mapping.key"
        try:
            with key_path.open("xb") as key_file:
                key_file.write(Fernet.generate_key())
            if os.name != "nt":
                key_path.chmod(0o600)
        except FileExistsError:
            pass

        try:
            key = key_path.read_bytes()
            Fernet(key)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Unable to load local mapping encryption key: {exc}") from exc
        return key

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS requests (
                        request_id TEXT PRIMARY KEY,
                        sanitized_text TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS mappings (
                        request_id TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
                        placeholder TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        encrypted_value BLOB NOT NULL,
                        PRIMARY KEY (request_id, placeholder)
                    );
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT,
                        event TEXT NOT NULL,
                        entity_types TEXT NOT NULL,
                        entity_count INTEGER NOT NULL,
                        success INTEGER NOT NULL,
                        provider TEXT,
                        model TEXT,
                        duration_ms REAL NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )
                audit_columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(audit_logs)")
                }
                if "model" not in audit_columns:
                    connection.execute("ALTER TABLE audit_logs ADD COLUMN model TEXT")
        except sqlite3.Error as exc:
            logger.error("Could not initialize local database")
            raise RuntimeError("Could not initialize PrivacyShield local storage.") from exc
        self.purge_expired()

    def purge_expired(self) -> int:
        """Delete expired audit events, sanitized requests, and their encrypted mappings."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        ).isoformat()
        try:
            with self._connect() as connection:
                deleted_audits = connection.execute(
                    "DELETE FROM audit_logs WHERE created_at < ?",
                    (cutoff,),
                ).rowcount
                connection.execute(
                    "DELETE FROM requests WHERE created_at < ?",
                    (cutoff,),
                )
            return max(0, deleted_audits)
        except sqlite3.Error as exc:
            logger.error("Could not purge expired local records")
            raise RuntimeError("Could not purge expired local records.") from exc

    def save_scan(
        self,
        request_id: UUID,
        sanitized_text: str,
        mappings: Iterable[MappingEntry],
        duration_ms: float,
    ) -> None:
        self.purge_expired()
        entries = tuple(mappings)
        entity_types = sorted({entry.entity_type for entry in entries})
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO requests(request_id, sanitized_text, created_at) VALUES (?, ?, ?)",
                    (str(request_id), sanitized_text, now),
                )
                connection.executemany(
                    """
                    INSERT INTO mappings(request_id, placeholder, entity_type, encrypted_value)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            str(request_id),
                            entry.placeholder,
                            entry.entity_type,
                            self._fernet.encrypt(entry.original_value.encode("utf-8")),
                        )
                        for entry in entries
                    ],
                )
                connection.execute(
                    """
                    INSERT INTO audit_logs(
                        request_id, event, entity_types, entity_count, success, provider,
                        duration_ms, created_at
                    ) VALUES (?, 'scan', ?, ?, 1, NULL, ?, ?)
                    """,
                    (str(request_id), json.dumps(entity_types), len(entries), duration_ms, now),
                )
        except sqlite3.Error as exc:
            logger.error("Could not save local scan data")
            raise RuntimeError("Could not save the scan in local storage.") from exc

    def get_sanitized_text(self, request_id: UUID) -> str:
        self.purge_expired()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT sanitized_text FROM requests WHERE request_id = ?",
                    (str(request_id),),
                ).fetchone()
        except sqlite3.Error as exc:
            logger.error("Could not read the sanitized request")
            raise RuntimeError("Could not read the saved request.") from exc
        if row is None:
            raise MappingNotFoundError("Scan request was not found. Scan the text again.")
        return str(row["sanitized_text"])

    def get_mappings(self, request_id: UUID) -> dict[str, str]:
        self.purge_expired()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT placeholder, encrypted_value FROM mappings WHERE request_id = ?",
                    (str(request_id),),
                ).fetchall()
        except sqlite3.Error as exc:
            logger.error("Could not read the local mapping")
            raise RuntimeError("Could not read the saved local mapping.") from exc
        try:
            return {
                str(row["placeholder"]): self._fernet.decrypt(row["encrypted_value"]).decode("utf-8")
                for row in rows
            }
        except (InvalidToken, UnicodeDecodeError) as exc:
            logger.error("Could not decrypt local mapping")
            raise RuntimeError("Local mapping could not be decrypted; check the encryption key.") from exc

    def record_completion(
        self,
        request_id: UUID,
        entity_types: list[str],
        provider: str,
        model: str,
        duration_ms: float,
        success: bool,
    ) -> None:
        self.purge_expired()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO audit_logs(
                        request_id, event, entity_types, entity_count, success, provider,
                        model, duration_ms, created_at
                    ) VALUES (?, 'completion', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(request_id),
                        json.dumps(sorted(set(entity_types))),
                        len(entity_types),
                        int(success),
                        provider,
                        model,
                        duration_ms,
                        now,
                    ),
                )
        except sqlite3.Error as exc:
            logger.error("Could not write completion audit record")
            raise RuntimeError("Could not record the completion in the local audit log.") from exc

    def record_reidentification(
        self,
        request_id: UUID,
        entity_types: list[str],
        restored_count: int,
    ) -> None:
        self.purge_expired()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO audit_logs(
                        request_id, event, entity_types, entity_count, success, provider,
                        model, duration_ms, created_at
                    ) VALUES (?, 'reidentification', ?, ?, 1, NULL, NULL, 0, ?)
                    """,
                    (
                        str(request_id),
                        json.dumps(sorted(set(entity_types))),
                        restored_count,
                        now,
                    ),
                )
        except sqlite3.Error as exc:
            logger.error("Could not write re-identification audit record")
            raise RuntimeError(
                "Could not record placeholder restoration in the local audit log."
            ) from exc

    def get_audit_logs(self, limit: int = 50) -> list[dict[str, object]]:
        self.purge_expired()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT request_id, event, entity_types, entity_count, success, provider, model,
                           duration_ms, created_at
                    FROM audit_logs ORDER BY id DESC LIMIT ?
                    """,
                    (max(1, min(limit, 200)),),
                ).fetchall()
            return [
                {
                    "request_id": row["request_id"],
                    "event": row["event"],
                    "entity_types": json.loads(row["entity_types"]),
                    "entity_count": row["entity_count"],
                    "success": bool(row["success"]),
                    "provider": row["provider"],
                    "model": row["model"],
                    "duration_ms": row["duration_ms"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            logger.error("Could not read audit log")
            raise RuntimeError("Could not load the local audit log.") from exc

    def get_metrics(self) -> dict[str, int]:
        self.purge_expired()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT
                        COALESCE(SUM(CASE WHEN event = 'scan' THEN 1 ELSE 0 END), 0) AS scans,
                        COALESCE(SUM(CASE WHEN event = 'completion' AND success = 1 THEN 1 ELSE 0 END), 0)
                            AS completions,
                        COALESCE(SUM(CASE WHEN event = 'scan' THEN entity_count ELSE 0 END), 0)
                            AS entities_masked
                    FROM audit_logs
                    """
                ).fetchone()
            return {
                "scans": int(row["scans"]),
                "completions": int(row["completions"]),
                "entities_masked": int(row["entities_masked"]),
            }
        except sqlite3.Error as exc:
            logger.error("Could not calculate privacy metrics")
            raise RuntimeError("Could not load privacy metrics.") from exc
