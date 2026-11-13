from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.privacy.detector import PIIDetector
from app.services.llm import MockProvider
from app.services.privacy import PrivacyService
from app.storage.database import MappingNotFoundError, MappingStore


def _settings(data_dir: Path, retention_days: int = 30) -> Settings:
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "privacyshield.db",
        encryption_key=Fernet.generate_key().decode("ascii"),
        llm_provider="mock",
        llm_api_key=None,
        llm_base_url="https://api.example.invalid/v1",
        llm_model="fictional-model",
        llm_timeout_seconds=1,
        presidio_enabled=False,
        presidio_model="en_core_web_sm",
        api_key="fictional-api-key",
        retention_days=retention_days,
    )


def test_audit_has_event_time_entity_and_model_metadata_but_no_prompt_text(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    store = MappingStore(settings)
    service = PrivacyService(PIIDetector(settings), store, MockProvider())
    raw_prompt = (
        "Applicant: Asha Mehta; phone 9876543210; "
        "monthly salary INR 85,000; loan INR 5,00,000."
    )
    scan = service.scan(raw_prompt)
    request_id = UUID(str(scan["request_id"]))
    sanitized = str(scan["sanitized_text"])
    service.complete(request_id)

    events = store.get_audit_logs()
    scan_event = next(event for event in events if event["event"] == "scan")
    completion_event = next(event for event in events if event["event"] == "completion")

    assert datetime.fromisoformat(scan_event["created_at"]).tzinfo is not None
    assert datetime.fromisoformat(completion_event["created_at"]).tzinfo is not None
    assert scan_event["entity_types"] == ["PERSON", "PHONE"]
    assert completion_event["entity_types"] == ["PERSON", "PHONE"]
    assert scan_event["provider"] is None and scan_event["model"] is None
    assert completion_event["provider"] == "mock"
    assert completion_event["model"] == "local-mock"
    assert sanitized in store.get_sanitized_text(request_id)
    assert "Asha Mehta" not in json.dumps(events)
    assert "9876543210" not in json.dumps(events)
    assert raw_prompt not in json.dumps(events)

    with store._connect() as connection:
        audit_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(audit_logs)")
        }
        assert "sanitized_payload" not in audit_columns
        assert connection.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_expiration_deletes_audit_requests_and_cascaded_encrypted_mappings(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, retention_days=7)
    store = MappingStore(settings)
    service = PrivacyService(PIIDetector(settings), store, MockProvider())
    old_scan = service.scan("Applicant: Asha Mehta; phone 9876543210.")
    current_scan = service.scan("Applicant: Neha Iyer; phone 9876543211.")
    old_request_id = UUID(str(old_scan["request_id"]))
    expired_at = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()

    with store._connect() as connection:
        connection.execute(
            "UPDATE requests SET created_at = ? WHERE request_id = ?",
            (expired_at, str(old_request_id)),
        )
        connection.execute(
            "UPDATE audit_logs SET created_at = ? WHERE request_id = ?",
            (expired_at, str(old_request_id)),
        )

    remaining_audits = store.get_audit_logs()

    assert len(remaining_audits) == 1
    assert remaining_audits[0]["request_id"] == current_scan["request_id"]
    with pytest.raises(MappingNotFoundError):
        store.get_sanitized_text(old_request_id)
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM requests WHERE request_id = ?",
            (str(old_request_id),),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM mappings WHERE request_id = ?",
            (str(old_request_id),),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE request_id = ?",
            (str(old_request_id),),
        ).fetchone()[0] == 0


def test_existing_audit_database_is_migrated_with_nullable_model_metadata(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(settings.database_path) as connection:
        connection.execute(
            """
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                event TEXT NOT NULL,
                entity_types TEXT NOT NULL,
                entity_count INTEGER NOT NULL,
                success INTEGER NOT NULL,
                provider TEXT,
                duration_ms REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO audit_logs(
                request_id, event, entity_types, entity_count, success, provider,
                duration_ms, created_at
            ) VALUES ('old-request', 'completion', '[]', 0, 1, 'legacy', 1.0, ?)
            """,
            (created_at,),
        )

    store = MappingStore(settings)
    logs = store.get_audit_logs()

    assert len(logs) == 1
    assert logs[0]["provider"] == "legacy"
    assert logs[0]["model"] is None


def test_provider_failure_details_are_not_logged_or_returned(tmp_path: Path, caplog) -> None:
    settings = _settings(tmp_path)
    store = MappingStore(settings)

    class LeakyErrorProvider:
        name = "external-test"
        model = "fictional-model"

        def complete(self, _: str) -> str:
            raise RuntimeError("Asha Mehta 9876543210 fictional-api-key")

    service = PrivacyService(PIIDetector(settings), store, LeakyErrorProvider())
    scan = service.scan("Applicant: Asha Mehta; phone 9876543210.")
    caplog.set_level(logging.ERROR)

    with pytest.raises(RuntimeError, match="^AI completion failed\\.$") as error:
        service.complete(UUID(str(scan["request_id"])))

    assert "Asha Mehta" not in caplog.text
    assert "9876543210" not in caplog.text
    assert "fictional-api-key" not in caplog.text
    assert "Asha Mehta" not in str(error.value)
    assert "9876543210" not in str(error.value)
    assert "fictional-api-key" not in str(error.value)
    failure_event = next(
        event for event in store.get_audit_logs() if event["event"] == "completion"
    )
    assert failure_event["success"] is False
    assert failure_event["provider"] == "external-test"
    assert failure_event["model"] == "fictional-model"
