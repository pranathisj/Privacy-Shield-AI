from __future__ import annotations

import secrets
import asyncio
from dataclasses import replace
from pathlib import Path
from uuid import UUID
from unittest.mock import patch

import httpx
import pytest
from cryptography.fernet import Fernet

from app.backend.api import app
from app.config import Settings
from app.privacy.detector import PIIDetector
from app.services.privacy import PrivacyService
from app.services.llm import MockProvider, OpenAICompatibleProvider, create_provider
from app.storage.database import MappingStore


def _settings() -> Settings:
    return Settings(
        data_dir=Path("unused"),
        database_path=Path("unused") / "privacyshield.db",
        encryption_key=Fernet.generate_key().decode("ascii"),
        llm_provider="openai-compatible",
        llm_api_key="fictional-external-key",
        llm_base_url="https://provider.example.invalid/v1",
        llm_model="fictional-model",
        llm_timeout_seconds=1,
        presidio_enabled=False,
        presidio_model="en_core_web_sm",
        api_key="fictional-backend-key",
    )


def _uses_configured_bearer_key(headers: object, api_key: str) -> bool:
    if not isinstance(headers, dict):
        return False
    authorization = headers.get("Authorization")
    return isinstance(authorization, str) and secrets.compare_digest(
        authorization,
        f"{'Bear' + 'er'} {api_key}",
    )


def test_external_provider_request_uses_configured_auth_and_sanitized_payload() -> None:
    sanitized_payload = "Applicant [PERSON_1], phone [PHONE_1]."
    settings = _settings()
    response = httpx.Response(
        200,
        json={"choices": [{"message": {"content": "Analysis of [PERSON_1]."}}]},
        request=httpx.Request("POST", "https://provider.example.invalid/v1/chat/completions"),
    )
    with patch("app.services.llm.httpx.post", return_value=response) as post:
        result = OpenAICompatibleProvider(settings).complete(sanitized_payload)

    assert result == "Analysis of [PERSON_1]."
    assert _uses_configured_bearer_key(
        post.call_args.kwargs["headers"],
        settings.llm_api_key or "",
    ), "The provider must use the configured credential format."
    request_payload = post.call_args.kwargs["json"]
    assert request_payload["model"] == "fictional-model"
    assert request_payload["messages"][1]["content"] == sanitized_payload
    assert [message["role"] for message in request_payload["messages"]] == ["system", "user"]
    assert "Asha Mehta" not in str(request_payload)
    assert "9876543210" not in str(request_payload)


@pytest.mark.parametrize("api_key", [None, "", " \t"])
def test_external_provider_rejects_missing_or_blank_api_key(api_key: str | None) -> None:
    settings = replace(_settings(), llm_api_key=api_key)

    with pytest.raises(
        ValueError,
        match="^LLM_API_KEY is required for the openai-compatible provider\\.$",
    ):
        OpenAICompatibleProvider(settings)


def test_mock_provider_remains_available_without_external_api_key() -> None:
    settings = replace(_settings(), llm_provider="mock", llm_api_key=None)

    provider = create_provider(settings)

    assert isinstance(provider, MockProvider)
    assert provider.complete("Applicant [PERSON_1].").endswith("Applicant [PERSON_1].")


def test_external_provider_errors_do_not_expose_api_key_or_response_body() -> None:
    response = httpx.Response(
        500,
        text="fictional-external-key Asha Mehta 9876543210",
        request=httpx.Request("POST", "https://provider.example.invalid/v1/chat/completions"),
    )
    with patch("app.services.llm.httpx.post", return_value=response):
        with pytest.raises(RuntimeError, match="^LLM provider request failed\\.$") as error:
            OpenAICompatibleProvider(_settings()).complete("Sanitized [PHONE_1].")

    assert "fictional-external-key" not in str(error.value)
    assert "Asha Mehta" not in str(error.value)
    assert "9876543210" not in str(error.value)


def test_external_provider_timeout_is_reported_without_sensitive_details() -> None:
    secret_values = ("fictional-external-key", "Asha Mehta", "9876543210")
    with patch(
        "app.services.llm.httpx.post",
        side_effect=httpx.TimeoutException(" ".join(secret_values)),
    ):
        with pytest.raises(RuntimeError, match="^LLM provider request failed\\.$") as error:
            OpenAICompatibleProvider(_settings()).complete(
                "Applicant [PERSON_1], phone [PHONE_1]."
            )

    assert all(value not in str(error.value) for value in secret_values)


def test_gateway_records_failed_provider_timeout_without_sensitive_values(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(),
        data_dir=tmp_path,
        database_path=tmp_path / "privacyshield.db",
    )
    store = MappingStore(settings)
    service = PrivacyService(
        PIIDetector(replace(settings, presidio_enabled=False)),
        store,
        OpenAICompatibleProvider(settings),
    )
    scan = service.scan("Applicant: Asha Mehta; phone 9876543210.")

    with patch(
        "app.services.llm.httpx.post",
        side_effect=httpx.TimeoutException("fictional-external-key Asha Mehta"),
    ):
        with pytest.raises(RuntimeError, match="^AI completion failed\\.$") as error:
            service.complete(UUID(str(scan["request_id"])))

    audit = store.get_audit_logs()
    completion = next(event for event in audit if event["event"] == "completion")
    assert completion["success"] is False
    assert completion["provider"] == "openai-compatible"
    assert completion["model"] == settings.llm_model
    assert all(
        value not in str(error.value) + str(audit)
        for value in ("fictional-external-key", "Asha Mehta", "9876543210")
    )


def test_openai_compatible_gateway_api_restores_response_only_locally_after_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    llm_key = "fictional-external-key"
    backend_key = "fictional-backend-key"
    settings = replace(
        _settings(),
        data_dir=tmp_path,
        database_path=tmp_path / "privacyshield.db",
        api_key=backend_key,
    )
    service = PrivacyService(
        PIIDetector(replace(settings, presidio_enabled=False)),
        MappingStore(settings),
        OpenAICompatibleProvider(settings),
    )
    monkeypatch.setattr("app.backend.api.get_service", lambda: service)
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", backend_key)
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PRIVACYSHIELD_DATABASE_PATH", str(tmp_path / "privacyshield.db"))
    monkeypatch.setenv("PRESIDIO_ENABLED", "false")

    original = "Applicant: Asha Mehta; phone 9876543210; Aadhaar 2345 6700 0019."
    raw_provider_response = "Call [PHONE_1] about applicant [PERSON_1]."
    fake_response = httpx.Response(
        200,
        json={"choices": [{"message": {"content": raw_provider_response}}]},
        request=httpx.Request(
            "POST",
            "https://provider.example.invalid/v1/chat/completions",
        ),
    )
    sanitized_payload: list[str] = []

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": backend_key}
            scan = await client.post("/api/scan", json={"text": original}, headers=headers)
            assert scan.status_code == 200
            scan_body = scan.json()
            sanitized = scan_body["sanitized_text"]
            sanitized_payload.append(sanitized)
            assert "Asha Mehta" not in sanitized
            assert "9876543210" not in sanitized
            assert "2345 6700 0019" not in sanitized

            completion = await client.post(
                "/api/complete",
                json={"request_id": scan_body["request_id"]},
                headers=headers,
            )
            assert completion.status_code == 200
            assert completion.json() == {
                "response": raw_provider_response,
                "display_response": raw_provider_response,
                "provider": "openai-compatible",
            }

            denied = await client.post(
                "/api/reidentify",
                json={
                    "request_id": scan_body["request_id"],
                    "raw_response": raw_provider_response,
                    "authorized": False,
                },
                headers=headers,
            )
            assert denied.status_code == 403

            restored = await client.post(
                "/api/reidentify",
                json={
                    "request_id": scan_body["request_id"],
                    "raw_response": raw_provider_response,
                    "authorized": True,
                },
                headers=headers,
            )
            assert restored.status_code == 200
            assert restored.json() == {
                "response": "Call 9876543210 about applicant Asha Mehta.",
                "restored_count": 2,
            }
            audit = (
                await client.get("/api/audit", headers=headers)
            ).json()["logs"]
            completion_audit = next(event for event in audit if event["event"] == "completion")
            assert completion_audit["provider"] == "openai-compatible"
            assert completion_audit["model"] == settings.llm_model
            assert completion_audit["success"] is True
            assert all(
                value not in str(audit)
                for value in (llm_key, backend_key, "Asha Mehta", "9876543210")
            )

    with patch("app.services.llm.httpx.post", return_value=fake_response) as post:
        asyncio.run(exercise_api())

    assert post.call_count == 1
    request_payload = post.call_args.kwargs["json"]
    outbound_text = request_payload["messages"][1]["content"]
    assert outbound_text == sanitized_payload[0]
    assert "[PERSON_1]" in outbound_text
    assert "[PHONE_1]" in outbound_text
    assert "[AADHAAR_1]" in outbound_text
    assert all(value not in outbound_text for value in ("Asha Mehta", "9876543210", "2345 6700 0019"))
    assert _uses_configured_bearer_key(post.call_args.kwargs["headers"], llm_key)
    assert llm_key not in str(request_payload)
