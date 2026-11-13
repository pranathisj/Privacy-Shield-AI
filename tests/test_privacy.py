from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.fernet import Fernet

from app.backend.api import app, get_service
from app.config import Settings
from app.privacy.detector import PIIDetector
from app.privacy.masking import mask_text
from app.services.llm import MockProvider
from app.services.privacy import PrivacyService
from app.storage.database import MappingStore


def test_india_patterns_detect_and_mask_fictional_pii() -> None:
    text = (
        "Name: Asha Mehta; phone +91 98765 43210; Aadhaar 2345 6789 0124; "
        "PAN ABCPE1234F; salary INR 85,000."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    findings = detector.detect(text)
    result = mask_text(text, findings)

    assert {finding.entity_type for finding in findings} >= {
        "PERSON",
        "PHONE",
        "AADHAAR",
        "PAN",
    }
    assert "Asha Mehta" not in result.sanitized_text
    assert "98765 43210" not in result.sanitized_text
    assert "2345 6789 0124" not in result.sanitized_text
    assert "ABCPE1234F" not in result.sanitized_text
    assert "salary INR 85,000." in result.sanitized_text


def test_banking_scan_masks_identifiers_but_preserves_financial_amounts() -> None:
    text = (
        "Applicant Asha Mehta, phone 9876543210, Aadhaar 2345 6789 0124, "
        "monthly salary INR 85,000, requested loan INR 5,00,000."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    result = mask_text(text, detector.detect(text))

    assert result.sanitized_text == (
        "Applicant [PERSON_1], phone [PHONE_1], Aadhaar [AADHAAR_1], "
        "monthly salary INR 85,000, requested loan INR 5,00,000."
    )


@pytest.mark.parametrize(
    ("text", "entity_type", "value", "validation_status"),
    [
        ("Aadhaar: 2345 6789 0123", "AADHAAR", "2345 6789 0123", "invalid"),
        ("Aadhaar: 2345 6700 0019", "AADHAAR", "2345 6700 0019", "valid"),
        ("Mobile: 12345", "PHONE", "12345", "invalid"),
    ],
)
def test_validation_status_never_blocks_masking_or_sanitized_completion(
    tmp_path: Path,
    text: str,
    entity_type: str,
    value: str,
    validation_status: str,
) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)

    class CapturingProvider:
        name = "test-provider"
        model = "fictional-test-model"

        def __init__(self) -> None:
            self.received = ""

        def complete(self, sanitized_text: str) -> str:
            self.received = sanitized_text
            return f"Reviewed {sanitized_text}"

    provider = CapturingProvider()
    service = PrivacyService(PIIDetector(settings), store, provider)

    scan = service.scan(text)
    completion = service.complete(UUID(str(scan["request_id"])))

    assert scan["validation"]["fields"][0]["status"] == validation_status
    assert scan["sanitized_text"] == f"{text.split(':', maxsplit=1)[0]}: [{entity_type}_1]"
    assert value not in scan["sanitized_text"]
    assert provider.received == scan["sanitized_text"]
    assert value not in provider.received
    assert value not in str(completion["response"])


def test_presidio_money_findings_do_not_mask_financial_amounts() -> None:
    class PresidioMoneyAnalyzer:
        def analyze(self, text: str, language: str) -> list[object]:
            start = text.index("85,000")
            return [
                type(
                    "AnalyzerResult",
                    (),
                    {"entity_type": "MONEY", "start": start, "end": start + 6, "score": 0.99},
                )()
            ]

    text = "Monthly salary INR 85,000"
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    detector._presidio = PresidioMoneyAnalyzer()
    result = mask_text(text, detector.detect(text))

    assert result.sanitized_text == text


def test_other_direct_identifiers_remain_masked_with_financial_context() -> None:
    text = (
        "Customer: Neha Iyer; email neha@example.invalid; "
        "address: 42 Fictional Lane, Pune; account number 123456789012; "
        "EMI INR 18,500; repayment INR 22,000."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    findings = detector.detect(text)
    result = mask_text(text, findings)
    masked_types = {finding.entity_type for finding in findings}

    assert {"PERSON", "EMAIL", "ADDRESS", "ACCOUNT_NUMBER"} <= masked_types
    assert "Neha Iyer" not in result.sanitized_text
    assert "neha@example.invalid" not in result.sanitized_text
    assert "42 Fictional Lane, Pune" not in result.sanitized_text
    assert "123456789012" not in result.sanitized_text
    assert "EMI INR 18,500" in result.sanitized_text
    assert "repayment INR 22,000" in result.sanitized_text


@pytest.mark.parametrize(
    ("text", "entity_type", "identifier"),
    [
        ("GSTIN: 27ABCPE1234F1ZB", "GSTIN", "27ABCPE1234F1ZB"),
        ("Voter ID: ABC1234567", "VOTER_ID", "ABC1234567"),
        ("Passport No: N1234567", "PASSPORT", "N1234567"),
    ],
)
def test_contextual_india_identifiers_are_masked(
    text: str,
    entity_type: str,
    identifier: str,
) -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    findings = detector.detect(text)
    result = mask_text(text, findings)

    assert [finding.entity_type for finding in findings] == [entity_type]
    assert result.sanitized_text == text.replace(identifier, f"[{entity_type}_1]")
    assert result.mappings[0].original_value == identifier


@pytest.mark.parametrize(
    "text",
    [
        "Reference 27ABCPE1234F1ZB",
        "Reference ABC1234567",
        "Reference N1234567",
    ],
)
def test_india_identifier_candidates_without_context_are_not_detected(text: str) -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    assert detector.detect(text) == []


@pytest.mark.parametrize(
    ("text", "expected_type", "expected_value"),
    [
        ("Aadhaar no. 2345 6789 0124", "AADHAAR", "2345 6789 0124"),
        ("UID: 2345-6789-0124", "AADHAAR", "2345-6789-0124"),
        ("PAN card: ABCPE1234F", "PAN", "ABCPE1234F"),
        ("Customer is Asha Mehta", "PERSON", "Asha Mehta"),
        ("Customer name is Asha Mehta", "PERSON", "Asha Mehta"),
        ("Applicant: Asha Mehta", "PERSON", "Asha Mehta"),
        ("pata: 42 Fictional Lane, Pune", "ADDRESS", "42 Fictional Lane, Pune"),
    ],
)
def test_contextual_indian_pii_formats_are_extracted_without_label_text(
    text: str,
    expected_type: str,
    expected_value: str,
) -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))

    findings = detector.detect(text)

    assert [(finding.entity_type, text[finding.start : finding.end]) for finding in findings] == [
        (expected_type, expected_value)
    ]


def test_email_id_label_and_customer_identifier_do_not_create_false_positives() -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    text = (
        "Email ID: case01@example.invalid; "
        "Transaction reference has no customer identifier."
    )

    findings = detector.detect(text)

    assert [
        (finding.entity_type, text[finding.start : finding.end]) for finding in findings
    ] == [("EMAIL", "case01@example.invalid")]


def test_contextual_name_and_address_candidates_stop_before_location_context() -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    text = "Applicant: Priya Sharma from Bengaluru; lives at 42 Fictional Lane, Pune."

    findings = detector.detect(text)

    assert [
        (finding.entity_type, text[finding.start : finding.end]) for finding in findings
    ] == [
        ("PERSON", "Priya Sharma"),
        ("ADDRESS", "42 Fictional Lane, Pune"),
    ]


@pytest.mark.skipif(
    importlib.util.find_spec("en_core_web_sm") is None,
    reason="The optional local spaCy NER model is not installed.",
)
def test_presidio_local_ner_masks_unlabelled_person_and_address() -> None:
    text = (
        "Asha Mehta applied for a loan; she lives at 42 Fictional Lane, Pune. "
        "Her monthly salary is INR 85,000."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=True))

    assert detector._presidio is not None
    findings = detector.detect(text)
    masked = mask_text(text, findings)

    assert any(
        finding.entity_type == "PERSON"
        and text[finding.start : finding.end] == "Asha Mehta"
        and finding.source == "presidio"
        for finding in findings
    )
    assert "[PERSON_1]" in masked.sanitized_text
    assert "[ADDRESS_1]" in masked.sanitized_text
    assert "Asha Mehta" not in masked.sanitized_text
    assert "42 Fictional Lane, Pune" not in masked.sanitized_text
    assert "monthly salary is INR 85,000" in masked.sanitized_text


@pytest.mark.parametrize(
    "text",
    [
        "Invoice reference 123456789012",
        "Reference 9876543210 is an internal code",
    ],
)
def test_unlabeled_ambiguous_numbers_are_not_detected_as_identifiers(text: str) -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))

    assert detector.detect(text) == []


@pytest.mark.parametrize(
    ("text", "entity_type", "value"),
    [
        ("Aadhaar: 2345 6789 0123", "AADHAAR", "2345 6789 0123"),
        ("PAN: ABCDE1234F", "PAN", "ABCDE1234F"),
        ("GSTIN: 27ABCPE1234F1Z0", "GSTIN", "27ABCPE1234F1Z0"),
        ("Voter ID: ABC123456", "VOTER_ID", "ABC123456"),
        ("Passport: N123456", "PASSPORT", "N123456"),
        ("Mobile: 12345", "PHONE", "12345"),
    ],
)
def test_invalid_contextual_identifiers_remain_maskable(
    text: str,
    entity_type: str,
    value: str,
) -> None:
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))

    findings = detector.detect(text)

    assert [(finding.entity_type, text[finding.start : finding.end]) for finding in findings] == [
        (entity_type, value)
    ]


def test_code_mixed_indian_text_masks_contextual_pii_but_preserves_financial_values() -> None:
    text = (
        "Namaste, grahak ka naam Asha Mehta; pata: 42 Fictional Lane, Pune; "
        "mobile number +91 98765 43210; Aadhaar no. 2345-6789-0124. "
        "Invoice ref 123456789012; reference 9876543210; salary INR 85,000."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))

    findings = detector.detect(text)
    result = mask_text(text, findings)

    assert {finding.entity_type for finding in findings} == {
        "PERSON",
        "ADDRESS",
        "PHONE",
        "AADHAAR",
    }
    assert "Asha Mehta" not in result.sanitized_text
    assert "42 Fictional Lane, Pune" not in result.sanitized_text
    assert "98765 43210" not in result.sanitized_text
    assert "2345-6789-0124" not in result.sanitized_text
    assert "123456789012" in result.sanitized_text
    assert "9876543210" in result.sanitized_text
    assert "salary INR 85,000" in result.sanitized_text


def test_new_india_identifiers_reuse_typed_placeholders() -> None:
    text = (
        "GSTIN: 27ABCPE1234F1ZB; GSTIN: 27ABCPE1234F1ZB; "
        "Voter ID: ABC1234567; EPIC: ABC1234567; "
        "Passport No: N1234567; Passport: N1234567."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    result = mask_text(text, detector.detect(text))

    assert result.sanitized_text.count("[GSTIN_1]") == 2
    assert result.sanitized_text.count("[VOTER_ID_1]") == 2
    assert result.sanitized_text.count("[PASSPORT_1]") == 2
    assert len(result.mappings) == 3


def test_identical_values_reuse_typed_placeholder() -> None:
    text = "Call 9876543210 or 9876543210."
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=False))
    masked = mask_text(text, detector.detect(text))
    assert masked.sanitized_text.count("[PHONE_1]") == 2
    assert len(masked.mappings) == 1


def test_mappings_are_encrypted_and_audits_exclude_original(tmp_path: Path) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)
    text = "Contact 9876543210"
    finding = PIIDetector(settings).detect(text)
    masked = mask_text(text, finding)

    request_id = uuid4()
    store.save_scan(request_id, masked.sanitized_text, masked.mappings, 1.0)
    raw_database = settings.database_path.read_bytes()
    assert b"9876543210" not in raw_database
    assert store.get_mappings(request_id)["[PHONE_1]"] == "9876543210"
    assert all("9876543210" not in str(event) for event in store.get_audit_logs())


def test_completion_receives_sanitized_text_without_reidentifying_response(tmp_path: Path) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)
    detector = PIIDetector(settings)

    class CapturingMockProvider:
        name = "test"
        model = "fictional-test-model"
        received = ""
        mock = MockProvider()

        def complete(self, sanitized_text: str) -> str:
            self.received = sanitized_text
            return self.mock.complete(sanitized_text)

    provider = CapturingMockProvider()
    service = PrivacyService(detector, store, provider)
    original = (
        "Applicant Asha Mehta, phone 9876543210, Aadhaar 2345 6789 0124, "
        "PAN ABCPE1234F, GSTIN 27ABCPE1234F1ZB, Voter ID ABC1234567, "
        "Passport N1234567, address: 42 Fictional Lane, Pune; "
        "account number 123456789012."
    )
    result = service.scan(original)
    sanitized = str(result["sanitized_text"])
    completion = service.complete(UUID(str(result["request_id"])))

    sensitive_values = (
        "Asha Mehta",
        "9876543210",
        "2345 6789 0124",
        "ABCPE1234F",
        "27ABCPE1234F1ZB",
        "ABC1234567",
        "N1234567",
        "42 Fictional Lane, Pune",
        "123456789012",
    )
    assert provider.received == sanitized
    assert "[PERSON_1]" in provider.received
    assert "[PHONE_1]" in provider.received
    assert "[AADHAAR_1]" in provider.received
    assert "[PAN_1]" in provider.received
    assert "[GSTIN_1]" in provider.received
    assert "[VOTER_ID_1]" in provider.received
    assert "[PASSPORT_1]" in provider.received
    assert "[ADDRESS_1]" in provider.received
    assert "[ACCOUNT_NUMBER_1]" in provider.received
    assert all(value not in provider.received for value in sensitive_values)
    assert all(value not in str(completion["response"]) for value in sensitive_values)
    assert all(value not in str(event) for event in store.get_audit_logs() for value in sensitive_values)
    completion_log = next(
        event for event in store.get_audit_logs() if event["event"] == "completion"
    )
    assert completion_log["provider"] == "test"
    assert completion_log["model"] == "fictional-test-model"
    assert completion_log["created_at"]
    assert store.get_sanitized_text(UUID(str(result["request_id"]))) == sanitized
    raw_database = settings.database_path.read_bytes()
    assert all(value.encode("utf-8") not in raw_database for value in sensitive_values)
    assert store.get_mappings(UUID(str(result["request_id"])))[
        "[PERSON_1]"
    ] == "Asha Mehta"


def test_completion_includes_locally_masked_response_for_dashboard_display(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)
    detector = PIIDetector(settings)

    class PIIReturningProvider:
        name = "test"
        model = "fictional-test-model"

        def complete(self, _: str) -> str:
            return "Name: Asha Mehta; phone: 9876543210; PAN: ABCPE1234F"

    service = PrivacyService(detector, store, PIIReturningProvider())
    scan = service.scan("Summarize this fictional loan application.")
    completion = service.complete(UUID(str(scan["request_id"])))

    assert completion["response"] == (
        "Name: Asha Mehta; phone: 9876543210; PAN: ABCPE1234F"
    )
    display_response = str(completion["display_response"])
    assert "[PERSON_1]" in display_response
    assert "[PHONE_1]" in display_response
    assert "[PAN_1]" in display_response
    assert all(
        sensitive_value not in display_response
        for sensitive_value in ("Asha Mehta", "9876543210", "ABCPE1234F")
    )


def test_reidentification_requires_explicit_authorization(tmp_path: Path) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)
    service = PrivacyService(PIIDetector(settings), store, MockProvider())
    scan = service.scan("Applicant: Asha Mehta; phone 9876543210.")

    with pytest.raises(PermissionError):
        service.reidentify(
            UUID(str(scan["request_id"])),
            "[PERSON_1] [PHONE_1]",
            authorized=False,
        )

    assert not any(
        event["event"] == "reidentification"
        for event in store.get_audit_logs()
    )


def test_authorized_restoration_handles_order_repeats_unknown_and_dropped_placeholders(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)

    class CapturingProvider:
        name = "test"
        model = "fictional-test-model"

        def __init__(self) -> None:
            self.received: list[str] = []

        def complete(self, sanitized_text: str) -> str:
            self.received.append(sanitized_text)
            return (
                "For [EMAIL_1], tell [PERSON_1] to call [PHONE_1]. "
                "The number [PHONE_1] is repeated. Unknown [UNKNOWN_1], "
                "malformed [PHONE_X] and [phone_1]."
            )

    provider = CapturingProvider()
    service = PrivacyService(PIIDetector(settings), store, provider)
    scan = service.scan(
        "Applicant: Asha Mehta; phone 9876543210; email asha@example.invalid; "
        "Aadhaar 2345 6789 0124."
    )
    request_id = UUID(str(scan["request_id"]))
    sanitized = str(scan["sanitized_text"])
    completion = service.complete(request_id)
    raw_response = str(completion["response"])
    provider_call_count = len(provider.received)
    assert provider.received == [sanitized]

    restoration = service.reidentify(request_id, raw_response, authorized=True)

    assert restoration["response"] == (
        "For asha@example.invalid, tell Asha Mehta to call 9876543210. "
        "The number 9876543210 is repeated. Unknown [UNKNOWN_1], "
        "malformed [PHONE_X] and [phone_1]."
    )
    assert restoration["restored_count"] == 4
    assert "2345 6789 0124" not in str(restoration["response"])
    assert len(provider.received) == provider_call_count
    assert provider.received == [sanitized]

    audit = store.get_audit_logs()
    restoration_event = next(event for event in audit if event["event"] == "reidentification")
    assert restoration_event["entity_types"] == ["EMAIL", "PERSON", "PHONE"]
    assert restoration_event["entity_count"] == 4
    assert all(
        value not in str(event)
        for event in audit
        for value in ("Asha Mehta", "9876543210", "asha@example.invalid", "2345 6789 0124")
    )


def test_api_scan_completion_and_audit_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACYSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PRESIDIO_ENABLED", "false")
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "test-api-key")
    get_service.cache_clear()

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/scan",
                json={"text": "Please call 9876543210."},
                headers={"X-API-Key": "test-api-key"},
            )
            assert response.status_code == 200
            scan_result = response.json()
            assert "9876543210" not in scan_result["sanitized_text"]
            assert scan_result["validation"]["invalid_count"] == 0
            assert "fields" in scan_result["validation"]

            completion = await client.post(
                "/api/complete",
                json={"request_id": scan_result["request_id"]},
                headers={"X-API-Key": "test-api-key"},
            )
            assert completion.status_code == 200
            assert "[PHONE_1]" in completion.json()["response"]
            assert "9876543210" not in completion.json()["response"]

            denied = await client.post(
                "/api/reidentify",
                json={
                    "request_id": scan_result["request_id"],
                    "raw_response": completion.json()["response"],
                    "authorized": False,
                },
                headers={"X-API-Key": "test-api-key"},
            )
            assert denied.status_code == 403

            restored = await client.post(
                "/api/reidentify",
                json={
                    "request_id": scan_result["request_id"],
                    "raw_response": completion.json()["response"],
                    "authorized": True,
                },
                headers={"X-API-Key": "test-api-key"},
            )
            assert restored.status_code == 200
            assert "9876543210" in restored.json()["response"]
            assert restored.json()["restored_count"] == 1

            audit = (
                await client.get("/api/audit", headers={"X-API-Key": "test-api-key"})
            ).json()["logs"]
            assert [item["event"] for item in audit] == [
                "reidentification",
                "completion",
                "scan",
            ]
            assert audit[1]["provider"] == "mock"
            assert audit[1]["model"] == "local-mock"
            assert audit[0]["model"] is None
            metrics = await client.get(
                "/api/metrics",
                headers={"X-API-Key": "test-api-key"},
            )
            assert metrics.json()["entities_masked"] == 1
            evaluation = await client.get(
                "/api/evaluation",
                headers={"X-API-Key": "test-api-key"},
            )
            assert evaluation.status_code == 200
            assert evaluation.json()["document_count"] == 50
            assert evaluation.json()["privacy_leakage_count"] == 0
            assert "Aarav Nair" not in evaluation.text

    try:
        asyncio.run(exercise_api())
    finally:
        get_service.cache_clear()


def test_end_to_end_api_masks_stores_completes_and_authorized_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    store = MappingStore(settings)

    class CapturingProvider:
        name = "mock-e2e"
        model = "fictional-local-model"

        def __init__(self) -> None:
            self.received: list[str] = []

        def complete(self, sanitized_text: str) -> str:
            self.received.append(sanitized_text)
            return (
                "Reviewed [PERSON_1], [PHONE_1], [AADHAAR_1], [PAN_1], "
                "[GSTIN_1], [VOTER_ID_1], [PASSPORT_1], [ADDRESS_1], "
                "[ACCOUNT_NUMBER_1]. Salary INR 85,000; loan INR 5,00,000."
            )

    provider = CapturingProvider()
    service = PrivacyService(PIIDetector(settings), store, provider)
    monkeypatch.setattr("app.backend.api.get_service", lambda: service)
    original = (
        "Applicant: Asha Mehta; phone +91 98765 43210; Aadhaar 2345 6789 0124; "
        "PAN ABCPE1234F; GSTIN: 27ABCPE1234F1ZB; Voter ID: ABC1234567; "
        "Passport No: N1234567; address: 42 Fictional Lane, Pune; "
        "account number: 123456789012; salary INR 85,000; loan INR 5,00,000."
    )
    expected_sensitive_values = (
        "Asha Mehta",
        "98765 43210",
        "2345 6789 0124",
        "ABCPE1234F",
        "27ABCPE1234F1ZB",
        "ABC1234567",
        "N1234567",
        "42 Fictional Lane, Pune",
        "123456789012",
    )

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": "fictional-e2e-key"}
            monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "fictional-e2e-key")
            scan_response = await client.post(
                "/api/scan",
                json={"text": original},
                headers=headers,
            )
            assert scan_response.status_code == 200
            scan = scan_response.json()
            sanitized = scan["sanitized_text"]
            for placeholder in (
                "[PERSON_1]",
                "[PHONE_1]",
                "[AADHAAR_1]",
                "[PAN_1]",
                "[GSTIN_1]",
                "[VOTER_ID_1]",
                "[PASSPORT_1]",
                "[ADDRESS_1]",
                "[ACCOUNT_NUMBER_1]",
            ):
                assert placeholder in sanitized
            assert "salary INR 85,000" in sanitized
            assert "loan INR 5,00,000" in sanitized
            assert all(value not in sanitized for value in expected_sensitive_values)

            request_id = scan["request_id"]
            completion_response = await client.post(
                "/api/complete",
                json={"request_id": request_id},
                headers=headers,
            )
            assert completion_response.status_code == 200
            completion_payload = completion_response.json()
            raw_ai_response = completion_payload["response"]
            display_response = completion_payload["display_response"]
            assert provider.received == [sanitized]
            assert all(value not in provider.received[0] for value in expected_sensitive_values)
            assert all(value not in raw_ai_response for value in expected_sensitive_values)
            assert all(value not in display_response for value in expected_sensitive_values)

            denied_restoration = await client.post(
                "/api/reidentify",
                json={
                    "request_id": request_id,
                    "raw_response": raw_ai_response,
                    "authorized": False,
                },
                headers=headers,
            )
            assert denied_restoration.status_code == 403
            restoration = await client.post(
                "/api/reidentify",
                json={
                    "request_id": request_id,
                    "raw_response": raw_ai_response,
                    "authorized": True,
                },
                headers=headers,
            )
            assert restoration.status_code == 200
            restored_response = restoration.json()["response"]
            assert "Asha Mehta" in restored_response
            assert "98765 43210" in restored_response
            assert "123456789012" in restored_response
            assert provider.received == [sanitized]

            audit_response = await client.get("/api/audit", headers=headers)
            assert audit_response.status_code == 200
            audit_events = audit_response.json()["logs"]
            completion_event = next(
                event for event in audit_events if event["event"] == "completion"
            )
            assert completion_event["provider"] == provider.name
            assert completion_event["model"] == provider.model
            assert all(
                value not in str(audit_events)
                for value in (*expected_sensitive_values, "fictional-e2e-key")
            )
            metrics_response = await client.get("/api/metrics", headers=headers)
            assert metrics_response.json()["scans"] == 1
            assert metrics_response.json()["entities_masked"] == 9

            unauthorized = await client.post(
                "/api/scan",
                json={"text": original},
                headers={"X-API-Key": "invalid-key"},
            )
            assert unauthorized.status_code == 401
            assert "Asha Mehta" not in unauthorized.text
            assert "invalid-key" not in unauthorized.text

    asyncio.run(exercise_api())
    request_id = UUID(
        next(
            event["request_id"]
            for event in store.get_audit_logs()
            if event["event"] == "scan"
        )
    )
    raw_database = settings.database_path.read_bytes()
    assert all(value.encode("utf-8") not in raw_database for value in expected_sensitive_values)
    mappings = store.get_mappings(request_id)
    assert mappings["[PERSON_1]"] == "Asha Mehta"
    assert mappings["[ACCOUNT_NUMBER_1]"] == "123456789012"


def test_api_returns_safe_validation_errors_while_masking_invalid_pii(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path, presidio_enabled=False)
    service = PrivacyService(PIIDetector(settings), MappingStore(settings), MockProvider())
    monkeypatch.setattr("app.backend.api.get_service", lambda: service)
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "fictional-validation-key")
    text = "Mobile: 12345; Aadhaar: 2345 6789 0123; Email: invalid@"

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/scan",
                json={"text": text},
                headers={"X-API-Key": "fictional-validation-key"},
            )

        assert response.status_code == 200
        result = response.json()
        validation = result["validation"]
        assert validation["invalid_count"] == 3
        assert all(field["status"] == "invalid" for field in validation["fields"])
        assert "12345" not in response.text
        assert "2345 6789 0123" not in response.text
        assert "invalid@" not in response.text
        assert "12345" not in result["sanitized_text"]
        assert "2345 6789 0123" not in result["sanitized_text"]
        assert "invalid@" not in result["sanitized_text"]

    asyncio.run(exercise_api())


@pytest.mark.parametrize(
    ("method", "path", "payload", "sensitive_value"),
    [
        ("POST", "/api/scan", {"text": "Asha Mehta 9876543210"}, "Asha Mehta"),
        ("POST", "/api/complete", {"request_id": str(uuid4())}, None),
        (
            "POST",
            "/api/reidentify",
            {
                "request_id": str(uuid4()),
                "raw_response": "Private response 9876543210",
                "authorized": True,
            },
            "9876543210",
        ),
        ("GET", "/api/audit", None, None),
        ("GET", "/api/metrics", None, None),
        ("GET", "/api/evaluation", None, None),
    ],
)
@pytest.mark.parametrize("api_key", [None, "invalid-api-key"], ids=["missing", "invalid"])
def test_sensitive_api_routes_reject_missing_or_invalid_api_key_before_processing(
    method: str,
    path: str,
    payload: dict[str, object] | None,
    sensitive_value: str | None,
    api_key: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "expected-test-api-key")

    def unexpected_service_access() -> PrivacyService:
        raise AssertionError("Unauthorized request reached the application service.")

    monkeypatch.setattr("app.backend.api.get_service", unexpected_service_access)

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        headers = {"X-API-Key": api_key} if api_key is not None else {}
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.request(method, path, json=payload, headers=headers)
        assert response.status_code == 401
        assert "expected-test-api-key" not in response.text
        if sensitive_value is not None:
            assert sensitive_value not in response.text

    asyncio.run(exercise_api())


def test_sensitive_api_routes_fail_closed_when_server_key_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("app.config.PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "")

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/scan",
                json={"text": "Asha Mehta 9876543210"},
            )
        assert response.status_code == 503
        assert "Asha Mehta" not in response.text

    asyncio.run(exercise_api())


def test_api_authentication_configuration_error_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_settings() -> Settings:
        raise ValueError("fictional-secret-detail")

    monkeypatch.setattr("app.backend.api.Settings.from_env", broken_settings)

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/scan",
                json={"text": "Asha Mehta 9876543210"},
            )
        assert response.status_code == 503
        assert "fictional-secret-detail" not in response.text
        assert "Asha Mehta" not in response.text
        assert "9876543210" not in response.text

    asyncio.run(exercise_api())


@pytest.mark.parametrize(
    ("path", "payload", "private_marker"),
    [
        (
            "/api/scan",
            {"text": "PRIVATE-SCAN-MARKER " + ("fictional " * 2_500)},
            "PRIVATE-SCAN-MARKER",
        ),
        (
            "/api/reidentify",
            {
                "request_id": str(uuid4()),
                "raw_response": "PRIVATE-RESPONSE-MARKER " + ("fictional " * 6_000),
                "authorized": True,
            },
            "PRIVATE-RESPONSE-MARKER",
        ),
    ],
)
def test_validation_errors_do_not_echo_submitted_private_content(
    path: str,
    payload: dict[str, object],
    private_marker: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", "expected-test-api-key")

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                path,
                json=payload,
                headers={"X-API-Key": "expected-test-api-key"},
            )
        assert response.status_code == 422
        assert private_marker not in response.text
        assert "expected-test-api-key" not in response.text

    asyncio.run(exercise_api())


def _settings(data_dir: Path, presidio_enabled: bool) -> Settings:
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "privacyshield.db",
        encryption_key=Fernet.generate_key().decode("ascii"),
        llm_provider="mock",
        llm_api_key=None,
        llm_base_url="https://api.openai.com/v1",
        llm_model="test",
        llm_timeout_seconds=1,
        presidio_enabled=presidio_enabled,
        presidio_model="en_core_web_sm",
        api_key=None,
    )
