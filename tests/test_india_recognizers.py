from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.privacy.detector import PIIDetector
from app.privacy.india_recognizers import build_india_recognizers
from app.privacy.masking import mask_text
from app.services.llm import MockProvider
from app.services.privacy import PrivacyService
from app.storage.database import MappingStore


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
        api_key="fictional-backend-key",
    )

_VALID_IDENTIFIERS = (
    ("AADHAAR", "Aadhaar", "2345 6700 0019"),
    ("PAN", "PAN", "ABCPE1234F"),
    ("GSTIN", "GSTIN", "27ABCPE1234F1ZB"),
    ("VOTER_ID", "Voter ID", "ABC1234567"),
    ("PASSPORT", "Passport", "N1234567"),
)


@pytest.mark.parametrize(("entity_type", "label", "value"), _VALID_IDENTIFIERS)
def test_presidio_custom_recognizers_detect_contextual_fictional_identifiers(
    entity_type: str,
    label: str,
    value: str,
) -> None:
    recognizer = next(
        recognizer
        for recognizer in build_india_recognizers()
        if recognizer.supported_entities == [entity_type]
    )

    results = recognizer.analyze(
        f"Customer {label}: {value}.",
        entities=[entity_type],
    )

    assert len(results) == 1
    result = results[0]
    assert result.entity_type == entity_type
    assert f"Customer {label}: {value}."[result.start : result.end] == value
    assert result.score > 0.0


@pytest.mark.parametrize(
    ("entity_type", "label", "value"),
    [
        ("AADHAAR", "Aadhaar", "2345 6700 0018"),
        ("PAN", "PAN", "ABCDE1234F"),
        ("GSTIN", "GSTIN", "27ABCPE1234F1Z0"),
        ("VOTER_ID", "Voter ID", "AB1234567"),
        ("PASSPORT", "Passport", "N123456"),
    ],
)
def test_presidio_custom_recognizers_reject_invalid_identifier_formats_or_checksums(
    entity_type: str,
    label: str,
    value: str,
) -> None:
    recognizer = next(
        recognizer
        for recognizer in build_india_recognizers()
        if recognizer.supported_entities == [entity_type]
    )

    results = recognizer.analyze(
        f"Customer {label}: {value}.",
        entities=[entity_type],
    )

    assert results == []


@pytest.mark.parametrize(("entity_type", "label", "value"), _VALID_IDENTIFIERS)
def test_custom_recognizers_require_identifier_context(
    entity_type: str,
    label: str,
    value: str,
) -> None:
    recognizer = next(
        recognizer
        for recognizer in build_india_recognizers()
        if recognizer.supported_entities == [entity_type]
    )

    assert recognizer.analyze(f"Reference: {value}.", entities=[entity_type]) == []


@pytest.mark.skipif(
    importlib.util.find_spec("en_core_web_sm") is None,
    reason="The configured local spaCy model is not installed.",
)
def test_invalid_context_labeled_values_remain_masked_with_presidio_enabled() -> None:
    text = (
        "Aadhaar: 2345 6700 0018; PAN: ABCDE1234F; "
        "GSTIN: 27ABCPE1234F1Z0; Voter ID: AB1234567; Passport: N123456."
    )
    detector = PIIDetector(_settings(Path("unused"), presidio_enabled=True))

    findings = detector.detect(text)
    masked = mask_text(text, findings)

    for entity_type, _, value in (
        ("AADHAAR", "Aadhaar", "2345 6700 0018"),
        ("PAN", "PAN", "ABCDE1234F"),
        ("GSTIN", "GSTIN", "27ABCPE1234F1Z0"),
        ("VOTER_ID", "Voter ID", "AB1234567"),
        ("PASSPORT", "Passport", "N123456"),
    ):
        assert value not in masked.sanitized_text
        assert any(
            finding.entity_type == entity_type
            and finding.source == "india_pattern"
            for finding in findings
        )


@pytest.mark.skipif(
    importlib.util.find_spec("en_core_web_sm") is None,
    reason="The configured local spaCy model is not installed.",
)
def test_presidio_custom_identifiers_use_typed_placeholders_before_provider(
    tmp_path: Path,
) -> None:
    text = (
        "Aadhaar: 2345 6700 0019; PAN: ABCPE1234F; "
        "GSTIN: 27ABCPE1234F1ZB; Voter ID: ABC1234567; "
        "Passport: N1234567."
    )
    detector = PIIDetector(_settings(tmp_path, presidio_enabled=True))

    findings = detector.detect(text)
    masked = mask_text(text, findings)

    assert {
        (finding.entity_type, finding.source)
        for finding in findings
        if finding.entity_type in {"AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT"}
    } == {
        (entity_type, "presidio_india")
        for entity_type, _, _ in _VALID_IDENTIFIERS
    }
    for entity_type, _, value in _VALID_IDENTIFIERS:
        assert value not in masked.sanitized_text
        assert f"[{entity_type}_1]" in masked.sanitized_text


@pytest.mark.skipif(
    importlib.util.find_spec("en_core_web_sm") is None,
    reason="The configured local spaCy model is not installed.",
)
def test_custom_recognized_identifiers_are_masked_before_provider_call(tmp_path: Path) -> None:
    settings = _settings(tmp_path, presidio_enabled=True)

    class CapturingProvider:
        name = "test-provider"
        model = "fictional-test-model"

        def __init__(self) -> None:
            self.received = ""

        def complete(self, sanitized_text: str) -> str:
            self.received = sanitized_text
            return MockProvider().complete(sanitized_text)

    original = "; ".join(
        f"{label}: {value}" for _, label, value in _VALID_IDENTIFIERS
    )
    provider = CapturingProvider()
    service = PrivacyService(
        PIIDetector(settings),
        MappingStore(settings),
        provider,
    )

    scan = service.scan(original)
    completion = service.complete(UUID(str(scan["request_id"])))

    assert provider.received == scan["sanitized_text"]
    assert all(value not in provider.received for _, _, value in _VALID_IDENTIFIERS)
    assert all(value not in str(completion) for _, _, value in _VALID_IDENTIFIERS)
