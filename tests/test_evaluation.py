from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from app.config import Settings
from app.evaluation import (
    SyntheticDocument,
    SyntheticEntity,
    evaluate_dataset,
    load_synthetic_dataset,
    score_spans,
)
from app.privacy.detector import Finding, PIIDetector
from app.privacy.india_identifiers import is_valid_aadhaar, is_valid_gstin


def _detector(tmp_path: Path) -> PIIDetector:
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "privacyshield.db",
        encryption_key=Fernet.generate_key().decode("ascii"),
        llm_provider="mock",
        llm_api_key=None,
        llm_base_url="https://api.openai.com/v1",
        llm_model="test",
        llm_timeout_seconds=1,
        presidio_enabled=False,
        presidio_model="en_core_web_sm",
        api_key=None,
    )
    return PIIDetector(settings)


def test_synthetic_dataset_has_fifty_labeled_and_negative_documents() -> None:
    documents = load_synthetic_dataset()
    assert len(documents) == 50
    assert sum(bool(document.entities) for document in documents) == 45
    assert sum(not document.entities for document in documents) == 5

    entity_types = {entity.entity_type for document in documents for entity in document.entities}
    assert entity_types == {
        "PERSON",
        "PHONE",
        "EMAIL",
        "AADHAAR",
        "PAN",
        "GSTIN",
        "VOTER_ID",
        "PASSPORT",
        "ADDRESS",
        "ACCOUNT_NUMBER",
    }
    assert sum(len(document.entities) for document in documents) == 450
    assert all(
        is_valid_aadhaar(entity.value)
        for document in documents
        for entity in document.entities
        if entity.entity_type == "AADHAAR"
    )
    assert all(
        is_valid_gstin(entity.value)
        for document in documents
        for entity in document.entities
        if entity.entity_type == "GSTIN"
    )
    assert any("Namaste" in document.text or "loan chahiye" in document.text for document in documents)
    assert all("example.invalid" in document.text for document in documents if document.entities)


def test_synthetic_evaluation_reports_measured_detection_masking_and_leakage(
    tmp_path: Path,
) -> None:
    report = evaluate_dataset(_detector(tmp_path))

    assert report.document_count == 50
    assert report.positive_document_count == 45
    assert report.negative_document_count == 5
    assert report.labeled_entity_count == 450
    assert report.true_positives == 450
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1 == 1.0
    assert report.correctly_masked_entities == 450
    assert report.placeholder_masking_accuracy == 1.0
    assert report.sanitized_payload_leakage_count == 0
    assert report.provider_input_leakage_count == 0
    assert report.raw_ai_response_leakage_count == 0
    assert report.privacy_leakage_count == 0
    assert "Aarav Nair" not in str(report.to_dict())


def test_span_scoring_counts_true_positives_false_positives_and_false_negatives() -> None:
    expected = [("PERSON", 0, 10), ("PHONE", 11, 21)]
    predicted = [
        Finding("PHONE", 11, 21, 0.95, "test"),
        Finding("EMAIL", 0, 10, 0.95, "test"),
    ]

    assert score_spans(expected, predicted) == (1, 1, 1)


def test_negative_examples_expose_detector_false_positives_and_false_negatives(
    tmp_path: Path,
) -> None:
    detector = _detector(tmp_path)
    false_positive_text = (
        "Fictional voucher reference 9876543210 and invoice 123456789012 "
        "are internal codes, not personal identifiers."
    )
    false_positive_findings = detector.detect(false_positive_text)
    assert score_spans([], false_positive_findings) == (0, 0, 0)

    false_negative_text = "Aarav Nair"
    expected_name = [("PERSON", 0, len(false_negative_text))]
    assert score_spans(expected_name, detector.detect(false_negative_text)) == (0, 0, 1)


def test_undetected_pii_is_counted_as_leakage_across_provider_boundaries() -> None:
    text = "Aadhaar 2345 6700 0003"
    start = text.index("2345")
    document = SyntheticDocument(
        "false-negative",
        text,
        (SyntheticEntity("AADHAAR", "2345 6700 0003", start, len(text)),),
    )

    class EmptyDetector:
        def detect(self, _: str) -> list[Finding]:
            return []

    report = evaluate_dataset(EmptyDetector(), (document,))

    assert report.false_negatives == 1
    assert report.correctly_masked_entities == 0
    assert report.sanitized_payload_leakage_count == 1
    assert report.provider_input_leakage_count == 1
    assert report.raw_ai_response_leakage_count == 1
    assert report.privacy_leakage_count == 2
    assert report.privacy_leakage_rate == 1.0


def test_financial_amounts_are_not_counted_as_pii_false_positives(tmp_path: Path) -> None:
    text = "Monthly salary INR 85,000; requested loan INR 5,00,000; EMI INR 18,500."
    assert _detector(tmp_path).detect(text) == []
