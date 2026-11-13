"""Detection, masking, and privacy-leakage measurements for the synthetic corpus."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from app.privacy.detector import Finding
from app.privacy.masking import mask_text
from app.services.llm import MockProvider
from app.evaluation.synthetic_dataset import SyntheticDocument, load_synthetic_dataset

Span = tuple[str, int, int]


class Detector(Protocol):
    def detect(self, text: str) -> list[Finding]: ...


@dataclass(frozen=True)
class EvaluationReport:
    document_count: int
    positive_document_count: int
    negative_document_count: int
    labeled_entity_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    correctly_masked_entities: int
    placeholder_masking_accuracy: float
    sanitized_payload_leakage_count: int
    provider_input_leakage_count: int
    raw_ai_response_leakage_count: int
    privacy_leakage_count: int
    privacy_leakage_rate: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


def _span_for_finding(finding: Finding) -> Span:
    return finding.entity_type, finding.start, finding.end


def score_spans(
    expected: list[Span] | tuple[Span, ...],
    predicted: list[Finding] | tuple[Finding, ...],
) -> tuple[int, int, int]:
    """Return exact typed-span true-positive, false-positive, and false-negative counts."""
    expected_set = set(expected)
    predicted_set = {_span_for_finding(finding) for finding in predicted}
    return (
        len(expected_set & predicted_set),
        len(predicted_set - expected_set),
        len(expected_set - predicted_set),
    )


def evaluate_dataset(
    detector: Detector,
    documents: tuple[SyntheticDocument, ...] | None = None,
) -> EvaluationReport:
    corpus = documents if documents is not None else load_synthetic_dataset()
    provider = MockProvider()
    true_positives = false_positives = false_negatives = 0
    labeled_entity_count = correctly_masked_entities = 0
    sanitized_leakage = provider_input_leakage = raw_response_leakage = 0
    positive_document_count = 0

    for document in corpus:
        expected = [
            (entity.entity_type, entity.start, entity.end) for entity in document.entities
        ]
        findings = detector.detect(document.text)
        tp, fp, fn = score_spans(expected, findings)
        true_positives += tp
        false_positives += fp
        false_negatives += fn
        labeled_entity_count += len(expected)
        positive_document_count += bool(expected)

        masked = mask_text(document.text, findings)
        predicted_spans = {_span_for_finding(finding) for finding in findings}
        for entity in document.entities:
            if (entity.entity_type, entity.start, entity.end) in predicted_spans:
                placeholder = next(
                    (
                        mapping.placeholder
                        for mapping in masked.mappings
                        if mapping.entity_type == entity.entity_type
                        and mapping.original_value.casefold() == entity.value.casefold()
                    ),
                    None,
                )
                if placeholder is not None and placeholder in masked.sanitized_text:
                    correctly_masked_entities += 1
            if entity.value in masked.sanitized_text:
                sanitized_leakage += 1

        provider_input = masked.sanitized_text
        raw_response = provider.complete(provider_input)
        for entity in document.entities:
            provider_input_leakage += entity.value in provider_input
            raw_response_leakage += entity.value in raw_response

    precision = true_positives / (true_positives + false_positives) if (
        true_positives + false_positives
    ) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (
        true_positives + false_negatives
    ) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    privacy_leakage_count = provider_input_leakage + raw_response_leakage
    leakage_surfaces = 2 * labeled_entity_count

    return EvaluationReport(
        document_count=len(corpus),
        positive_document_count=positive_document_count,
        negative_document_count=len(corpus) - positive_document_count,
        labeled_entity_count=labeled_entity_count,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        correctly_masked_entities=correctly_masked_entities,
        placeholder_masking_accuracy=round(
            correctly_masked_entities / labeled_entity_count if labeled_entity_count else 0.0,
            4,
        ),
        sanitized_payload_leakage_count=sanitized_leakage,
        provider_input_leakage_count=provider_input_leakage,
        raw_ai_response_leakage_count=raw_response_leakage,
        privacy_leakage_count=privacy_leakage_count,
        privacy_leakage_rate=round(
            privacy_leakage_count / leakage_surfaces if leakage_surfaces else 0.0,
            4,
        ),
    )
