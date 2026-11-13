"""Orchestration for scanning, masking, safe completion, and reinsertion."""

from __future__ import annotations

import logging
import re
import time
from uuid import UUID, uuid4

from app.evaluation.metrics import evaluate_dataset
from app.privacy.detector import PIIDetector
from app.privacy.masking import mask_text
from app.services.llm import LLMProvider
from app.storage.database import MappingStore
from app.validation.input_validation import validate_text

logger = logging.getLogger(__name__)
MAX_INPUT_LENGTH = 20_000
MAX_AI_RESPONSE_LENGTH = 50_000
PLACEHOLDER_PATTERN = re.compile(r"\[([A-Z][A-Z0-9_]*)_\d+\]")


class PrivacyService:
    def __init__(self, detector: PIIDetector, store: MappingStore, provider: LLMProvider) -> None:
        self._detector = detector
        self._store = store
        self._provider = provider

    def scan(self, text: str) -> dict[str, object]:
        if not text.strip():
            raise ValueError("Enter text to scan.")
        if len(text) > MAX_INPUT_LENGTH:
            raise ValueError(f"Input exceeds the {MAX_INPUT_LENGTH:,}-character limit.")

        started = time.perf_counter()
        findings = self._detector.detect(text)
        validation = validate_text(text, findings)
        masked = mask_text(text, findings)
        request_id = uuid4()
        duration_ms = (time.perf_counter() - started) * 1000
        self._store.save_scan(request_id, masked.sanitized_text, masked.mappings, duration_ms)
        entity_types = sorted({finding.entity_type for finding in findings})
        return {
            "request_id": str(request_id),
            "sanitized_text": masked.sanitized_text,
            "entity_count": len(findings),
            "entity_types": entity_types,
            "duration_ms": round(duration_ms, 2),
            "validation": validation.to_dict(),
        }

    def complete(self, request_id: UUID) -> dict[str, object]:
        sanitized_text = self._store.get_sanitized_text(request_id)
        entity_types = sorted(set(PLACEHOLDER_PATTERN.findall(sanitized_text)))
        started = time.perf_counter()
        try:
            provider_response = self._provider.complete(sanitized_text)
        except Exception:
            self._store.record_completion(
                request_id,
                entity_types,
                self._provider.name,
                self._provider.model,
                (time.perf_counter() - started) * 1000,
                False,
            )
            logger.error("LLM completion failed for request %s", request_id)
            raise RuntimeError("AI completion failed.") from None

        self._store.record_completion(
            request_id,
            entity_types,
            self._provider.name,
            self._provider.model,
            (time.perf_counter() - started) * 1000,
            True,
        )
        display_findings = self._detector.detect(provider_response)
        display_response = mask_text(provider_response, display_findings).sanitized_text
        return {
            "response": provider_response,
            "display_response": display_response,
            "provider": self._provider.name,
        }

    def reidentify(
        self,
        request_id: UUID,
        raw_response: str,
        *,
        authorized: bool,
    ) -> dict[str, object]:
        if not authorized:
            raise PermissionError("Explicit authorization is required to restore placeholders.")
        if len(raw_response) > MAX_AI_RESPONSE_LENGTH:
            raise ValueError(
                f"AI response exceeds the {MAX_AI_RESPONSE_LENGTH:,}-character limit."
            )

        mapping = self._store.get_mappings(request_id)
        restored_count = 0
        restored_types: set[str] = set()

        def restore(match: re.Match[str]) -> str:
            nonlocal restored_count
            placeholder = match.group(0)
            original_value = mapping.get(placeholder)
            if original_value is None:
                return placeholder
            restored_count += 1
            restored_types.add(match.group(1))
            return original_value

        restored_response = PLACEHOLDER_PATTERN.sub(restore, raw_response)
        self._store.record_reidentification(
            request_id,
            sorted(restored_types),
            restored_count,
        )
        return {
            "response": restored_response,
            "restored_count": restored_count,
        }

    def get_audit_logs(self, limit: int = 50) -> list[dict[str, object]]:
        return self._store.get_audit_logs(limit)

    def get_metrics(self) -> dict[str, int]:
        return self._store.get_metrics()

    def evaluate_synthetic_dataset(self) -> dict[str, int | float]:
        return evaluate_dataset(self._detector).to_dict()
