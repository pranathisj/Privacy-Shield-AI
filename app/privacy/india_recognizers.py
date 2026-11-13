"""Presidio recognizers for context-labeled Indian identity numbers."""

from __future__ import annotations

import re
from typing import Callable, Pattern as RegexPattern

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult

from app.privacy.india_identifiers import (
    is_valid_aadhaar,
    is_valid_gstin,
    is_valid_pan,
)


class ContextualIdentifierRecognizer(PatternRecognizer):
    """Apply Presidio patterns only when a nearby field label supports the match."""

    def __init__(
        self,
        entity_type: str,
        name: str,
        pattern: str,
        context: list[str],
        validator: Callable[[str], bool],
    ) -> None:
        super().__init__(
            supported_entity=entity_type,
            name=name,
            supported_language="en",
            patterns=[Pattern(name=f"{name}_pattern", regex=pattern, score=0.8)],
            context=context,
            country_code="IN",
        )
        self._context_pattern: RegexPattern[str] = re.compile(
            r"(?<!\w)(?:" + "|".join(re.escape(term) for term in context) + r")(?!\w)",
            re.IGNORECASE,
        )
        self._validator = validator

    def validate_result(self, pattern_text: str) -> bool:
        return self._validator(pattern_text)

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts=None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        if self.supported_entities[0] not in entities:
            return []

        supported_results = super().analyze(
            text,
            entities,
            nlp_artifacts=nlp_artifacts,
            regex_flags=regex_flags,
        )
        return [
            result
            for result in supported_results
            if self._has_preceding_context(text, result.start)
        ]

    def _has_preceding_context(self, text: str, start: int) -> bool:
        clause_start = max(
            text.rfind(separator, 0, start) for separator in (";", "\n", ".", "!")
        )
        context_start = max(clause_start + 1, start - 80)
        return self._context_pattern.search(text[context_start:start]) is not None


def build_india_recognizers() -> list[ContextualIdentifierRecognizer]:
    """Construct Presidio recognizers with format/checksum validation."""
    return [
        ContextualIdentifierRecognizer(
            "AADHAAR",
            "IndiaAadhaarRecognizer",
            r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)",
            ["aadhaar", "aadhar", "uid", "uidai"],
            is_valid_aadhaar,
        ),
        ContextualIdentifierRecognizer(
            "PAN",
            "IndiaPANRecognizer",
            r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])",
            ["pan", "pan card", "permanent account number"],
            is_valid_pan,
        ),
        ContextualIdentifierRecognizer(
            "GSTIN",
            "IndiaGSTINRecognizer",
            r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[A-Z0-9](?![A-Z0-9])",
            ["gstin", "gst", "goods and services tax"],
            is_valid_gstin,
        ),
        ContextualIdentifierRecognizer(
            "VOTER_ID",
            "IndiaVoterIDRecognizer",
            r"(?<![A-Z0-9])[A-Z]{3}\d{7}(?![A-Z0-9])",
            ["voter id", "voter identity", "epic"],
            lambda value: re.fullmatch(r"[A-Z]{3}\d{7}", value, re.IGNORECASE)
            is not None,
        ),
        ContextualIdentifierRecognizer(
            "PASSPORT",
            "IndiaPassportRecognizer",
            r"(?<![A-Z0-9])[A-Z]\d{7}(?![A-Z0-9])",
            ["passport"],
            lambda value: re.fullmatch(r"[A-Z]\d{7}", value, re.IGNORECASE) is not None,
        ),
    ]
