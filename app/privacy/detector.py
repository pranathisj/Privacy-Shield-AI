"""PII detection using India-focused patterns and optional Presidio enrichment."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Pattern

from app.config import Settings

logger = logging.getLogger(__name__)

_PRESIDIO_ENTITY_TYPES = {
    "PERSON": "PERSON",
    "LOCATION": "ADDRESS",
    "LOC": "ADDRESS",
    "GPE": "ADDRESS",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "IBAN_CODE": "ACCOUNT_NUMBER",
    "CREDIT_CARD": "CREDIT_CARD",
    "DATE_TIME": "DATE_TIME",
}


@dataclass(frozen=True)
class Finding:
    entity_type: str
    start: int
    end: int
    score: float
    source: str


@dataclass(frozen=True)
class PatternRule:
    entity_type: str
    pattern: Pattern[str]
    score: float


def _compile_rules() -> list[PatternRule]:
    return [
        PatternRule(
            "AADHAAR",
            re.compile(
                r"\b(?:aadhaar|aadhar|uid(?:ai)?)(?:\s*(?:card|id|no\.?|number))?"
                r"\s*[:#=-]?\s*([0-9][0-9 -]{0,22})",
                re.IGNORECASE,
            ),
            0.99,
        ),
        PatternRule(
            "PAN",
            re.compile(
                r"\b(?:pan(?:\s*(?:card|no\.?|number))?|"
                r"permanent\s+account\s+number)\s*[:#=-]?\s*"
                r"([A-Z0-9]{1,16})",
                re.IGNORECASE,
            ),
            0.98,
        ),
        PatternRule(
            "GSTIN",
            re.compile(
                r"\b(?:gstin(?:\s*(?:id|no\.?|number))?|"
                r"gst\s*(?:identification\s*)?(?:no\.?|number))"
                r"\s*[:#=-]?\s*([A-Z0-9]{1,20})",
                re.IGNORECASE,
            ),
            0.97,
        ),
        PatternRule(
            "VOTER_ID",
            re.compile(
                r"\b(?:voter(?:\s*(?:id|identity)(?:\s*card)?)?|"
                r"epic(?:\s*(?:no\.?|number))?)\s*[:#=-]?\s*([A-Z0-9]{1,16})",
                re.IGNORECASE,
            ),
            0.96,
        ),
        PatternRule(
            "PASSPORT",
            re.compile(
                r"\bpassport(?:\s*(?:no\.?|number))?\s*[:#=-]?\s*([A-Z0-9]{1,16})",
                re.IGNORECASE,
            ),
            0.96,
        ),
        PatternRule(
            "PHONE",
            re.compile(
                r"\b(?:phone|mobile|contact(?:\s*(?:no\.?|number))?|"
                r"whatsapp|call(?:\s+at)?|telephone|tel|number)"
                r"\s*(?:no\.?|number)?\s*[:#=-]?\s*"
                r"(?=([+()\d -]{1,32}\d))([+()\d -]{1,32})",
                re.IGNORECASE,
            ),
            0.95,
        ),
        PatternRule(
            "EMAIL",
            re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?!\w)", re.I),
            0.95,
        ),
        PatternRule(
            "EMAIL",
            re.compile(
                r"\b(?:email(?:\s+(?:address|id))?|e-mail(?:\s+(?:address|id))?)"
                r"\s*[:#=-]?\s*"
                r"([^\s,;\n]{1,80})",
                re.IGNORECASE,
            ),
            0.94,
        ),
        PatternRule(
            "UPI_ID",
            re.compile(r"(?<![\w.-])[A-Z0-9._-]{2,}@[A-Z][A-Z0-9.-]{1,}(?![\w.-])", re.I),
            0.91,
        ),
        PatternRule(
            "ACCOUNT_NUMBER",
            re.compile(
                r"(?:account(?:\s*(?:number|no\.?))?|a/c)\s*[:#-]?\s*(\d{9,18})",
                re.I,
            ),
            0.93,
        ),
        PatternRule(
            "PERSON",
            re.compile(
                r"(?i:\b(?:name|naam)\b)\s*(?:is\s*)?[:=-]?\s*"
                r"([^;,\n.!?]{1,80}?)(?=\s+(?:from|living\s+in|lives?\s+in|"
                r"resides?\s+in|based\s+in)\b|[;,\n.!?]|$)"
                r"|(?i:\b(?:customer\s+name|applicant(?:\s+name)?)\b)"
                r"(?:\s+(?:is\s+)?|[:=-]\s*)([^;,\n.!?]{1,80}?)"
                r"(?=\s+(?:from|living\s+in|lives?\s+in|resides?\s+in|based\s+in)"
                r"\b|[;,\n.!?]|$)"
                r"|(?i:\bcustomer)\s+(?:is\s+)([^;,\n.!?]{1,80}?)"
                r"(?=\s+(?:from|living\s+in|lives?\s+in|resides?\s+in|based\s+in)"
                r"\b|[;,\n.!?]|$)"
                r"|(?i:\bcustomer)\s*[:=-]\s*([^;,\n.!?]{1,80}?)"
                r"(?=\s+(?:from|living\s+in|lives?\s+in|resides?\s+in|based\s+in)"
                r"\b|[;,\n.!?]|$)"
            ),
            0.82,
        ),
        PatternRule(
            "ADDRESS",
            re.compile(
                r"\b(?:address|residing\s+at|resides?\s+at|lives?\s+at|pata)"
                r"\s*[:=-]?\s*"
                r"([^\n;.]{5,120})",
                re.I,
            ),
            0.78,
        ),
        PatternRule(
            "PIN_CODE",
            re.compile(
                r"\b(?:pin(?:\s*code)?|pincode|postal\s+code|zip(?:\s*code)?)"
                r"\s*[:#=-]?\s*(\d{1,10})",
                re.IGNORECASE,
            ),
            0.80,
        ),
        PatternRule(
            "DATE_OF_BIRTH",
            re.compile(
                r"\b(?:date\s+of\s+birth|dob)\s*[:#=-]?\s*"
                r"([A-Z0-9/.-]{1,20})",
                re.IGNORECASE,
            ),
            0.80,
        ),
    ]


class PIIDetector:
    """Detect common PII locally; use Presidio when its NLP model is available."""

    def __init__(self, settings: Settings) -> None:
        self._rules = _compile_rules()
        self._presidio = None
        if settings.presidio_enabled:
            self._presidio = self._create_presidio_analyzer(settings.presidio_model)

    @staticmethod
    def _create_presidio_analyzer(model_name: str):
        try:
            if not Path(model_name).exists() and find_spec(model_name) is None:
                logger.warning(
                    "Presidio model '%s' is not installed; India-focused local patterns remain active.",
                    model_name,
                )
                return None
        except (ImportError, ModuleNotFoundError, ValueError):
            logger.warning(
                "Presidio model '%s' is unavailable; India-focused local patterns remain active.",
                model_name,
            )
            return None

        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            from app.privacy.india_recognizers import build_india_recognizers

            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
            )
            nlp_engine = provider.create_engine()
            analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            for recognizer in build_india_recognizers():
                analyzer.registry.add_recognizer(recognizer)
            return analyzer
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            logger.warning(
                "Presidio NLP unavailable (%s); India-focused local patterns remain active.",
                exc,
            )
            return None

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                if rule.entity_type == "PERSON":
                    spans = [
                        match.span(index)
                        for index in range(1, (match.lastindex or 0) + 1)
                        if match.group(index)
                    ]
                    start, end = spans[0]
                else:
                    if rule.entity_type == "PHONE":
                        start, end = match.span(2)
                    elif match.lastindex:
                        start, end = match.span(1)
                    else:
                        start, end = match.span()
                while end > start and text[end - 1].isspace():
                    end -= 1
                value = text[start:end]
                findings.append(Finding(rule.entity_type, start, end, rule.score, "india_pattern"))

        for finding in tuple(findings):
            value = text[finding.start : finding.end]
            cursor = finding.end
            while (start := text.find(value, cursor)) >= 0:
                end = start + len(value)
                findings.append(
                    Finding(finding.entity_type, start, end, finding.score, finding.source)
                )
                cursor = end

        if self._presidio is not None:
            try:
                for result in self._presidio.analyze(text=text, language="en"):
                    presidio_type = result.entity_type.upper()
                    entity_type = (
                        presidio_type
                        if presidio_type
                        in {"AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT"}
                        else _PRESIDIO_ENTITY_TYPES.get(presidio_type)
                    )
                    if entity_type is None or (
                        presidio_type == "DATE_TIME"
                        and not any(char.isdigit() for char in text[result.start : result.end])
                    ):
                        continue
                    findings.append(
                        Finding(
                            entity_type,
                            result.start,
                            result.end,
                            float(result.score),
                            "presidio_india"
                            if str(
                                result.recognition_metadata.get(
                                    "recognizer_name", ""
                                )
                            ).startswith("India")
                            else "presidio",
                        )
                    )
            except (ValueError, RuntimeError):
                logger.error("Presidio analysis failed; pattern detection still completed.")

        return self._select_non_overlapping(findings)

    @staticmethod
    def _select_non_overlapping(findings: list[Finding]) -> list[Finding]:
        priority = {
            "GSTIN": 115,
            "ACCOUNT_NUMBER": 110,
            "AADHAAR": 100,
            "PAN": 95,
            "VOTER_ID": 92,
            "PASSPORT": 92,
            "PHONE": 85,
            "EMAIL": 80,
            "UPI_ID": 78,
            "FINANCIAL_AMOUNT": 70,
            "PERSON": 50,
            "ADDRESS": 45,
        }
        ranked = sorted(
            findings,
            key=lambda finding: (
                -priority.get(finding.entity_type, 40),
                0 if finding.source == "presidio_india" else 1,
                -(finding.end - finding.start),
                finding.start,
            ),
        )
        selected: list[Finding] = []
        for candidate in ranked:
            if candidate.start < 0 or candidate.end <= candidate.start:
                continue
            if any(candidate.start < item.end and item.start < candidate.end for item in selected):
                continue
            selected.append(candidate)
        return sorted(selected, key=lambda finding: finding.start)
