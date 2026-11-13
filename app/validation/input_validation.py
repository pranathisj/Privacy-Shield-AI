"""Privacy-safe validation of explicitly labeled fields in free-text input."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable

from app.privacy.detector import Finding
from app.privacy.india_identifiers import is_valid_aadhaar, is_valid_gstin, is_valid_pan


class ValidationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class FieldValidation:
    field: str
    status: ValidationStatus
    message: str

    def to_dict(self) -> dict[str, str]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


@dataclass(frozen=True)
class ValidationReport:
    fields: tuple[FieldValidation, ...]

    @property
    def invalid_count(self) -> int:
        return sum(item.status is ValidationStatus.INVALID for item in self.fields)

    @property
    def missing_count(self) -> int:
        return sum(item.status is ValidationStatus.MISSING for item in self.fields)

    @property
    def uncertain_count(self) -> int:
        return sum(item.status is ValidationStatus.UNCERTAIN for item in self.fields)

    @property
    def valid_count(self) -> int:
        return sum(item.status is ValidationStatus.VALID for item in self.fields)

    def to_dict(self) -> dict[str, object]:
        if not self.fields:
            summary = (
                "No explicitly labeled or detected fields found. Unstructured text is not "
                "assumed to require every field."
            )
        elif self.invalid_count or self.missing_count:
            summary = (
                f"{self.invalid_count} invalid and {self.missing_count} missing "
                f"field(s); sensitive values will still be masked."
            )
        elif self.uncertain_count:
            summary = (
                f"{self.uncertain_count} field(s) need review; "
                "unambiguous values passed validation."
            )
        else:
            summary = f"All {self.valid_count} detected or entered field value(s) passed validation."

        return {
            "fields": [item.to_dict() for item in self.fields],
            "summary": summary,
            "valid_count": self.valid_count,
            "invalid_count": self.invalid_count,
            "missing_count": self.missing_count,
            "uncertain_count": self.uncertain_count,
        }


_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Person name",
        re.compile(
            r"\b(?:person\s+name|applicant(?:\s+name)?|customer(?:\s+name)?|name|naam)"
            r"(?:\s+is)?\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Indian mobile number",
        re.compile(
            r"\b(?:mobile|phone|telephone|tel|whatsapp|contact(?:\s*(?:number|no\.?))?)"
            r"(?:\s*(?:number|no\.?))?\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Email address",
        re.compile(
            r"\b(?:email(?:\s+address)?|e-mail)\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Aadhaar",
        re.compile(
            r"\b(?:aadhaar|aadhar|uidai|uid)(?:\s*(?:card|id|no\.?|number))?"
            r"\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "PAN",
        re.compile(
            r"\b(?:pan(?:\s*(?:card|no\.?|number))?|permanent\s+account\s+number)"
            r"\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "GSTIN",
        re.compile(
            r"\b(?:gstin(?:\s*(?:id|no\.?|number))?|gst\s*(?:identification\s*)?"
            r"(?:no\.?|number))\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Voter ID",
        re.compile(
            r"\b(?:voter(?:\s*(?:id|identity)(?:\s*card)?)?|epic(?:\s*(?:no\.?|number))?)"
            r"\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Passport number",
        re.compile(
            r"\bpassport(?:\s*(?:no\.?|number))?\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Indian PIN code",
        re.compile(
            r"\b(?:pin(?:\s*code)?|pincode|postal\s+code|zip(?:\s*code)?)"
            r"\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "Date",
        re.compile(
            r"\b(?:date\s+of\s+birth|dob|date)\s*(?::|=)?\s*(?P<value>[^;,\n]*)",
            re.IGNORECASE,
        ),
    ),
)

_VALIDATORS = {
    "Person name": lambda value: _validate_name(value),
    "Indian mobile number": lambda value: _validate_mobile(value),
    "Email address": lambda value: _validate_email(value),
    "Aadhaar": lambda value: (
        ValidationStatus.VALID if is_valid_aadhaar(value) else ValidationStatus.INVALID,
        "Aadhaar format and checksum are valid."
        if is_valid_aadhaar(value)
        else "Enter a 12-digit Aadhaar value with a valid checksum.",
    ),
    "PAN": lambda value: (
        ValidationStatus.VALID if is_valid_pan(value) else ValidationStatus.INVALID,
        "PAN format is valid."
        if is_valid_pan(value)
        else "Enter a 10-character PAN with a valid holder-category code.",
    ),
    "GSTIN": lambda value: (
        ValidationStatus.VALID if is_valid_gstin(value) else ValidationStatus.INVALID,
        "GSTIN structure and checksum are valid."
        if is_valid_gstin(value)
        else "Enter a 15-character GSTIN with a valid state code, PAN structure, and checksum.",
    ),
    "Voter ID": lambda value: _validate_shape(
        value, r"[A-Z]{3}\d{7}", "Enter a 3-letter and 7-digit Voter ID."
    ),
    "Passport number": lambda value: _validate_shape(
        value, r"[A-Z]\d{7}", "Enter a passport number with 1 letter followed by 7 digits."
    ),
    "Indian PIN code": lambda value: _validate_shape(
        value, r"[1-9]\d{5}", "Enter a 6-digit Indian PIN code that does not start with zero."
    ),
    "Date": lambda value: _validate_date(value),
}


def _validate_shape(value: str, pattern: str, invalid_message: str) -> tuple[ValidationStatus, str]:
    if re.fullmatch(pattern, value, re.IGNORECASE):
        return ValidationStatus.VALID, "Format is valid."
    return ValidationStatus.INVALID, invalid_message


def _validate_name(value: str) -> tuple[ValidationStatus, str]:
    parts = value.split()
    if not parts or any(not part.replace(".", "").replace("'", "").replace("-", "").isalpha() for part in parts):
        return ValidationStatus.INVALID, "Use letters, spaces, apostrophes, or hyphens for the name."
    if len(parts) == 1:
        return ValidationStatus.UNCERTAIN, "Only one name component was found; confirm it is complete."
    if len(parts) > 4:
        return ValidationStatus.INVALID, "Enter a name with no more than four components."
    return ValidationStatus.VALID, "Name format is valid."


def _validate_mobile(value: str) -> tuple[ValidationStatus, str]:
    if not re.fullmatch(r"(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}", value):
        return ValidationStatus.INVALID, "Enter a 10-digit Indian mobile number, optionally prefixed by +91."
    return ValidationStatus.VALID, "Indian mobile number format is valid."


def _validate_email(value: str) -> tuple[ValidationStatus, str]:
    pattern = r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+"
    if re.fullmatch(pattern, value, re.IGNORECASE):
        return ValidationStatus.VALID, "Email address format is valid."
    return ValidationStatus.INVALID, "Enter an email address in the form name@example.com."


def _validate_date(value: str) -> tuple[ValidationStatus, str]:
    formats = ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y")
    for date_format in formats:
        try:
            datetime.strptime(value, date_format)
        except ValueError:
            continue
        if date_format in {"%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y"}:
            separator = date_format[2]
            day, month, _ = value.split(separator)
            if int(day) <= 12 and int(month) <= 12 and day != month:
                return ValidationStatus.UNCERTAIN, "Date is valid but day/month order may be ambiguous."
        return ValidationStatus.VALID, "Calendar date is valid."
    return ValidationStatus.INVALID, "Enter a real date in YYYY-MM-DD or DD/MM/YYYY format."


_ENTITY_FIELDS = {
    "PERSON": "Person name",
    "PHONE": "Indian mobile number",
    "EMAIL": "Email address",
    "AADHAAR": "Aadhaar",
    "PAN": "PAN",
    "GSTIN": "GSTIN",
    "VOTER_ID": "Voter ID",
    "PASSPORT": "Passport number",
    "PIN_CODE": "Indian PIN code",
    "DATE_OF_BIRTH": "Date",
}


def _validate_field(field: str, value: str) -> FieldValidation:
    if not value:
        return FieldValidation(
            field,
            ValidationStatus.MISSING,
            f"{field} is labeled but has no value.",
        )
    status, message = _VALIDATORS[field](value)
    return FieldValidation(field, status, message)


def validate_text(
    text: str,
    detected_findings: Iterable[Finding] = (),
) -> ValidationReport:
    """Validate labeled fields and detected PII without retaining or returning values."""
    if not text.strip():
        return ValidationReport(
            (FieldValidation("Input text", ValidationStatus.MISSING, "Enter text to validate."),)
        )

    field_results: list[tuple[int, FieldValidation]] = []
    for finding in detected_findings:
        field = _ENTITY_FIELDS.get(finding.entity_type)
        if field is None or finding.start < 0 or finding.end > len(text):
            continue
        value = text[finding.start : finding.end].strip()
        field_results.append((finding.start, _validate_field(field, value)))

    for field, pattern in _FIELD_PATTERNS:
        for match in pattern.finditer(text):
            value = (match.group("value") or "").strip().rstrip(".")
            result = _validate_field(field, value)
            field_results.append((match.start(), result))

    field_results.sort(key=lambda item: item[0])
    unique_results: list[FieldValidation] = []
    seen_results: set[tuple[str, ValidationStatus, str]] = set()
    for _, result in field_results:
        key = (result.field, result.status, result.message)
        if key not in seen_results:
            unique_results.append(result)
            seen_results.add(key)
    return ValidationReport(tuple(unique_results))
