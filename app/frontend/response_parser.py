"""Conservative parsing for placeholder-based multi-record AI responses."""

from __future__ import annotations

import re
from dataclasses import dataclass

PLACEHOLDER_PATTERN = re.compile(r"\[([A-Z][A-Z0-9_]*)_(\d+)\]")
PERSON_PATTERN = re.compile(r"\[PERSON_(\d+)\]")
RECORD_LABEL_PATTERN = re.compile(
    r"(?im)^\s*(?:(?:record|applicant|customer)\s*(?:#|no\.?)?\s*)?"
    r"(\d+)\s*[:.)-]\s*"
)
SALARY_PATTERN = re.compile(
    r"\b(?:monthly\s+)?(?:salary|income|earnings)\b\s*"
    r"(?:(?:is|of|:|=)\s*)?(?P<currency>INR|Rs\.?|₹)?\s*"
    r"([0-9][0-9,]*(?:\.\d{1,2})?)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ResponseRecord:
    number: int
    person: str
    identity_placeholders: tuple[str, ...]
    address_placeholder: str
    phone_placeholder: str
    salary: str
    placeholders: tuple[str, ...]

    @property
    def entity_types(self) -> frozenset[str]:
        return frozenset(
            match.group(1)
            for placeholder in self.placeholders
            if (match := PLACEHOLDER_PATTERN.fullmatch(placeholder)) is not None
        )

    @property
    def pan_placeholder(self) -> str:
        return next((token for token in self.identity_placeholders if token.startswith("[PAN_")), "")

    @property
    def aadhaar_placeholder(self) -> str:
        return next(
            (token for token in self.identity_placeholders if token.startswith("[AADHAAR_")),
            "",
        )


def parse_response_records(response: str) -> tuple[ResponseRecord, ...]:
    """Parse multi-record responses while requiring masked, record-like fields."""
    record_labels = list(RECORD_LABEL_PATTERN.finditer(response))
    person_matches = list(PERSON_PATTERN.finditer(response))
    if len(record_labels) >= 2:
        candidates = [
            (
                label.start(),
                record_labels[index + 1].start()
                if index + 1 < len(record_labels)
                else len(response),
                index + 1,
                int(label.group(1)),
                PERSON_PATTERN.search(
                    response,
                    label.start(),
                    record_labels[index + 1].start()
                    if index + 1 < len(record_labels)
                    else len(response),
                ),
            )
            for index, label in enumerate(record_labels)
        ]
    elif len(person_matches) >= 2:
        boundaries: list[tuple[int, int]] = []
        for index, person_match in enumerate(person_matches):
            prefix_start = person_matches[index - 1].end() if index else 0
            prefix = response[prefix_start : person_match.start()]
            labels = list(RECORD_LABEL_PATTERN.finditer(prefix))
            record_start = prefix_start + labels[-1].start() if labels else person_match.start()
            if boundaries:
                previous_start, _ = boundaries[-1]
                boundaries[-1] = (previous_start, record_start)
            boundaries.append((record_start, len(response)))
        candidates = [
            (
                start,
                end,
                index,
                int(label.group(1)) if (label := RECORD_LABEL_PATTERN.search(response, start, end)) else index,
                person_match,
            )
            for index, ((start, end), person_match) in enumerate(
                zip(boundaries, person_matches, strict=True),
                start=1,
            )
        ]
    else:
        return ()

    records: list[ResponseRecord] = []
    for start, end, index, record_number, person_match in candidates:
        segment = response[start:end].strip()
        tokens = tuple(
            dict.fromkeys(
                f"[{match.group(1)}_{match.group(2)}]"
                for match in PLACEHOLDER_PATTERN.finditer(segment)
            )
        )
        entity_types = {
            match.group(1)
            for match in PLACEHOLDER_PATTERN.finditer(segment)
        }
        if not entity_types.intersection(
            {"PAN", "AADHAAR", "ADDRESS", "PHONE", "VOTER_ID", "PASSPORT"}
        ):
            return ()

        identity = tuple(
            token
            for token in tokens
            if token.startswith(("[PAN_", "[AADHAAR_"))
        )
        address = next((token for token in tokens if token.startswith("[ADDRESS_")), "")
        phone = next((token for token in tokens if token.startswith("[PHONE_")), "")
        salary_match = SALARY_PATTERN.search(segment)
        salary = ""
        if salary_match:
            currency = salary_match.group("currency")
            amount = salary_match.group(2)
            salary = f"{currency} {amount}".strip() if currency else amount
        records.append(
            ResponseRecord(
                number=record_number,
                person=f"[PERSON_{person_match.group(1)}]" if person_match else "",
                identity_placeholders=identity,
                address_placeholder=address,
                phone_placeholder=phone,
                salary=salary,
                placeholders=tokens,
            )
        )
    return tuple(records)


def filter_response_records(
    records: tuple[ResponseRecord, ...],
    *,
    query: str = "",
    entity_type: str = "All entity types",
    record_number: int | None = None,
) -> tuple[ResponseRecord, ...]:
    normalized_query = query.casefold().strip()
    return tuple(
        record
        for record in records
        if (record_number is None or record.number == record_number)
        and (entity_type == "All entity types" or entity_type in record.entity_types)
        and (
            not normalized_query
            or normalized_query in record.person.casefold()
            or normalized_query in record.salary.casefold()
            or any(normalized_query in token.casefold() for token in record.placeholders)
        )
    )


def count_masked_entities(response: str) -> int:
    return len(set(PLACEHOLDER_PATTERN.findall(response)))
