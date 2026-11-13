"""Deterministic format checks for common Indian identifiers."""

from __future__ import annotations

import re

_VERHOEFF_MULTIPLICATION = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_PERMUTATION = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_GSTIN_STATES = frozenset(f"{code:02d}" for code in range(1, 39)) | {"97"}
_VALID_PAN_TYPES = frozenset("PCHFATBLJG")


def _has_verhoeff_checksum(digits: str) -> bool:
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        checksum = _VERHOEFF_MULTIPLICATION[checksum][
            _VERHOEFF_PERMUTATION[index % 8][int(digit)]
        ]
    return checksum == 0


def is_valid_aadhaar(value: str) -> bool:
    """Validate a 12-digit Aadhaar-shaped value with its Verhoeff checksum."""
    digits = re.sub(r"[\s-]", "", value)
    return (
        len(digits) == 12
        and digits.isdigit()
        and digits[0] in "23456789"
        and _has_verhoeff_checksum(digits)
    )


def is_valid_pan(value: str) -> bool:
    """Validate PAN structure and the encoded holder category."""
    return (
        re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", value, re.IGNORECASE) is not None
        and value[3].upper() in _VALID_PAN_TYPES
    )


def gstin_checksum_digit(value_without_checksum: str) -> str:
    """Return the GSTIN mod-36 check character for a 14-character prefix."""
    value = value_without_checksum.upper()
    if len(value) != 14 or any(char not in _GSTIN_ALPHABET for char in value):
        raise ValueError("GSTIN checksum requires a 14-character alphanumeric prefix.")

    total = 0
    for index, char in enumerate(reversed(value)):
        product = _GSTIN_ALPHABET.index(char) * (2 if index % 2 == 0 else 1)
        total += product // 36 + product % 36
    return _GSTIN_ALPHABET[(36 - total % 36) % 36]


def is_valid_gstin(value: str) -> bool:
    """Validate GSTIN structure, embedded PAN category, state code, and checksum."""
    gstin = value.upper()
    if re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[A-Z0-9]", gstin) is None:
        return False
    if gstin[:2] not in _GSTIN_STATES or not is_valid_pan(gstin[2:12]):
        return False
    return gstin[-1] == gstin_checksum_digit(gstin[:14])
