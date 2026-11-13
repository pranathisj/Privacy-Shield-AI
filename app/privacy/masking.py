"""Request-scoped, typed placeholder generation."""

from __future__ import annotations

from dataclasses import dataclass

from app.privacy.detector import Finding


@dataclass(frozen=True)
class MappingEntry:
    placeholder: str
    entity_type: str
    original_value: str


@dataclass(frozen=True)
class MaskResult:
    sanitized_text: str
    mappings: tuple[MappingEntry, ...]


def mask_text(text: str, findings: list[Finding]) -> MaskResult:
    counters: dict[str, int] = {}
    seen: dict[tuple[str, str], str] = {}
    mappings: list[MappingEntry] = []
    replacements: list[tuple[int, int, str]] = []

    for finding in findings:
        original = text[finding.start : finding.end]
        key = (finding.entity_type, original.casefold())
        placeholder = seen.get(key)
        if placeholder is None:
            counters[finding.entity_type] = counters.get(finding.entity_type, 0) + 1
            placeholder = f"[{finding.entity_type}_{counters[finding.entity_type]}]"
            seen[key] = placeholder
            mappings.append(MappingEntry(placeholder, finding.entity_type, original))
        replacements.append((finding.start, finding.end, placeholder))

    sanitized = text
    for start, end, placeholder in reversed(replacements):
        sanitized = sanitized[:start] + placeholder + sanitized[end:]
    return MaskResult(sanitized, tuple(mappings))
