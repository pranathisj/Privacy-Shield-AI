from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from docx import Document
from pypdf import PdfWriter

from app.config import Settings
from app.privacy.detector import PIIDetector
from app.privacy.masking import mask_text
from app.validation.document_extraction import DocumentExtractionError, extract_document_text
from app.validation.input_validation import ValidationStatus, validate_text


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("Applicant name: Asha Mehta", "Person name"),
        ("Mobile: +91 98765 43210", "Indian mobile number"),
        ("Email: asha@example.invalid", "Email address"),
        ("Aadhaar: 2345 6789 0124", "Aadhaar"),
        ("PAN: ABCPE1234F", "PAN"),
        ("GSTIN: 27ABCPE1234F1ZB", "GSTIN"),
        ("Voter ID: ABC1234567", "Voter ID"),
        ("Passport: N1234567", "Passport number"),
        ("PIN code: 411001", "Indian PIN code"),
        ("Date of birth: 1990-04-15", "Date"),
    ],
)
def test_valid_labeled_fields_pass_validation(text: str, field: str) -> None:
    report = validate_text(text)

    assert len(report.fields) == 1
    assert report.fields[0].field == field
    assert report.fields[0].status is ValidationStatus.VALID


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("Applicant name: Asha123 Mehta", "Person name"),
        ("Mobile: 12345", "Indian mobile number"),
        ("Email: asha@", "Email address"),
        ("Aadhaar: 2345 6789 0123", "Aadhaar"),
        ("PAN: ABCDE1234F", "PAN"),
        ("GSTIN: 27ABCPE1234F1Z0", "GSTIN"),
        ("Voter ID: AB1234567", "Voter ID"),
        ("Passport: N123456", "Passport number"),
        ("PIN code: 041100", "Indian PIN code"),
        ("Date of birth: 31/02/2025", "Date"),
    ],
)
def test_malformed_labeled_fields_are_reported_without_echoing_values(
    text: str,
    field: str,
) -> None:
    report = validate_text(text)
    rendered = str(report.to_dict())

    assert report.fields[0].field == field
    assert report.fields[0].status is ValidationStatus.INVALID
    assert report.invalid_count == 1
    assert text.split(":", maxsplit=1)[-1].strip() not in rendered


@pytest.mark.parametrize(
    "text",
    [
        "Applicant name:; Mobile:; Email:; Aadhaar:; PAN:; GSTIN:; "
        "Voter ID:; Passport:; PIN code:; Date of birth:",
        "",
    ],
)
def test_missing_labeled_or_empty_input_is_reported(text: str) -> None:
    report = validate_text(text)

    assert report.missing_count == (10 if text else 1)
    assert all(item.status is ValidationStatus.MISSING for item in report.fields)


@pytest.mark.parametrize(
    ("text", "expected_status"),
    [
        ("Applicant name: Asha", ValidationStatus.UNCERTAIN),
        ("Date: 03/04/2025", ValidationStatus.UNCERTAIN),
        ("A natural-language loan review with no labeled fields.", None),
    ],
)
def test_ambiguous_or_unstructured_text_is_not_misclassified(
    text: str,
    expected_status: ValidationStatus | None,
) -> None:
    report = validate_text(text)

    if expected_status is None:
        assert report.fields == ()
        assert "not assumed to require every field" in str(report.to_dict())
    else:
        assert report.fields[0].status is expected_status


def test_validation_includes_detected_identifiers_without_inventing_unentered_fields() -> None:
    text = "Aadhaar 2345 6789 0123 and mobile 12345."
    settings = Settings(
    data_dir=Path("unused"),
    database_path=Path("unused") / "privacyshield.db",
    encryption_key=None,
    llm_provider="mock",
    llm_api_key=None,
    llm_base_url="",
    llm_model="",
    llm_timeout_seconds=1,
    presidio_enabled=False,
    presidio_model="en_core_web_sm",
    api_key=None,
    )
    findings = PIIDetector(settings).detect(text)

    report = validate_text(text, findings)

    assert {(item.field, item.status) for item in report.fields} == {
    ("Aadhaar", ValidationStatus.INVALID),
    ("Indian mobile number", ValidationStatus.INVALID),
    }


def test_duplicate_detected_and_labeled_field_messages_are_deduplicated() -> None:
    text = "Aadhaar: 2345 6789 0123; Aadhaar: 2345 6789 0123"
    settings = Settings(
    data_dir=Path("unused"),
    database_path=Path("unused") / "privacyshield.db",
    encryption_key=None,
    llm_provider="mock",
    llm_api_key=None,
    llm_base_url="",
    llm_model="",
    llm_timeout_seconds=1,
    presidio_enabled=False,
    presidio_model="en_core_web_sm",
    api_key=None,
    )
    findings = PIIDetector(settings).detect(text)

    report = validate_text(text, findings)

    assert len(report.fields) == 1
    assert report.fields[0].field == "Aadhaar"
    assert report.fields[0].status is ValidationStatus.INVALID


def test_invalid_sensitive_values_are_still_masked_and_validation_never_returns_them() -> None:
    text = (
        "Applicant name: Asha123 Mehta; Mobile: 12345; Email: asha@; "
        "Aadhaar: 2345 6789 0123; PAN: ABCDE1234F; GSTIN: 27ABCPE1234F1Z0; "
        "Voter ID: AB1234567; Passport: N123456; PIN code: 041100; "
        "Date of birth: 31/02/2025."
    )
    settings = Settings(
        data_dir=Path("unused"),
        database_path=Path("unused") / "privacyshield.db",
        encryption_key=None,
        llm_provider="mock",
        llm_api_key=None,
        llm_base_url="",
        llm_model="",
        llm_timeout_seconds=1,
        presidio_enabled=False,
        presidio_model="en_core_web_sm",
        api_key=None,
    )
    masked = mask_text(text, PIIDetector(settings).detect(text))
    report = validate_text(text).to_dict()

    assert report["invalid_count"] == 10
    assert "Asha123 Mehta" not in masked.sanitized_text
    assert "12345" not in masked.sanitized_text
    assert "asha@" not in masked.sanitized_text
    assert "2345 6789 0123" not in masked.sanitized_text
    assert "ABCDE1234F" not in masked.sanitized_text
    assert "27ABCPE1234F1Z0" not in masked.sanitized_text
    assert "AB1234567" not in masked.sanitized_text
    assert "N123456" not in masked.sanitized_text
    assert "041100" not in masked.sanitized_text
    assert "31/02/2025" not in masked.sanitized_text
    assert all(value not in str(report) for value in ("Asha123", "12345", "asha@", "2345"))


def test_text_upload_extracts_utf8_and_rejects_bad_encoding_and_unsupported_types() -> None:
    assert extract_document_text("fictional.txt", b"Applicant: Asha Mehta") == (
        "Applicant: Asha Mehta"
    )

    with pytest.raises(DocumentExtractionError, match="UTF-8"):
        extract_document_text("fictional.txt", b"\xff")
    with pytest.raises(DocumentExtractionError, match="TXT, PDF, or DOCX"):
        extract_document_text("fictional.csv", b"a,b")


def test_docx_upload_extracts_paragraphs_and_tables() -> None:
    document = Document()
    document.add_paragraph("Applicant: Asha Mehta")
    table = document.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "Mobile"
    table.cell(0, 1).text = "9876543210"
    buffer = BytesIO()
    document.save(buffer)

    text = extract_document_text("fictional.docx", buffer.getvalue())

    assert "Applicant: Asha Mehta" in text
    assert "Mobile | 9876543210" in text


def test_pdf_upload_reports_unextractable_scanned_content() -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    buffer = BytesIO()
    writer.write(buffer)

    with pytest.raises(DocumentExtractionError, match="No selectable text"):
        extract_document_text("fictional.pdf", buffer.getvalue())


def test_pdf_upload_extracts_selectable_text() -> None:
    content_stream = b"BT /F1 12 Tf 72 720 Td (Applicant name: Asha Mehta) Tj ET"
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(content_stream)).encode("ascii")
        + b" >>\nstream\n"
        + content_stream
        + b"\nendstream",
    )
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF".encode("ascii")
    )

    text = extract_document_text("fictional.pdf", bytes(pdf))

    assert "Applicant name: Asha Mehta" in text


def test_document_upload_limits_size_before_parsing() -> None:
    with pytest.raises(DocumentExtractionError, match="10 MB limit"):
        extract_document_text("fictional.txt", b"x" * (10 * 1024 * 1024 + 1))
