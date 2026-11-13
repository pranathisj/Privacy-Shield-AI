"""Bounded text extraction for uploaded text, PDF, and Word documents."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_DOCUMENT_PAGES = 100
MAX_DOCX_UNCOMPRESSED_BYTES = 30 * 1024 * 1024


class DocumentExtractionError(ValueError):
    """Raised when an uploaded document cannot be safely converted to text."""


def extract_document_text(filename: str, content: bytes) -> str:
    if not content:
        raise DocumentExtractionError("The uploaded document is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise DocumentExtractionError("The uploaded document exceeds the 10 MB limit.")

    extension = Path(filename).suffix.casefold()
    if extension == ".txt":
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise DocumentExtractionError("Text documents must use UTF-8 encoding.") from None
    elif extension == ".pdf":
        text = _extract_pdf(content)
    elif extension == ".docx":
        text = _extract_docx(content)
    else:
        raise DocumentExtractionError("Use a TXT, PDF, or DOCX document.")

    if not text.strip():
        raise DocumentExtractionError(
            "No selectable text was found. Scanned documents require OCR, which is not enabled."
        )
    return text


def _extract_pdf(content: bytes) -> str:
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError, PdfStreamError

        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted:
            raise DocumentExtractionError("Password-protected PDFs are not supported.")
        if len(reader.pages) > MAX_DOCUMENT_PAGES:
            raise DocumentExtractionError("PDF documents are limited to 100 pages.")
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except DocumentExtractionError:
        raise
    except (PdfReadError, PdfStreamError, OSError, ValueError):
        raise DocumentExtractionError("The PDF could not be read as a valid document.") from None


def _extract_docx(content: bytes) -> str:
    try:
        with ZipFile(BytesIO(content)) as archive:
            entries = archive.infolist()
            if len(entries) > 1000 or sum(entry.file_size for entry in entries) > MAX_DOCX_UNCOMPRESSED_BYTES:
                raise DocumentExtractionError("The Word document exceeds the extraction limits.")

        from docx import Document
        from docx.opc.exceptions import PackageNotFoundError
        from lxml.etree import XMLSyntaxError

        document = Document(BytesIO(content))
        paragraphs = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
        table_rows = [
            " | ".join(cell.text for cell in row.cells)
            for table in document.tables
            for row in table.rows
        ]
        return "\n".join(paragraphs + table_rows)
    except DocumentExtractionError:
        raise
    except (BadZipFile, KeyError, OSError, PackageNotFoundError, ValueError, XMLSyntaxError):
        raise DocumentExtractionError("The Word document could not be read.") from None
