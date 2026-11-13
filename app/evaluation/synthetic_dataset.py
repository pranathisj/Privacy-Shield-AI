"""Deterministic, fictional Indian-language documents with exact PII labels."""

from __future__ import annotations

from dataclasses import dataclass

from app.privacy.india_identifiers import gstin_checksum_digit, is_valid_aadhaar


@dataclass(frozen=True)
class SyntheticEntity:
    entity_type: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class SyntheticDocument:
    document_id: str
    text: str
    entities: tuple[SyntheticEntity, ...]


_PROFILES = (
    ("Aarav Nair", "9876500001", "85,000", "5,00,000", "18,500", "Pune"),
    ("Diya Raman", "9876500002", "92,000", "6,50,000", "21,200", "Kochi"),
    ("Kabir Desai", "9876500003", "76,500", "4,25,000", "16,300", "Surat"),
    ("Mira Kulkarni", "9876500004", "1,05,000", "8,00,000", "26,400", "Nagpur"),
    ("Rohan Pillai", "9876500005", "68,000", "3,75,000", "14,900", "Thiruvananthapuram"),
    ("Tara Iqbal", "9876500006", "88,500", "5,75,000", "19,800", "Lucknow"),
    ("Vihaan Bose", "9876500007", "1,12,000", "9,00,000", "29,700", "Kolkata"),
    ("Zoya Menon", "9876500008", "73,000", "4,00,000", "15,800", "Mysuru"),
    ("Ishaan Rao", "9876500009", "96,000", "7,25,000", "23,600", "Hyderabad"),
)

_TEMPLATES = (
    (
        "Loan application applicant {name}; phone {phone}; email {email}; Aadhaar {aadhaar}; "
        "PAN {pan}; GSTIN: {gstin}; Voter ID: {voter}; Passport No: {passport}; "
        "address: {address}; account number: {account}; monthly salary INR {salary}, "
        "requested loan INR {loan}, EMI INR {emi}."
    ),
    (
        "Kindly review applicant {name}; mobile {phone}; email ID {email}; Aadhaar no. "
        "{aadhaar}; PAN no. {pan}; GSTIN number {gstin}; EPIC number {voter}; "
        "passport number {passport}; residing at: {address}; A/C {account}; take-home "
        "salary INR {salary}, loan amount INR {loan}, repayment EMI INR {emi}."
    ),
    (
        "Namaste, applicant {name}; contact no. {phone}; email id {email}; Aadhaar card "
        "{aadhaar}; PAN no. {pan}; GSTIN no. {gstin}; Voter ID {voter}; Passport no. "
        "{passport}; address: {address}; bank account number {account}; salary INR "
        "{salary}, loan chahiye INR {loan}; EMI INR {emi}."
    ),
    (
        "Fictional case review for applicant {name}; WhatsApp {phone} / {email}; "
        "Aadhaar ID {aadhaar}; PAN: {pan}; GSTIN: {gstin}; Voter ID: {voter}; "
        "Passport: {passport}; residing at: {address}; account no: {account}; "
        "monthly income INR {salary}; requested amount INR {loan}; monthly repayment "
        "INR {emi}."
    ),
    (
        "Case {case_id}; applicant {name}; number {phone}; mail {email}; Aadhaar ID "
        "{aadhaar}; PAN no. {pan}; GSTIN no. {gstin}; EPIC no. {voter}; passport no. "
        "{passport}; address: {address}; account number {account}. Salary per month "
        "INR {salary}, loan INR {loan}, EMI INR {emi}."
    ),
)

_GST_STATE_CODES = ("27", "32", "24", "27", "32", "09", "19", "29", "36")

_NEGATIVE_TEXTS = (
    "Monthly salary INR 85,000; requested loan INR 5,00,000; EMI INR 18,500.",
    "Fictional voucher reference 9876543210 is a non-phone internal code.",
    "A demo report contains 12 monthly instalments and 3 dependants.",
    "Transaction reference INV-TEST-42 has no customer identifier.",
    "The sample uses no personal names, phone values, or account numbers.",
)


def _phone_variant(phone: str, template_index: int) -> str:
    first, last = phone[:5], phone[5:]
    return (
        phone,
        f"+91-{first}-{last}",
        f"+91 {first} {last}",
        f"{first}-{last}",
        f"+91 {first}-{last}",
    )[template_index]


def _synthetic_aadhaar(profile_index: int) -> str:
    prefix = f"23456700{profile_index:03d}"
    for check_digit in "0123456789":
        digits = f"{prefix}{check_digit}"
        if is_valid_aadhaar(digits):
            break
    else:
        raise ValueError("Could not generate a checksum-valid synthetic Aadhaar value.")
    return f"{digits[:4]} {digits[4:8]} {digits[8:]}"


def _make_document(
    document_id: str,
    text: str,
    labels: tuple[tuple[str, str], ...] = (),
) -> SyntheticDocument:
    entities: list[SyntheticEntity] = []
    search_from = 0
    for entity_type, value in labels:
        start = text.find(value, search_from)
        if start < 0:
            raise ValueError(f"Synthetic label {entity_type} is absent from {document_id}.")
        end = start + len(value)
        entities.append(SyntheticEntity(entity_type, value, start, end))
        search_from = end
    return SyntheticDocument(document_id, text, tuple(entities))


def load_synthetic_dataset() -> tuple[SyntheticDocument, ...]:
    """Return 45 labeled PII documents and five negative examples (50 total)."""
    documents: list[SyntheticDocument] = []
    for profile_index, profile in enumerate(_PROFILES, start=1):
        name, base_phone, salary, loan, emi, city = profile
        pan = f"FICPA{profile_index:04d}{chr(64 + profile_index)}"
        gstin_prefix = f"{_GST_STATE_CODES[profile_index - 1]}{pan}1Z"
        fields = {
            "name": name,
            "email": f"case{profile_index:02d}@example.invalid",
            "aadhaar": _synthetic_aadhaar(profile_index),
            "pan": pan,
            "gstin": f"{gstin_prefix}{gstin_checksum_digit(gstin_prefix)}",
            "voter": f"VTR{profile_index:07d}",
            "passport": f"Z{profile_index:07d}",
            "address": f"Plot {profile_index}, Fictional Marg, Demo Nagar, {city}",
            "account": f"100000000{profile_index:03d}",
            "salary": salary,
            "loan": loan,
            "emi": emi,
        }
        for template_index, template in enumerate(_TEMPLATES):
            phone = _phone_variant(base_phone, template_index)
            text = template.format(
                **fields,
                phone=phone,
                case_id=f"DEMO-{profile_index:02d}-{template_index + 1}",
            )
            labels = (
                ("PERSON", fields["name"]),
                ("PHONE", phone),
                ("EMAIL", fields["email"]),
                ("AADHAAR", fields["aadhaar"]),
                ("PAN", fields["pan"]),
                ("GSTIN", fields["gstin"]),
                ("VOTER_ID", fields["voter"]),
                ("PASSPORT", fields["passport"]),
                ("ADDRESS", fields["address"]),
                ("ACCOUNT_NUMBER", fields["account"]),
            )
            documents.append(
                _make_document(
                    f"synthetic-{profile_index:02d}-{template_index + 1:02d}",
                    text,
                    labels,
                )
            )

    documents.extend(
        _make_document(f"negative-{index:02d}", text)
        for index, text in enumerate(_NEGATIVE_TEXTS, start=1)
    )
    return tuple(documents)
