from __future__ import annotations

from app.frontend.response_parser import (
    count_masked_entities,
    filter_response_records,
    parse_response_records,
)


STRUCTURED_RESPONSE = (
    "Record 3: Applicant [PERSON_3], phone [PHONE_3], PAN [PAN_3], "
    "address [ADDRESS_3], monthly salary INR 85,000.\n"
    "Record 8: Applicant [PERSON_8], phone [PHONE_8], Aadhaar [AADHAAR_8], "
    "address [ADDRESS_8]."
)


def test_parses_multiple_masked_records_and_optional_salary() -> None:
    records = parse_response_records(STRUCTURED_RESPONSE)

    assert len(records) == 2
    assert records[0].number == 3
    assert records[0].person == "[PERSON_3]"
    assert records[0].identity_placeholders == ("[PAN_3]",)
    assert records[0].pan_placeholder == "[PAN_3]"
    assert records[0].aadhaar_placeholder == ""
    assert records[0].address_placeholder == "[ADDRESS_3]"
    assert records[0].phone_placeholder == "[PHONE_3]"
    assert records[0].salary == "INR 85,000"
    assert records[1].number == 8
    assert records[1].identity_placeholders == ("[AADHAAR_8]",)
    assert records[1].aadhaar_placeholder == "[AADHAAR_8]"
    assert records[1].salary == ""
    assert count_masked_entities(STRUCTURED_RESPONSE) == 8


def test_filters_records_by_name_placeholder_entity_and_record_number() -> None:
    records = parse_response_records(STRUCTURED_RESPONSE)

    assert [
        record.number
        for record in filter_response_records(records, query="[PAN_3]")
    ] == [3]
    assert [
        record.number
        for record in filter_response_records(records, entity_type="AADHAAR")
    ] == [8]
    assert [
        record.number
        for record in filter_response_records(records, record_number=8)
    ] == [8]
    assert filter_response_records(records, query="not-found") == ()


def test_normal_prose_is_not_forced_into_record_table() -> None:
    assert parse_response_records(
        "The masked applicant [PERSON_1] may qualify based on salary and [PHONE_1]."
    ) == ()
    assert parse_response_records("A normal response without PII placeholders.") == ()


def test_multiple_person_mentions_without_record_fields_fall_back_to_prose() -> None:
    assert parse_response_records(
        "[PERSON_1] and [PERSON_2] are mentioned in the analysis."
    ) == ()


def test_parses_numbered_rows_with_sensitive_fields_before_the_name() -> None:
    response = (
        "1. PAN: [PAN_1] | Name: [PERSON_1] | Mobile: [PHONE_1] "
        "| Address: [ADDRESS_1] | Salary: INR 90,000\n"
        "2. Aadhaar: [AADHAAR_2] | Name: [PERSON_2] | Address: [ADDRESS_2]"
    )

    records = parse_response_records(response)

    assert [record.number for record in records] == [1, 2]
    assert records[0].pan_placeholder == "[PAN_1]"
    assert records[0].person == "[PERSON_1]"
    assert records[0].phone_placeholder == "[PHONE_1]"
    assert records[0].salary == "INR 90,000"
    assert records[1].aadhaar_placeholder == "[AADHAAR_2]"
    assert records[1].address_placeholder == "[ADDRESS_2]"
    assert [
        record.number
        for record in filter_response_records(records, query="90,000")
    ] == [1]


def test_parses_numbered_records_when_name_was_not_detected() -> None:
    records = parse_response_records(
        "Record 4: PAN [PAN_4], mobile [PHONE_4], address [ADDRESS_4]\n"
        "Record 9: Aadhaar [AADHAAR_9], mobile [PHONE_9], address [ADDRESS_9]"
    )

    assert [record.number for record in records] == [4, 9]
    assert records[0].person == ""
    assert records[0].pan_placeholder == "[PAN_4]"
    assert records[1].aadhaar_placeholder == "[AADHAAR_9]"
