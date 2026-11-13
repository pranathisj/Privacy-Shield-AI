from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = PROJECT_ROOT / "app" / "frontend" / "dashboard.py"
ORIGINAL_TEXT = "Please call fictional number 9876543210."
SANITIZED_TEXT = "Please call fictional number [PHONE_1]."
REQUEST_ID = "e9c54144-61b0-4ea6-9e83-a157add0950e"
TEST_API_KEY = "dashboard-test-api-key"


def test_dashboard_config_key_helper_is_available_from_workspace_config() -> None:
    from app.config import dashboard_api_key, dashboard_api_url

    assert callable(dashboard_api_key)
    assert callable(dashboard_api_url)


@pytest.fixture(autouse=True)
def configure_test_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACYSHIELD_API_KEY", TEST_API_KEY)


def _response(payload: object, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def _metrics_response() -> httpx.Response:
    return _response({"scans": 1, "entities_masked": 1, "completions": 1})


def _evaluation_response() -> httpx.Response:
    return _response(
        {
            "document_count": 50,
            "positive_document_count": 45,
            "negative_document_count": 5,
            "labeled_entity_count": 450,
            "true_positives": 450,
            "false_positives": 2,
            "false_negatives": 0,
            "precision": round(450 / 452, 4),
            "recall": 1.0,
            "f1": round(2 * (450 / 452) / (450 / 452 + 1), 4),
            "correctly_masked_entities": 450,
            "placeholder_masking_accuracy": 1.0,
            "sanitized_payload_leakage_count": 0,
            "provider_input_leakage_count": 0,
            "raw_ai_response_leakage_count": 0,
            "privacy_leakage_count": 0,
            "privacy_leakage_rate": 0.0,
        }
    )


def _audit_response() -> httpx.Response:
    return _response(
        {
            "logs": [
                {
                    "created_at": "2026-11-12T10:00:00+00:00",
                    "event": "completion",
                    "entity_types": ["PHONE"],
                    "entity_count": 1,
                    "provider": "mock",
                    "model": "local-mock",
                    "success": True,
                },
                {
                    "created_at": "2026-11-12T09:59:00+00:00",
                    "event": "scan",
                    "entity_types": ["PHONE"],
                    "entity_count": 1,
                    "provider": None,
                    "model": None,
                    "success": True,
                },
            ]
        }
    )


def _validation_response() -> dict[str, object]:
    return {
        "fields": [],
        "summary": (
            "No labeled fields found. Unstructured text is not assumed to require every field."
        ),
        "valid_count": 0,
        "invalid_count": 0,
        "missing_count": 0,
        "uncertain_count": 0,
    }


def _dashboard_get(url: str, **kwargs: object) -> httpx.Response:
    if url.endswith("/api/health"):
        return _response({"status": "ok"})
    assert kwargs["headers"] == {"X-API-Key": TEST_API_KEY}
    if url.endswith("/api/metrics"):
        return _metrics_response()
    if url.endswith("/api/evaluation"):
        return _evaluation_response()
    return _audit_response()


def test_dashboard_scan_completion_and_refreshes() -> None:
    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        assert kwargs["headers"] == {"X-API-Key": TEST_API_KEY}
        if url.endswith("/api/scan"):
            assert kwargs["json"] == {"text": ORIGINAL_TEXT}
            return _response(
                {
                    "request_id": REQUEST_ID,
                    "sanitized_text": SANITIZED_TEXT,
                    "entity_count": 1,
                    "entity_types": ["PHONE"],
                    "duration_ms": 1.5,
                    "validation": _validation_response(),
                }
            )
        if url.endswith("/api/complete"):
            assert kwargs["json"] == {"request_id": REQUEST_ID}
            return _response(
                {
                    "response": "Reviewed [PHONE_1].",
                    "display_response": "Reviewed [PHONE_1].",
                    "provider": "mock",
                }
            )
        assert url.endswith("/api/reidentify")
        assert kwargs["json"] == {
            "request_id": REQUEST_ID,
            "raw_response": "Reviewed [PHONE_1].",
            "authorized": True,
        }
        return _response({"response": "Reviewed 9876543210.", "restored_count": 1})

    with patch("httpx.post", side_effect=fake_post) as post, patch(
        "httpx.get",
        side_effect=_dashboard_get,
    ) as get:
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        assert not app.exception
        assert TEST_API_KEY not in str(app)

        original_input = app.text_area(key="original_text")
        assert not original_input.disabled
        original_input.set_value(ORIGINAL_TEXT).run()
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        post.assert_called_once()
        assert app.text_area[1].value == SANITIZED_TEXT
        assert any("detected 1 item(s): PHONE" in item.value for item in app.success)
        assert any(
            "All detected fields are valid" in item.value for item in app.markdown
        )
        assert not app.button(key="send_button").disabled

        app.button(key="send_button").click().run(timeout=15)
        assert not app.exception
        assert post.call_count == 2
        assert app.info[0].value == "Reviewed [PHONE_1]."
        assert any("Response received from mock" in item.value for item in app.success)
        assert app.checkbox[0].value is False
        assert app.button(key="reidentify_button").disabled
        assert app.session_state["reidentified_response"] == ""

        app.checkbox[0].check().run(timeout=15)
        assert not app.button(key="reidentify_button").disabled
        app.button(key="reidentify_button").click().run(timeout=15)
        assert not app.exception
        assert post.call_count == 3
        assert app.session_state["reidentified_response"] == "Reviewed 9876543210."
        assert any("1 placeholder occurrence(s) restored" in item.value for item in app.success)

        assert [metric.value for metric in app.metric] == ["1", "1", "1", "Not tracked"]
        assert len(app.dataframe) == 1

        app.radio[0].set_value("Analytics").run(timeout=15)
        assert [metric.value for metric in app.metric] == [
            "1",
            "1",
            "1",
            "Not tracked",
            "99.6%",
            "100.0%",
            "99.8%",
            "100.0%",
        ]
        assert any("50 documents" in item.value for item in app.caption)
        assert len(app.dataframe) == 1
        app.radio[0].set_value("Audit Logs").run(timeout=15)
        assert len(app.dataframe) == 1
        app.radio[0].set_value("Privacy Gateway").run(timeout=15)
        app.button(key="clear_button").click().run(timeout=15)
        assert app.text_area(key="original_text").value == ""
        assert app.text_area[1].value == ""
        assert app.button(key="send_button").disabled
        assert get.call_count >= 18


def test_dashboard_renders_structured_records_and_keeps_raw_response_collapsed() -> None:
    record_response = (
        "Record 1: Applicant [PERSON_1], phone [PHONE_1], PAN [PAN_1], "
        "address [ADDRESS_1], salary INR 85,000.\n"
        "Record 2: Applicant [PERSON_2], phone [PHONE_2], Aadhaar [AADHAAR_2], "
        "address [ADDRESS_2]."
    )

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        if url.endswith("/api/scan"):
            return _response(
                {
                    "request_id": REQUEST_ID,
                    "sanitized_text": "Analyze these masked records.",
                    "entity_count": 0,
                    "entity_types": [],
                    "duration_ms": 1.0,
                    "validation": _validation_response(),
                }
            )
        if url.endswith("/api/complete"):
            return _response(
                {
                    "response": record_response,
                    "display_response": record_response,
                    "provider": "mock",
                }
            )
        raise AssertionError(f"Unexpected API request: {url}")

    with patch("httpx.post", side_effect=fake_post), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value("Analyze these masked records.").run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)
        app.button(key="send_button").click().run(timeout=15)

        assert not app.exception
        metric_values = {item.label: item.value for item in app.metric}
        assert metric_values["Records found"] == "2"
        assert metric_values["Masked entities"] == "8"
        assert metric_values["Records displayed"] == "2"
        assert app.expander[0].label == "Record 1  ·  [PERSON_1]"
        assert app.expander[1].label == "Record 2  ·  [PERSON_2]"
        assert app.expander[-1].label == "View technical response"

        app.text_input(key="response_record_search").set_value("[PAN_1]").run(timeout=15)
        filtered_metrics = {item.label: item.value for item in app.metric}
        assert filtered_metrics["Records displayed"] == "1"
        assert [item.label for item in app.expander if item.label.startswith("Record")] == [
            "Record 1  ·  [PERSON_1]"
        ]

        app.text_input(key="response_record_search").set_value("")
        app.selectbox(key="response_entity_filter").set_value("AADHAAR").run(timeout=15)
        assert [item.label for item in app.expander if item.label.startswith("Record")] == [
            "Record 2  ·  [PERSON_2]"
        ]

        app.selectbox(key="response_entity_filter").set_value("All entity types")
        app.selectbox(key="response_number_filter").set_value(1).run(timeout=15)
        assert [item.label for item in app.expander if item.label.startswith("Record")] == [
            "Record 1  ·  [PERSON_1]"
        ]


@pytest.mark.parametrize(
    ("invalid_text", "sanitized_text", "entity_type", "field", "message"),
    [
        (
            "Mobile: 12345",
            "Mobile: [PHONE_1]",
            "PHONE",
            "Indian mobile number",
            "Enter a 10-digit Indian mobile number, optionally prefixed by +91.",
        ),
        (
            "Aadhaar: 2345 6789 0123",
            "Aadhaar: [AADHAAR_1]",
            "AADHAAR",
            "Aadhaar",
            "Enter a 12-digit Aadhaar value with a valid checksum.",
        ),
    ],
)
def test_dashboard_displays_validation_warning_and_allows_masked_workflow(
    invalid_text: str,
    sanitized_text: str,
    entity_type: str,
    field: str,
    message: str,
) -> None:
    completion_response = f"Review {sanitized_text}."

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        if url.endswith("/api/scan"):
            assert kwargs["json"] == {"text": invalid_text}
            return _response(
                {
                    "request_id": REQUEST_ID,
                    "sanitized_text": sanitized_text,
                    "entity_count": 1,
                    "entity_types": [entity_type],
                    "duration_ms": 1.0,
                    "validation": {
                        "fields": [
                            {
                                "field": field,
                                "status": "invalid",
                                "message": message,
                            }
                        ],
                        "summary": "1 invalid and 0 missing labeled field(s); sensitive values will still be masked.",
                        "valid_count": 0,
                        "invalid_count": 1,
                        "missing_count": 0,
                        "uncertain_count": 0,
                    },
                }
            )
        if url.endswith("/api/complete"):
            assert kwargs["json"] == {"request_id": REQUEST_ID}
            return _response(
                {
                    "response": completion_response,
                    "display_response": completion_response,
                    "provider": "mock",
                }
            )
        raise AssertionError(f"Unexpected API request: {url}")

    with patch("httpx.post", side_effect=fake_post), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value(invalid_text).run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any(
            "Invalid sensitive data detected" in item.value for item in app.markdown
        )
        assert any(field in item.value for item in app.caption)
        assert all(invalid_text not in item.value for item in app.caption)
        assert app.text_area[1].value == sanitized_text
        assert not app.button(key="send_button").disabled
        app.button(key="send_button").click().run(timeout=15)
        assert not app.exception
        assert app.session_state["final_response"] == completion_response
        assert invalid_text not in app.session_state["final_response"]


def test_dashboard_compact_validation_summary_deduplicates_details() -> None:
    invalid_text = "Aadhaar: 2345 6789 0123; Aadhaar: 2345 6789 0123"

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        if not url.endswith("/api/scan"):
            raise AssertionError(f"Unexpected API request: {url}")
        return _response(
            {
                "request_id": REQUEST_ID,
                "sanitized_text": "Aadhaar: [AADHAAR_1]; Aadhaar: [AADHAAR_1]",
                "entity_count": 1,
                "entity_types": ["AADHAAR"],
                "duration_ms": 1.0,
                "validation": {
                    "fields": [
                        {
                            "field": "Aadhaar",
                            "status": "invalid",
                            "message": "Enter a 12-digit Aadhaar value with a valid checksum.",
                        },
                        {
                            "field": "Aadhaar",
                            "status": "invalid",
                            "message": "Enter a 12-digit Aadhaar value with a valid checksum.",
                        },
                    ],
                    "summary": "2 invalid fields.",
                    "valid_count": 0,
                    "invalid_count": 2,
                    "missing_count": 0,
                    "uncertain_count": 0,
                },
            }
        )

    with patch("httpx.post", side_effect=fake_post), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value(invalid_text).run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any(
            "Invalid sensitive data detected" in item.value for item in app.markdown
        )
        assert app.expander[0].label == "View details"
        messages = [
            item.value
            for item in app.caption
            if "12-digit Aadhaar" in item.value
        ]
        assert len(messages) == 1
        assert invalid_text not in app.text_area[1].value
        assert invalid_text not in str(messages)


def test_dashboard_shows_compact_attention_count_for_distinct_fields() -> None:
    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        if not url.endswith("/api/scan"):
            raise AssertionError(f"Unexpected API request: {url}")
        return _response(
            {
                "request_id": REQUEST_ID,
                "sanitized_text": "Applicant [PERSON_1]; phone [PHONE_1]",
                "entity_count": 2,
                "entity_types": ["PERSON", "PHONE"],
                "duration_ms": 1.0,
                "validation": {
                    "fields": [
                        {
                            "field": "Person name",
                            "status": "uncertain",
                            "message": "Only one name component was found; confirm it is complete.",
                        },
                        {
                            "field": "Indian mobile number",
                            "status": "missing",
                            "message": "Indian mobile number is labeled but has no value.",
                        },
                    ],
                    "summary": "Fields need review.",
                    "valid_count": 0,
                    "invalid_count": 0,
                    "missing_count": 1,
                    "uncertain_count": 1,
                },
            }
        )

    with patch("httpx.post", side_effect=fake_post), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value("Applicant Asha; mobile:").run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any("2 fields need attention" in item.value for item in app.markdown)
        assert app.expander[0].label == "View details"


def test_dashboard_error_messages_do_not_echo_sensitive_input() -> None:
    def failed_scan(url: str, **kwargs: object) -> httpx.Response:
        assert kwargs["json"] == {"text": ORIGINAL_TEXT}
        return _response({"detail": ORIGINAL_TEXT}, status_code=400)

    with patch("httpx.post", side_effect=failed_scan), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value(ORIGINAL_TEXT).run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any("Scan was rejected" in item.value for item in app.error)
        assert all(ORIGINAL_TEXT not in item.value for item in app.error)
        assert app.text_area[1].value == ""
        assert app.button(key="send_button").disabled


def test_dashboard_reports_invalid_backend_response_without_details() -> None:
    with patch("httpx.post", return_value=_response({"detail": "sensitive-detail"})), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value(ORIGINAL_TEXT).run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any("invalid scan response" in item.value for item in app.error)
        assert all("sensitive-detail" not in item.value for item in app.error)


def test_dashboard_reports_backend_connection_failure_safely() -> None:
    with patch("httpx.post", side_effect=httpx.ConnectError("sensitive request content")), patch(
        "httpx.get", side_effect=_dashboard_get
    ):
        app = AppTest.from_file(str(DASHBOARD_PATH)).run(timeout=15)
        app.text_area(key="original_text").set_value(ORIGINAL_TEXT).run(timeout=15)
        app.button(key="scan_button").click().run(timeout=15)

        assert not app.exception
        assert any("Could not connect to the privacy backend" in item.value for item in app.error)
        assert all(ORIGINAL_TEXT not in item.value for item in app.error)
