"""PrivacyShield AI Streamlit dashboard."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sys

import httpx
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[2]
project_root_string = str(PROJECT_ROOT)
if project_root_string in sys.path:
    sys.path.remove(project_root_string)
sys.path.insert(0, project_root_string)

from app.config import dashboard_api_key, dashboard_api_url
from app.frontend.response_parser import (
    count_masked_entities,
    filter_response_records,
    parse_response_records,
)
from app.validation.document_extraction import DocumentExtractionError, extract_document_text

API_URL = dashboard_api_url()
API_KEY = dashboard_api_key()
API_HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}
REQUEST_TIMEOUT_SECONDS = 60
COMPLETION_TIMEOUT_SECONDS = 90
DEMO_TEXT = (
    "Please review this fictional loan application for applicant: Asha Mehta. "
    "Phone: +91 98765 43210, Aadhaar: 2345 6700 0019, PAN: ABCPE1234F. "
    "Address: 42, Sample Residency, Pune, Maharashtra. "
    "Account number: 123456789012; monthly salary: INR 85,000."
)


def _api_error_message(status_code: int, operation: str) -> str:
    if status_code == 400:
        return f"{operation} was rejected. Check the input and try again."
    if status_code == 404:
        return "This scan is no longer available. Scan the input again."
    if status_code == 502:
        return "The AI provider could not complete the request. Check its configuration and try again."
    if status_code == 503:
        if operation == "AI request":
            return "The AI provider is not configured. Check the backend configuration."
        return "Backend API authentication is not configured. Set PRIVACYSHIELD_API_KEY in .env."
    if status_code >= 500:
        return f"{operation} could not be completed because of a backend error."
    return f"{operation} was unsuccessful (HTTP {status_code}). Please try again."


def _require_object(payload: object, required_fields: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(payload, dict) or any(field not in payload for field in required_fields):
        raise ValueError("The backend response did not match the expected format.")
    return payload


def _parse_scan_response(payload: object) -> dict[str, object]:
    result = _require_object(
        payload,
        (
            "request_id",
            "sanitized_text",
            "entity_count",
            "entity_types",
            "duration_ms",
            "validation",
        ),
    )
    if (
        not isinstance(result["request_id"], str)
        or not result["request_id"]
        or not isinstance(result["sanitized_text"], str)
        or not isinstance(result["entity_count"], int)
        or isinstance(result["entity_count"], bool)
        or not isinstance(result["entity_types"], list)
        or any(not isinstance(entity, str) for entity in result["entity_types"])
        or not isinstance(result["duration_ms"], (int, float))
        or isinstance(result["duration_ms"], bool)
    ):
        raise ValueError("The backend response did not match the expected format.")
    result["validation"] = _parse_validation_response(result["validation"])
    return result


def _parse_validation_response(payload: object) -> dict[str, object]:
    result = _require_object(
        payload,
        (
            "fields",
            "summary",
            "valid_count",
            "invalid_count",
            "missing_count",
            "uncertain_count",
        ),
    )
    fields = result["fields"]
    allowed_statuses = {"valid", "invalid", "missing", "uncertain"}
    if (
        not isinstance(fields, list)
        or not isinstance(result["summary"], str)
        or any(
            not isinstance(result[key], int)
            or isinstance(result[key], bool)
            or result[key] < 0
            for key in ("valid_count", "invalid_count", "missing_count", "uncertain_count")
        )
    ):
        raise ValueError("The backend response did not match the expected format.")
    for field in fields:
        if (
            not isinstance(field, dict)
            or not isinstance(field.get("field"), str)
            or field.get("status") not in allowed_statuses
            or not isinstance(field.get("message"), str)
        ):
            raise ValueError("The backend response did not match the expected format.")
    return result


def _validation_display(
    validation: dict[str, object],
) -> tuple[str, str, list[dict[str, str]]]:
    fields = validation["fields"]
    if not isinstance(fields, list):
        raise ValueError("The backend response did not match the expected format.")

    details: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for field in fields:
        if not isinstance(field, dict):
            continue
        field_name = field.get("field")
        status = field.get("status")
        message = field.get("message")
        if not all(isinstance(value, str) for value in (field_name, status, message)):
            continue
        if status not in {"invalid", "missing", "uncertain"}:
            continue
        key = (field_name, status, message)
        if key not in seen:
            details.append({"field": field_name, "status": status, "message": message})
            seen.add(key)

    attention_fields = {item["field"] for item in details}
    if any(item["status"] == "invalid" for item in details):
        return "error", "Invalid sensitive data detected", details
    if attention_fields:
        return "warning", f"{len(attention_fields)} fields need attention", details
    return "success", "All detected fields are valid", []


def _render_provider_response(response: str) -> None:
    records = parse_response_records(response)
    if not records:
        st.info(response)
        return

    st.markdown("#### Structured records")
    total_col, entity_col, shown_col = st.columns(3)
    total_col.metric("Records found", len(records))
    entity_col.metric("Masked entities", count_masked_entities(response))

    filter_col, record_col = st.columns([2, 1])
    query = filter_col.text_input(
        "Search by name or placeholder ID",
        key="response_record_search",
        placeholder="Search [PERSON_12] or [PAN_4]…",
    )
    entity_types = sorted({entity for record in records for entity in record.entity_types})
    selected_entity = filter_col.selectbox(
        "Entity type",
        ["All entity types", *entity_types],
        key="response_entity_filter",
    )
    record_options: list[int | None] = [None, *sorted({record.number for record in records})]
    selected_record = record_col.selectbox(
        "Record number",
        record_options,
        format_func=lambda value: "All records" if value is None else f"Record {value}",
        key="response_number_filter",
    )
    visible_records = filter_response_records(
        records,
        query=query,
        entity_type=selected_entity,
        record_number=selected_record,
    )
    shown_col.metric("Records displayed", len(visible_records))

    if not visible_records:
        st.caption("No records match the current search and filters.")
    for record in visible_records:
        person_label = record.person or "Name not detected"
        with st.expander(
            f"Record {record.number}  ·  {person_label}",
            expanded=False,
        ):
            detail_col, identity_col = st.columns(2)
            detail_col.markdown(f"**Name**  \n{record.person or '—'}")
            detail_col.markdown(
                "**Mobile**  \n"
                + (record.phone_placeholder or "—")
            )
            identity_col.markdown(
                "**PAN**  \n"
                + (record.pan_placeholder or "—")
            )
            detail_col.markdown(
                "**Aadhaar**  \n"
                + (record.aadhaar_placeholder or "—")
            )
            identity_col.markdown(
                "**Address**  \n"
                + (record.address_placeholder or "—")
            )
            st.markdown(f"**Salary**  \n{record.salary or '—'}")

def _parse_completion_response(payload: object) -> dict[str, str]:
    result = _require_object(payload, ("response", "display_response", "provider"))
    if (
        not isinstance(result["response"], str)
        or not isinstance(result["display_response"], str)
        or not isinstance(result["provider"], str)
        or not result["provider"]
    ):
        raise ValueError("The backend response did not match the expected format.")
    return {
        "response": result["response"],
        "display_response": result["display_response"],
        "provider": result["provider"],
    }


def _parse_reidentification_response(payload: object) -> dict[str, object]:
    result = _require_object(payload, ("response", "restored_count"))
    if (
        not isinstance(result["response"], str)
        or not isinstance(result["restored_count"], int)
        or isinstance(result["restored_count"], bool)
        or result["restored_count"] < 0
    ):
        raise ValueError("The backend response did not match the expected format.")
    return result


def _parse_metrics_response(payload: object) -> dict[str, int]:
    result = _require_object(payload, ("scans", "entities_masked", "completions"))
    if any(
        not isinstance(result[key], int) or isinstance(result[key], bool)
        for key in ("scans", "entities_masked", "completions")
    ):
        raise ValueError("The backend response did not match the expected format.")
    return {key: result[key] for key in ("scans", "entities_masked", "completions")}


def _parse_evaluation_response(payload: object) -> dict[str, int | float]:
    count_fields = (
        "document_count",
        "positive_document_count",
        "negative_document_count",
        "labeled_entity_count",
        "true_positives",
        "false_positives",
        "false_negatives",
        "correctly_masked_entities",
        "sanitized_payload_leakage_count",
        "provider_input_leakage_count",
        "raw_ai_response_leakage_count",
        "privacy_leakage_count",
    )
    score_fields = (
        "precision",
        "recall",
        "f1",
        "placeholder_masking_accuracy",
        "privacy_leakage_rate",
    )
    result = _require_object(payload, count_fields + score_fields)
    if any(
        not isinstance(result[key], int)
        or isinstance(result[key], bool)
        or result[key] < 0
        for key in count_fields
    ):
        raise ValueError("The backend response did not match the expected format.")
    if any(
        not isinstance(result[key], (int, float))
        or isinstance(result[key], bool)
        or not 0 <= result[key] <= 1
        for key in score_fields
    ):
        raise ValueError("The backend response did not match the expected format.")
    return {key: result[key] for key in count_fields + score_fields}


def _parse_audit_response(payload: object) -> list[dict[str, object]]:
    result = _require_object(payload, ("logs",))
    logs = result["logs"]
    if not isinstance(logs, list) or any(not isinstance(item, dict) for item in logs):
        raise ValueError("The backend response did not match the expected format.")
    required_fields = (
        "created_at",
        "event",
        "entity_types",
        "entity_count",
        "provider",
        "model",
        "success",
    )
    if any(any(field not in item for field in required_fields) for item in logs):
        raise ValueError("The backend response did not match the expected format.")
    if any(
        not isinstance(item["created_at"], str)
        or not isinstance(item["event"], str)
        or not isinstance(item["entity_types"], list)
        or any(not isinstance(entity, str) for entity in item["entity_types"])
        or not isinstance(item["entity_count"], int)
        or isinstance(item["entity_count"], bool)
        or (item["provider"] is not None and not isinstance(item["provider"], str))
        or (item["model"] is not None and not isinstance(item["model"], str))
        or not isinstance(item["success"], bool)
        for item in logs
    ):
        raise ValueError("The backend response did not match the expected format.")
    return logs


def _clear_workspace() -> None:
    st.session_state.original_text = ""
    st.session_state.sanitized_text = ""
    st.session_state.request_id = ""
    st.session_state.final_response = ""
    st.session_state.display_response = ""
    st.session_state.reidentified_response = ""
    st.session_state.scan_summary = None
    st.session_state.validation_report = None
    st.session_state.reidentify_authorized = False


def _fetch_backend_status() -> tuple[bool, str]:
    try:
        response = httpx.get(f"{API_URL}/api/health", timeout=5)
        if response.is_error:
            return False, "Backend returned an error"
        payload = response.json()
        if isinstance(payload, dict) and payload.get("status") == "ok":
            return True, "Backend connected"
        return False, "Unexpected backend response"
    except (httpx.RequestError, ValueError):
        return False, "Backend unavailable"


def _render_metrics(metrics: dict[str, int]) -> None:
    columns = st.columns(4)
    labels = (
        ("Total Scans", metrics["scans"], "◈"),
        ("Entities Masked", metrics["entities_masked"], "♡"),
        ("AI Calls", metrics["completions"], "✧"),
        ("Privacy Leakage Count", "Not tracked", "⊘"),
    )
    for column, (label, value, icon) in zip(columns, labels):
        with column:
            with st.container(border=True):
                st.caption(f"{icon}  {label}")
                st.metric(label, value, label_visibility="collapsed")


def _render_audit(logs: list[dict[str, object]]) -> None:
    if not logs:
        st.caption("No audit events yet. Scan a request to begin.")
        return
    rows = [
        {
            "Time": datetime.fromisoformat(item["created_at"]).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "Event": item["event"],
            "Entities": ", ".join(item["entity_types"]) or "—",
            "Count": item["entity_count"],
            "Provider": item["provider"] or "—",
            "Model": item["model"] or "—",
            "Status": "♡ Success" if item["success"] else "✧ Failed",
        }
        for item in logs
    ]
    st.dataframe(rows, width="stretch", hide_index=True)


st.set_page_config(page_title="PrivacyShield AI", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    :root {
        color-scheme: dark;
        --ink: #100B12;
        --plum: #1B121F;
        --pink: #FF4F9A;
        --rose: #D98AAE;
        --crimson: #8B1538;
        --lavender: #C7A4FF;
        --white: #F8EDF5;
        --muted: #B9A5B5;
        --line: rgba(255, 79, 154, .22);
    }
    .stApp {
        background:
            radial-gradient(ellipse at 82% 4%, rgba(139, 21, 56, .19), transparent 34rem),
            radial-gradient(ellipse at 12% 48%, rgba(199, 164, 255, .055), transparent 38rem),
            var(--ink);
        color: var(--white);
    }
    [data-testid="stHeader"] { background: rgba(16, 11, 18, .78); }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1B121F 0%, #140D17 100%);
        border-right: 1px solid var(--line);
    }
    [data-testid="stSidebar"] > div:first-child { padding-top: 1.7rem; }
    .block-container { max-width: 1440px; padding: 2.2rem 2rem 4rem; }
    h1, h2, h3, h4 {
        color: var(--white) !important;
        font-family: Georgia, "Times New Roman", serif !important;
        letter-spacing: -.025em;
    }
    p, label, li, [data-testid="stCaptionContainer"] {
        color: var(--muted);
    }
    .brand-mark {
        color: var(--pink); font: 700 1.55rem Georgia, serif; letter-spacing: -.04em;
        text-shadow: 0 0 22px rgba(255,79,154,.4); margin: .35rem 0 0;
    }
    .brand-subtitle {
        color: var(--rose); font-size: .88rem; letter-spacing: .04em;
        margin: .25rem 0 1.2rem;
    }
    .sidebar-label {
        color: var(--muted); font-size: .68rem; letter-spacing: .2em;
        text-transform: uppercase; margin: 1.4rem 0 .4rem;
    }
    .connection-pill {
        display: inline-flex; align-items: center; gap: .55rem;
        padding: .5rem .75rem; border: 1px solid var(--line); border-radius: 999px;
        color: var(--muted); background: rgba(255,255,255,.025); font-size: .78rem;
    }
    .connection-dot {
        height: 8px; width: 8px; border-radius: 50%; display: inline-block;
        background: var(--rose); box-shadow: 0 0 10px currentColor;
    }
    .connection-dot.online { background: #FF7EAE; }
    .connection-dot.offline { background: #D86B75; }
    .hero {
        position: relative; overflow: hidden; padding: 2.05rem 2.2rem;
        border: 1px solid rgba(255,79,154,.3); border-radius: 22px;
        color: var(--white); margin: .1rem 0 1.5rem;
        background:
            radial-gradient(ellipse at 95% 0%, rgba(255,79,154,.19), transparent 25rem),
            linear-gradient(115deg, rgba(27,18,31,.98), rgba(54,14,34,.88) 65%, rgba(91,17,45,.8));
        box-shadow: 0 18px 55px rgba(0,0,0,.2), inset 0 1px rgba(255,255,255,.035);
    }
    .hero:after {
        content: "✧  ♡  ✧"; position: absolute; right: 2rem; top: 1.2rem;
        color: rgba(255,185,216,.34); letter-spacing: .65rem; font-size: 1rem;
    }
    .hero h1 {
        margin: .8rem 0 .45rem; font-size: clamp(2rem, 4vw, 3.2rem);
        line-height: 1.13; text-shadow: 0 0 28px rgba(255,79,154,.22);
    }
    .hero p { margin: 0; color: #E5C8D7; font-size: 1.03rem; }
    .engine-badge {
        display: inline-flex; align-items: center; gap: .45rem;
        border: 1px solid rgba(255,79,154,.42); border-radius: 999px;
        padding: .38rem .72rem; color: #FFC2DC; background: rgba(255,79,154,.09);
        font: 600 .68rem system-ui, sans-serif; letter-spacing: .13em;
    }
    .section-heading {
        display: flex; align-items: baseline; gap: .65rem; margin: .4rem 0 .2rem;
        color: var(--white); font: 600 1.55rem Georgia, serif;
    }
    .section-kicker {
        color: var(--rose); font: 600 .68rem system-ui, sans-serif;
        letter-spacing: .18em; text-transform: uppercase; margin: 0 0 1rem;
    }
    [data-testid="stVerticalBlockBorderWrapper"] {
        border-color: var(--line) !important; border-radius: 18px !important;
        background: linear-gradient(145deg, rgba(34,21,38,.96), rgba(24,15,28,.98));
        box-shadow: 0 12px 32px rgba(0,0,0,.16);
    }
    [data-testid="stTextArea"] textarea {
        background: #120D15 !important; color: var(--white) !important;
        border: 1px solid rgba(217,138,174,.24) !important; border-radius: 12px !important;
        line-height: 1.6; caret-color: var(--pink);
    }
    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--pink) !important;
        box-shadow: 0 0 0 1px rgba(255,79,154,.24), 0 0 22px rgba(255,79,154,.12) !important;
    }
    [data-testid="stTextArea"] textarea:disabled { color: #D6B8C8 !important; opacity: .9; }
    div.stButton > button {
        min-height: 2.8rem; border-radius: 11px; border: 1px solid rgba(255,79,154,.4);
        color: var(--white); background: linear-gradient(110deg, #8B1538, #B42D61);
        font-weight: 650; transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease;
        box-shadow: 0 6px 18px rgba(139,21,56,.19);
    }
    div.stButton > button:hover {
        color: white; border-color: var(--pink); transform: translateY(-1px);
        box-shadow: 0 8px 25px rgba(255,79,154,.22);
    }
    div.stButton > button[kind="secondary"] {
        background: rgba(255,255,255,.025); border-color: rgba(217,138,174,.23);
        color: var(--rose); box-shadow: none;
    }
    div.stButton > button:disabled { opacity: .45; transform: none; }
    [data-testid="stMetric"] {
        padding: .5rem 0; background: transparent; border: 0;
    }
    [data-testid="stMetricLabel"] { color: var(--muted) !important; }
    [data-testid="stMetricValue"] { color: var(--white) !important; }
    [data-testid="stMetricValue"] > div {
        font-family: Georgia, "Times New Roman", serif; letter-spacing: -.03em;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid var(--line); border-radius: 12px; overflow: hidden;
    }
    [data-testid="stAlert"] { border-radius: 12px; }
    .validation-summary {
        display: flex; align-items: center; gap: .55rem; margin: .25rem 0 .45rem;
        font: 650 .88rem system-ui, sans-serif; letter-spacing: .01em;
    }
    .validation-summary.success { color: #8FE0B2; }
    .validation-summary.warning { color: #F3C46B; }
    .validation-summary.error { color: #FF8A9B; }
    .validation-summary-icon {
        display: inline-flex; align-items: center; justify-content: center;
        height: 1.25rem; width: 1.25rem; border-radius: 50%;
        border: 1px solid currentColor; font-size: .75rem;
    }
    [data-testid="stExpander"] {
        margin: .15rem 0 .45rem; border: 1px solid rgba(217,138,174,.18);
        border-radius: 10px; background: rgba(18,13,21,.45);
    }
    [data-testid="stRadio"] label { color: #E7D5E1 !important; }
    [data-testid="stRadio"] label:hover { color: var(--pink) !important; }
    hr { border-color: rgba(255,79,154,.16) !important; }
    @media (max-width: 760px) {
        .block-container { padding: 1.2rem 1rem 3rem; }
        .hero { padding: 1.55rem 1.35rem; }
        .hero:after { right: 1rem; top: .8rem; letter-spacing: .25rem; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "original_text" not in st.session_state:
    st.session_state.original_text = DEMO_TEXT
if "sanitized_text" not in st.session_state:
    st.session_state.sanitized_text = ""
if "request_id" not in st.session_state:
    st.session_state.request_id = ""
if "final_response" not in st.session_state:
    st.session_state.final_response = ""
if "display_response" not in st.session_state:
    st.session_state.display_response = ""
if "reidentified_response" not in st.session_state:
    st.session_state.reidentified_response = ""
if "scan_summary" not in st.session_state:
    st.session_state.scan_summary = None
if "validation_report" not in st.session_state:
    st.session_state.validation_report = None
if "reidentify_authorized" not in st.session_state:
    st.session_state.reidentify_authorized = False

backend_connected, backend_status = _fetch_backend_status()
metrics: dict[str, int] | None = None
audit_logs: list[dict[str, object]] | None = None
metrics_error: str | None = None
audit_error: str | None = None
try:
    response = httpx.get(f"{API_URL}/api/metrics", headers=API_HEADERS, timeout=10)
    if response.is_error:
        metrics_error = _api_error_message(response.status_code, "Privacy metrics")
    else:
        metrics = _parse_metrics_response(response.json())
except httpx.RequestError:
    metrics_error = "Privacy metrics are unavailable because the backend could not be reached."
except (ValueError, TypeError):
    metrics_error = "Privacy metrics are unavailable because the backend returned invalid data."

try:
    response = httpx.get(f"{API_URL}/api/audit", headers=API_HEADERS, timeout=10)
    if response.is_error:
        audit_error = _api_error_message(response.status_code, "Local audit log")
    else:
        audit_logs = _parse_audit_response(response.json())
except httpx.RequestError:
    audit_error = "Local audit logs are unavailable because the backend could not be reached."
except (ValueError, TypeError):
    audit_error = "Local audit logs are unavailable because the backend returned invalid data."

with st.sidebar:
    st.markdown('<div class="brand-mark">♜ PrivacyShield AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-subtitle">Your secrets stay yours ♡</div>', unsafe_allow_html=True)
    st.divider()
    st.markdown('<div class="sidebar-label">Navigate</div>', unsafe_allow_html=True)
    page = st.radio(
        "Dashboard section",
        ("Privacy Gateway", "Analytics", "Audit Logs"),
        label_visibility="collapsed",
    )
    st.markdown('<div class="sidebar-label">Gateway status</div>', unsafe_allow_html=True)
    status_class = "online" if backend_connected else "offline"
    status_icon = "✦" if backend_connected else "♡"
    st.markdown(
        f'<div class="connection-pill"><span class="connection-dot {status_class}"></span>'
        f'{status_icon} {backend_status}</div>',
        unsafe_allow_html=True,
    )
    st.caption("Original text and encrypted mappings stay on your local backend.")
    st.divider()
    st.caption("✧  Local-first · Private by design")

st.markdown(
    """
    <div class="hero">
      <span class="engine-badge">♡ &nbsp; PRIVACY ENGINE ACTIVE</span>
      <h1>Your Data. Your Secrets. Protected. ♡</h1>
      <p>A little layer of privacy between you and the AI.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if page == "Privacy Gateway":
    st.markdown('<div class="section-heading">♧  The privacy gateway</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-kicker">Your prompt stays yours until it is safely masked</div>',
        unsafe_allow_html=True,
    )
    original_col, sanitized_col = st.columns(2, gap="large")
    with original_col:
        with st.container(border=True):
            st.markdown("### ♡ Original Input")
            st.caption("Enter the text you want to send. Sensitive values are masked before the AI call.")
            uploaded_file = st.file_uploader(
                "Upload a TXT, PDF, or DOCX document",
                type=["txt", "pdf", "docx"],
                key="document_upload",
            )
            if st.button(
                "Extract document text locally",
                width="stretch",
                disabled=uploaded_file is None,
                key="extract_document_button",
            ):
                if uploaded_file is not None:
                    try:
                        st.session_state.original_text = extract_document_text(
                            uploaded_file.name,
                            uploaded_file.getvalue(),
                        )
                        st.session_state.validation_report = None
                        st.session_state.sanitized_text = ""
                        st.session_state.request_id = ""
                        st.success("Document text extracted locally. Review it before scanning.")
                    except DocumentExtractionError as error:
                        st.error(str(error))
            st.text_area(
                "Text to inspect",
                key="original_text",
                height=230,
                label_visibility="collapsed",
                placeholder="Paste a request or prompt to scan for sensitive data…",
            )
            scan_col, clear_col = st.columns([3, 1], gap="small")
            with scan_col:
                if st.button(
                    "♡  Scan & Mask",
                    type="primary",
                    width="stretch",
                    key="scan_button",
                ):
                    st.session_state.sanitized_text = ""
                    st.session_state.request_id = ""
                    st.session_state.final_response = ""
                    st.session_state.display_response = ""
                    st.session_state.reidentified_response = ""
                    st.session_state.scan_summary = None
                    st.session_state.validation_report = None
                    st.session_state.reidentify_authorized = False
                    try:
                        with st.spinner("Scanning and masking sensitive information..."):
                            response = httpx.post(
                                f"{API_URL}/api/scan",
                                json={"text": st.session_state.original_text},
                                headers=API_HEADERS,
                                timeout=REQUEST_TIMEOUT_SECONDS,
                            )
                            if response.is_error:
                                if response.status_code == 400 and not st.session_state.original_text.strip():
                                    st.session_state.validation_report = {
                                        "fields": [
                                            {
                                                "field": "Input text",
                                                "status": "missing",
                                                "message": "Enter text to scan.",
                                            }
                                        ],
                                        "summary": "Input text is required.",
                                        "valid_count": 0,
                                        "invalid_count": 0,
                                        "missing_count": 1,
                                        "uncertain_count": 0,
                                    }
                                    st.error("Missing — Enter text to scan.")
                                else:
                                    st.error(_api_error_message(response.status_code, "Scan"))
                            else:
                                scan_result = _parse_scan_response(response.json())
                                st.session_state.sanitized_text = scan_result["sanitized_text"]
                                st.session_state.request_id = scan_result["request_id"]
                                st.session_state.scan_summary = scan_result
                                st.session_state.validation_report = scan_result["validation"]
                                st.success(
                                    f"Privacy scan complete — detected {scan_result['entity_count']} "
                                    f"item(s): {', '.join(scan_result['entity_types']) or 'none detected'}."
                                )
                    except httpx.RequestError:
                        st.error(
                            "Could not connect to the privacy backend. Check that the backend is running."
                        )
                    except (ValueError, TypeError):
                        st.error("The backend returned an invalid scan response. Please try again.")
            validation = st.session_state.validation_report
            if validation is not None:
                status, status_text, details = _validation_display(validation)
                icon = {"success": "✓", "warning": "!", "error": "×"}[status]
                st.markdown(
                    f'<div class="validation-summary {status}">'
                    f'<span class="validation-summary-icon">{icon}</span>'
                    f'<span>{status_text}</span></div>',
                    unsafe_allow_html=True,
                )
                if details:
                    with st.expander("View details", expanded=False):
                        for item in details:
                            status_label = {
                                "invalid": "Invalid",
                                "missing": "Missing",
                                "uncertain": "Review",
                            }[item["status"]]
                            st.caption(f"{status_label} · {item['field']} — {item['message']}")
            with clear_col:
                st.button(
                    "Clear",
                    width="stretch",
                    on_click=_clear_workspace,
                    key="clear_button",
                )
    with sanitized_col:
        with st.container(border=True):
            st.markdown("### ✧ Sanitized Payload")
            st.caption("Only this protected payload is made available to the configured AI provider.")
            st.text_area(
                "Sanitized text sent to the model",
                value=st.session_state.sanitized_text,
                height=230,
                disabled=True,
                label_visibility="collapsed",
                placeholder="Scan input to see the sanitized payload.",
            )
            if st.button(
                "✧  Send to AI",
                width="stretch",
                disabled=not bool(st.session_state.request_id),
                key="send_button",
            ):
                st.session_state.final_response = ""
                st.session_state.display_response = ""
                try:
                    with st.spinner("Waiting for the AI response..."):
                        response = httpx.post(
                            f"{API_URL}/api/complete",
                            json={"request_id": st.session_state.request_id},
                            headers=API_HEADERS,
                            timeout=COMPLETION_TIMEOUT_SECONDS,
                        )
                        if response.is_error:
                            st.error(_api_error_message(response.status_code, "AI request"))
                        else:
                            completion = _parse_completion_response(response.json())
                            st.session_state.final_response = completion["response"]
                            st.session_state.display_response = completion["display_response"]
                            st.session_state.reidentified_response = ""
                            st.session_state.reidentify_authorized = False
                            st.success(f"Response received from {completion['provider']}.")
                except httpx.RequestError:
                    st.error(
                        "Could not connect to the privacy backend. Check that the backend is running."
                    )
                except (ValueError, TypeError):
                    st.error("The backend returned an invalid AI response. Please try again.")

    with st.container(border=True):
        st.markdown("### ♡ AI Results")
        if st.session_state.final_response:
            _render_provider_response(st.session_state.display_response)
            with st.expander("View technical response", expanded=False):
                st.text(st.session_state.final_response)
            st.caption("The displayed result is locally screened and masked. Restoration is opt-in.")
            authorized = st.checkbox(
                "I reviewed this raw response and authorize local restoration of known placeholders.",
                key="reidentify_authorized",
            )
            if st.button(
                "♡  Restore authorized placeholders locally",
                width="stretch",
                disabled=not authorized or not st.session_state.request_id,
                key="reidentify_button",
            ):
                try:
                    with st.spinner("Restoring authorized placeholders on the local backend..."):
                        response = httpx.post(
                            f"{API_URL}/api/reidentify",
                            json={
                                "request_id": st.session_state.request_id,
                                "raw_response": st.session_state.final_response,
                                "authorized": True,
                            },
                            headers=API_HEADERS,
                            timeout=REQUEST_TIMEOUT_SECONDS,
                        )
                        if response.is_error:
                            st.error(_api_error_message(response.status_code, "Local restoration"))
                        else:
                            restoration = _parse_reidentification_response(response.json())
                            st.session_state.reidentified_response = restoration["response"]
                            st.success(
                                f"Local restoration complete — "
                                f"{restoration['restored_count']} placeholder occurrence(s) restored."
                            )
                except httpx.RequestError:
                    st.error(
                        "Could not connect to the privacy backend. Check that the backend is running."
                    )
                except (ValueError, TypeError):
                    st.error("The backend returned an invalid restoration response. Please try again.")
            if st.session_state.reidentified_response:
                st.markdown("#### Locally re-identified response")
                st.warning(st.session_state.reidentified_response)
        else:
            st.caption("Your raw AI response will appear here after a protected request.")
        summary = st.session_state.scan_summary
        if summary:
            st.caption(
                f"Request `{summary['request_id']}` · {summary['duration_ms']} ms · "
                "Only the sanitized payload is sent to the configured provider."
            )

elif page == "Analytics":
    st.markdown('<div class="section-heading">✧  Privacy at a glance</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-kicker">Live totals from your local audit store</div>',
        unsafe_allow_html=True,
    )
    try:
        evaluation_report: dict[str, int | float] | None = None
        evaluation_error: str | None = None
        try:
            evaluation_response = httpx.get(
                f"{API_URL}/api/evaluation",
                headers=API_HEADERS,
                timeout=30,
            )
            if evaluation_response.is_error:
                evaluation_error = _api_error_message(
                    evaluation_response.status_code,
                    "Synthetic privacy evaluation",
                )
            else:
                evaluation_report = _parse_evaluation_response(evaluation_response.json())
        except httpx.RequestError:
            evaluation_error = (
                "Synthetic privacy evaluation is unavailable because the backend "
                "could not be reached."
            )
        except (ValueError, TypeError):
            evaluation_error = (
                "Synthetic privacy evaluation is unavailable because the backend "
                "returned invalid data."
            )

        if metrics_error:
            st.warning(metrics_error)
        elif metrics is not None:
            with st.container(border=True):
                _render_metrics(metrics)
            st.caption(
                "Leakage counts are not currently recorded by the backend; no estimate is shown."
            )
        st.markdown("#### ✧ Synthetic PII evaluation")
        st.caption(
            "Measured against the local detector using a fixed fictional Indian-language corpus."
        )
        if evaluation_error:
            st.warning(evaluation_error)
        elif evaluation_report is not None:
            with st.container(border=True):
                evaluation_columns = st.columns(4)
                evaluation_metrics = (
                    ("PII Precision", "precision"),
                    ("PII Recall", "recall"),
                    ("PII F1", "f1"),
                    ("Masking Accuracy", "placeholder_masking_accuracy"),
                )
                for column, (label, key) in zip(evaluation_columns, evaluation_metrics):
                    with column:
                        st.metric(label, f"{evaluation_report[key]:.1%}")
                st.caption(
                    f"{evaluation_report['document_count']} documents · "
                    f"{evaluation_report['labeled_entity_count']} labeled entities · "
                    f"{evaluation_report['true_positives']} TP · "
                    f"{evaluation_report['false_positives']} FP · "
                    f"{evaluation_report['false_negatives']} FN"
                )
                st.caption(
                    f"Privacy leakage: {evaluation_report['privacy_leakage_count']} "
                    f"labeled-value occurrences across mock-provider input and raw response "
                    f"({evaluation_report['sanitized_payload_leakage_count']} in sanitized payload)."
                )
        st.markdown("#### ♡ Recent activity")
        if audit_error:
            st.warning(audit_error)
        elif audit_logs is not None:
            with st.container(border=True):
                _render_audit(audit_logs[:10])
    except (ValueError, TypeError):
        st.warning("Analytics are temporarily unavailable because the backend returned invalid data.")

elif page == "Audit Logs":
    st.markdown('<div class="section-heading">♡  Local audit logs</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-kicker">Sensitive values are never shown in this activity trail</div>',
        unsafe_allow_html=True,
    )
    with st.container(border=True):
        if audit_error:
            st.warning(audit_error)
        elif audit_logs is not None:
            try:
                _render_audit(audit_logs)
            except (ValueError, TypeError):
                st.warning("Audit logs are unavailable because the backend returned invalid data.")

if page == "Privacy Gateway":
    st.divider()
    st.markdown('<div class="section-heading">♡  Privacy metrics</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-kicker">Totals from your local audit store</div>', unsafe_allow_html=True)
    if metrics_error:
        st.warning(metrics_error)
    elif metrics is not None:
        with st.container(border=True):
            _render_metrics(metrics)
        st.caption("Privacy leakage is not currently tracked by the backend; no value is estimated.")

    st.markdown('<div class="section-heading">✧  Audit Logs</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-kicker">A local record, without original sensitive values</div>', unsafe_allow_html=True)
    with st.container(border=True):
        if audit_error:
            st.warning(audit_error)
        else:
            try:
                _render_audit(audit_logs or [])
            except (ValueError, TypeError):
                st.warning("Audit logs are unavailable because the backend returned invalid data.")
