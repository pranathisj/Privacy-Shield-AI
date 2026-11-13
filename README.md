# PrivacyShield AI

PrivacyShield AI is a local-first privacy gateway prototype for enterprise LLM requests. It detects common PII, replaces it with request-scoped typed placeholders, and sends only the saved sanitized payload to a configurable LLM provider. Original values remain in the encrypted local mapping and are not automatically restored in provider responses.

## What works in this foundation

- Streamlit dashboard for original input, sanitized payload, final response, scan/send actions, privacy metrics, and audit events.
- FastAPI endpoints for scanning, completion, audit logs, metrics, and health.
- India-focused local detection runs before any provider call. When Presidio and the configured spaCy model are available, custom contextual recognizers detect Aadhaar (Verhoeff checksum), PAN (structure and holder category), GSTIN (format and mod-36 checksum), Voter ID/EPIC, and Indian Passport formats. Local patterns remain as a fallback and continue to protect malformed values when a relevant identifier label is present. Phone numbers require a phone-related label. Email, UPI IDs, labeled account numbers, names, and addresses are also detected. Salary, loan, and other financial amounts remain visible for analysis.
- These checks establish identifier-shaped values, not issuance, ownership, or a person's identity. Voter ID/EPIC and Passport patterns have no checksum validation, and contextual names and addresses remain heuristic.
- Optional Microsoft Presidio Analyzer enrichment uses the configured local spaCy model when installed. Presidio PERSON findings and named locations are normalized into typed PERSON and ADDRESS findings; contextual patterns cover full street addresses, while standalone locations are protected as ADDRESS. Typed placeholder replacement continues to use the local masking module; Presidio Anonymizer is not used. Local India-focused patterns remain active without Presidio or its model.
- A fixed 50-document synthetic evaluation corpus with fictional Indian identifiers, Indian-English and code-mixed examples, financial context, exact PII labels, and negative examples. Analytics reports local detection precision/recall/F1, typed masking accuracy, and leakage measured against the mock provider input and raw mock response.
- Request-local placeholder reuse, encrypted local mapping values (Fernet), and SQLite audit records without original values.
- Configurable local retention: audit events, sanitized request payloads, and their encrypted mappings are purged after `PRIVACYSHIELD_RETENTION_DAYS` (30 days by default). Deletion runs at startup and on storage operations.
- Local mock completion provider for a no-credential demo and an OpenAI-compatible API provider configured exclusively in the backend.
- Synthetic fictional demo values only.

The demo is a technical foundation, not a certification of DPDP Act compliance. Pattern detection is not a substitute for a privacy impact assessment, legal review, production key management, or defense-in-depth controls.

## Smart input validation and document extraction

The dashboard validates supported fields that are explicitly labeled or detected by the local PII detector; it does not report absent, unentered fields. It reports valid, invalid, missing, or uncertain status without echoing entered values. A compact green/amber/red summary appears by Scan & Mask, with deduplicated individual messages in a “View details” expander. Validation is advisory for processing: invalid or missing values still go through local detection and masking, and the dashboard permits sending only the saved sanitized payload to AI while displaying validation warnings. Uncertain fields are shown for review.

TXT, selectable-text PDF, and DOCX uploads are extracted locally before scanning. Uploads are limited to 10 MB; PDFs are limited to 100 pages, and DOCX extraction applies archive size and entry limits. Scanned PDFs require OCR, which is not enabled. Extracted content follows the same validation, detection, and masking workflow as manually entered text.

## Requirements

- Python 3.14 (or a recent Python 3 release supported by the installed dependencies)
- pip

## Setup

From the project directory in PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

The first scan initializes local storage and creates `data/.mapping.key` if `PRIVACYSHIELD_ENCRYPTION_KEY` is not set. Keep that key file private and backed up if stored mappings must remain readable after restart. Never commit it. For production, provide a Fernet key through a secret manager/environment variable and secure the host, database, backups, and access controls.

Set `PRIVACYSHIELD_RETENTION_DAYS` in `.env` to a non-negative integer. The default is `30`; `0` expires local audit, request, and mapping records on the next storage operation. SQLite secure-delete is enabled for local row deletion, but it does not erase external backups, filesystem snapshots, or database copies.

Set `PRIVACYSHIELD_API_KEY` in `.env` before starting the backend or dashboard. Generate a development key with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated value into the `PRIVACYSHIELD_API_KEY` entry in `.env`. The Streamlit server reads this key locally and attaches it to server-to-server API requests; it is not rendered into the dashboard or sent by the browser. The backend fails closed with HTTP 503 when no key is configured and returns HTTP 401 for a missing or invalid request key. Keep `/api/health` public for the dashboard's connection indicator; scan, completion, restoration, audit, and metrics routes require `X-API-Key`. This mechanism is for local development and does not replace production identity, rotation, or secret-management controls.

To enable Presidio's additional named-entity detection, install the configured spaCy model:

```powershell
python -m spacy download en_core_web_sm
```

If that model is unavailable, the backend logs a warning and continues with India-focused local pattern detection. Set `PRESIDIO_ENABLED=false` to disable the optional enrichment explicitly.

## Run

Open two PowerShell terminals in the project directory and activate the virtual environment in each.

Terminal 1 — backend:

```powershell
uvicorn app.backend.api:app --reload
```

Terminal 2 — dashboard:

```powershell
streamlit run app/frontend/dashboard.py
```

Open the Streamlit URL printed by the command (normally `http://localhost:8501`). The sample is synthetic. With `LLM_PROVIDER=mock`, Scan & Mask and Send to AI work without a remote API key. To use an OpenAI-compatible service, set `LLM_PROVIDER=openai-compatible`, `LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL` in the backend's `.env`, then restart the backend. The backend reads the provider key from its process environment or `.env`; credentials are never returned by its API or included in settings representations. The provider receives only the sanitized request text loaded by scan ID. The dashboard renders a locally screened, masked display response and structures multi-record responses for search; the original provider response is kept in a collapsed “View technical response” expander. Local detection is not a guarantee against every possible sensitive value. Original scan values are restored only on the local backend after a separate explicit authorization. Automated provider tests use mocked HTTP responses and do not verify a real external API call.

The dashboard defaults to `http://127.0.0.1:8000`; if the backend runs elsewhere, set `PRIVACYSHIELD_API_URL` in the dashboard terminal before starting Streamlit. The dashboard reads only this URL from its process environment and does not load backend `.env` secrets.

## API

- `GET /api/health`
- `POST /api/scan` with `{"text":"..."}` and `X-API-Key`
- `POST /api/complete` with `{"request_id":"<scan request id>"}` and `X-API-Key`; the backend fetches the previously stored sanitized payload instead of accepting arbitrary text and returns the raw provider `response`, a locally detected/masked `display_response` for the dashboard, and provider metadata.
- `POST /api/reidentify` with `{"request_id":"<scan request id>","raw_response":"...","authorized":true}` and `X-API-Key`; exact known placeholders are restored from the encrypted local mapping only after explicit user confirmation. Unknown or malformed placeholders are preserved.
- `GET /api/audit?limit=50` and `GET /api/metrics` require `X-API-Key`.
- `GET /api/evaluation` requires `X-API-Key` and returns aggregate-only results for the bundled synthetic corpus.

Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

## Tests

```powershell
python -m pytest -q
```

Tests cover India-specific pattern detection, consistent typed masking, encrypted mapping persistence and audit privacy, sanitized provider input, explicit local placeholder restoration (including reordered, repeated, unknown, and omitted placeholders), and synthetic evaluation scoring.

## Storage and privacy boundaries

- SQLite stores sanitized request text, encrypted original-value mappings, and metadata-only audit events in the local `data/` directory.
- The original input is not written to the audit table or application logs. Audit rows contain UTC timestamps, event type, entity types/count, success, provider/model, duration, and request ID; they do not contain prompt text. The sanitized prompt needed for completion is stored separately in `requests` and is subject to the same retention period.
- The external provider is called only with the sanitized payload retrieved by request ID from local storage.
- The API exposes neither mapping values nor the encryption key. The dashboard uses the locally screened `display_response` for its default view, keeps raw provider output collapsed under “View technical response,” and requires explicit confirmation before requesting local restoration; the backend rejects restoration requests without `authorized: true`. Detection may miss unrecognized sensitive content, so this display screening is not a guarantee. All routes except `/api/health` require `X-API-Key`.
- The `authorized` flag is a user-confirmation signal, not identity authentication. The shared API key is intended for local development and does not provide production identity controls.
- The bundled evaluation is a small, fixed synthetic benchmark; its scores are not a guarantee of real-world detection quality and do not evaluate an external provider. SQLite deletion does not guarantee removal from backups, snapshots, journals, or other copied database files.
