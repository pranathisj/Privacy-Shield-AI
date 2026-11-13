"""FastAPI endpoints for the PrivacyShield dashboard."""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

from app.config import Settings
from app.privacy.detector import PIIDetector
from app.services.llm import create_provider
from app.services.privacy import PrivacyService
from app.storage.database import MappingNotFoundError, MappingStore

logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    text: str = Field(max_length=20_000)


class ScanResponse(BaseModel):
    request_id: str
    sanitized_text: str
    entity_count: int
    entity_types: list[str]
    duration_ms: float
    validation: "ValidationResponse"


class FieldValidationResponse(BaseModel):
    field: str
    status: str
    message: str


class ValidationResponse(BaseModel):
    fields: list[FieldValidationResponse]
    summary: str
    valid_count: int
    invalid_count: int
    missing_count: int
    uncertain_count: int


class CompletionRequest(BaseModel):
    request_id: UUID


class CompletionResponse(BaseModel):
    response: str
    display_response: str
    provider: str


class ReidentificationRequest(BaseModel):
    request_id: UUID
    raw_response: str = Field(max_length=50_000)
    authorized: bool = False


class ReidentificationResponse(BaseModel):
    response: str
    restored_count: int


@lru_cache(maxsize=1)
def get_service() -> PrivacyService:
    settings = Settings.from_env()
    store = MappingStore(settings)
    return PrivacyService(PIIDetector(settings), store, create_provider(settings))


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    try:
        configured_key = Settings.from_env().api_key
    except (OSError, ValueError) as exc:
        logger.error("Could not load backend API authentication configuration.")
        raise HTTPException(
            status_code=503,
            detail="Backend API authentication is unavailable.",
        ) from exc
    if configured_key is None:
        raise HTTPException(
            status_code=503,
            detail="Backend API authentication is not configured.",
        )
    if x_api_key is None or not secrets.compare_digest(
        x_api_key.encode("utf-8"),
        configured_key.encode("utf-8"),
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


app = FastAPI(
    title="PrivacyShield AI",
    description="A local privacy gateway that masks PII before an LLM request.",
    version="0.1.0",
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    logger.warning("Request validation failed.")
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed; check the request format and limits."},
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
def scan(request: ScanRequest) -> dict[str, object]:
    try:
        return get_service().scan(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError:
        logger.error("Scan could not be saved.")
        raise HTTPException(status_code=500, detail="Scan could not be saved.")


@app.post(
    "/api/complete",
    response_model=CompletionResponse,
    dependencies=[Depends(require_api_key)],
)
def complete(request: CompletionRequest) -> dict[str, str]:
    try:
        return get_service().complete(request.request_id)
    except MappingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError:
        raise HTTPException(status_code=503, detail="The AI provider is not configured.")
    except RuntimeError:
        logger.error("LLM completion or audit logging failed.")
        raise HTTPException(status_code=502, detail="AI completion failed.")


@app.post(
    "/api/reidentify",
    response_model=ReidentificationResponse,
    dependencies=[Depends(require_api_key)],
)
def reidentify(request: ReidentificationRequest) -> dict[str, object]:
    try:
        return get_service().reidentify(
            request.request_id,
            request.raw_response,
            authorized=request.authorized,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except MappingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError:
        logger.error("Authorized placeholder restoration failed.")
        raise HTTPException(status_code=500, detail="Placeholder restoration failed.")


@app.get("/api/audit", dependencies=[Depends(require_api_key)])
def audit(limit: int = 50) -> dict[str, object]:
    try:
        return {"logs": get_service().get_audit_logs(limit)}
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/metrics", dependencies=[Depends(require_api_key)])
def metrics() -> dict[str, int]:
    try:
        return get_service().get_metrics()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/evaluation", dependencies=[Depends(require_api_key)])
def evaluation() -> dict[str, int | float]:
    try:
        return get_service().evaluate_synthetic_dataset()
    except RuntimeError as exc:
        logger.error("Synthetic privacy evaluation failed.")
        raise HTTPException(status_code=500, detail="Synthetic evaluation failed.") from exc
