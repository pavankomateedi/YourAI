"""FastAPI service exposing the Secure Context Pipeline over HTTP.

Endpoints (all except /health require the ``X-API-Key`` header when
``SERVICE_API_KEY`` is set in the environment):

    GET    /health                 — liveness + which LLM backend is active
    POST   /sessions               — create a session, returns session_id
    DELETE /sessions/{session_id}  — destroy the session vault
    POST   /documents              — upload a document (multipart), returns document_id
    POST   /run                    — run the pipeline on text or an uploaded document

The service holds one pipeline instance with a real encrypted vault and document
store. Secrets come only from the environment; nothing sensitive is logged.

NOTE: this module intentionally does NOT use ``from __future__ import annotations``
— FastAPI needs real (not stringized) type objects to resolve ``UploadFile``/``Form``.
"""

import os
import uuid
from typing import Optional

from ..audit.audit_log import AuditLog
from ..config import get_settings
from ..pipeline.exceptions import (
    DocumentNotFoundError,
    FileTooLargeError,
    PIILeakError,
    UnsupportedFileTypeError,
)
from ..pipeline.pipeline import SecureContextPipeline
from ..store.store import SecureDocumentStore


def create_app():
    """Build and return the FastAPI application."""
    from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
    from pydantic import BaseModel

    settings = get_settings()
    store = SecureDocumentStore()
    audit = AuditLog()
    pipeline = SecureContextPipeline(audit_log=audit, store=store)

    app = FastAPI(
        title="Secure Context Pipeline",
        version="2.0.0",
        description="PII/PHI obfuscation between a document store and external LLMs.",
    )

    async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        expected = os.environ.get("SERVICE_API_KEY")
        if expected and x_api_key != expected:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    class CreateSessionRequest(BaseModel):
        user_id: str

    class RunRequest(BaseModel):
        user_id: str
        session_id: str
        user_query: str
        text: str | None = None
        document_id: str | None = None
        strategy: str | None = None

    @app.get("/health")
    async def health() -> dict:
        backend = "anthropic" if settings.anthropic_api_key else "mock"
        return {"status": "ok", "llm_backend": backend, "model": settings.llm_model}

    @app.post("/sessions", dependencies=[Depends(require_api_key)])
    async def create_session(req: CreateSessionRequest) -> dict:
        session_id = f"session-{uuid.uuid4().hex}"
        await pipeline._vault.create_session(session_id)
        return {"session_id": session_id, "user_id": req.user_id}

    @app.delete("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
    async def destroy_session(session_id: str, user_id: str = "unknown") -> dict:
        await pipeline.destroy_session(session_id, user_id=user_id)
        return {"session_id": session_id, "destroyed": True}

    @app.post("/documents", dependencies=[Depends(require_api_key)])
    async def upload_document(user_id: str = Form(...), file: UploadFile = File(...)) -> dict:
        content = await file.read()
        try:
            doc_id = await store.upload(user_id, content, file.content_type or "text/plain")
        except UnsupportedFileTypeError as e:
            raise HTTPException(status_code=415, detail=str(e))
        except FileTooLargeError as e:
            raise HTTPException(status_code=413, detail=str(e))
        return {"document_id": doc_id}

    @app.post("/run", dependencies=[Depends(require_api_key)])
    async def run(req: RunRequest) -> dict:
        if req.text is None and req.document_id is None:
            raise HTTPException(status_code=422, detail="Provide `text` or `document_id`")
        try:
            result = await pipeline.run(
                user_id=req.user_id,
                session_id=req.session_id,
                text=req.text,
                user_query=req.user_query,
                document_id=req.document_id,
                strategy=req.strategy,
            )
        except PIILeakError as e:
            # Fail closed: never proceed if the leak gate fired.
            raise HTTPException(status_code=422, detail=f"PII leak gate aborted call: {e}")
        except DocumentNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return {
            "session_id": result.session_id,
            "restored_response": result.restored_response,
            "entities_detected": result.entities_detected,
            "entities_obfuscated": result.entities_obfuscated,
            "tokens_restored": result.tokens_restored,
            "pipeline_duration_ms": result.pipeline_duration_ms,
        }

    return app


# Module-level app for `uvicorn secure_context_pipeline.api.app:app`.
try:  # pragma: no cover - only when FastAPI is installed
    app = create_app()
except Exception:  # pragma: no cover
    app = None
