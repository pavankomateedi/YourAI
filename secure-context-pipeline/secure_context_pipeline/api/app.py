"""FastAPI service exposing the Secure Context Pipeline over HTTP.

Endpoints (all except ``/health``, ``/ui`` require the ``X-API-Key`` header when
``SERVICE_API_KEY`` is set; ``/events`` and ``/events/history`` additionally
accept ``?api_key=…`` because the browser ``EventSource`` cannot set headers)::

    GET    /health                       — liveness + which LLM backend is active
    GET    /ui                           — self-contained demo page

    POST   /sessions                     — create a session, returns session_id
    DELETE /sessions/{session_id}        — destroy the session vault

    POST   /documents                    — upload a document (multipart)
    GET    /documents?user_id=…          — list the caller's documents
    DELETE /documents/{document_id}      — delete a stored document

    POST   /run                          — run the pipeline (text or document_id)

    GET    /events?session_id=…          — SSE live event stream for that session
    GET    /events/history?session_id=…  — ring-buffer replay (events emitted so far)

Every state-changing handler publishes a typed event to the shared ``EventBus``
so the UI's activity timeline reflects every Create/Read/Update/Delete and every
error in real time. Events carry zero recoverable PII — only counts, ids, types,
and structured error info.

NOTE: this module intentionally does NOT use ``from __future__ import annotations``
— FastAPI needs real (not stringized) type objects to resolve ``UploadFile``/``Form``.
"""

import asyncio
import json
import os
import uuid

from ..audit.audit_log import AuditLog
from ..config import get_settings
from ..pipeline.events import default_bus
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
    from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
    from fastapi.responses import HTMLResponse, StreamingResponse
    from pydantic import BaseModel

    from .ui import INDEX_HTML

    settings = get_settings()
    store = SecureDocumentStore()
    audit = AuditLog()
    bus = default_bus
    pipeline = SecureContextPipeline(audit_log=audit, store=store, event_bus=bus)

    app = FastAPI(
        title="Secure Context Pipeline",
        version="2.1.0",
        description="PII/PHI obfuscation between a document store and external LLMs, "
                    "with live activity timeline via SSE.",
    )

    async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        expected = os.environ.get("SERVICE_API_KEY")
        if expected and x_api_key != expected:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    def _check_query_key(api_key: str | None) -> None:
        """For SSE/history endpoints — browser EventSource can't set headers, so
        accept the same key as a query param. No-op when no key is configured."""
        expected = os.environ.get("SERVICE_API_KEY")
        if expected and api_key != expected:
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

    # ------------------------------------------------------------- public pages
    @app.get("/ui", response_class=HTMLResponse)
    async def ui() -> str:
        return INDEX_HTML

    @app.get("/health")
    async def health() -> dict:
        backend = "anthropic" if settings.anthropic_api_key else "mock"
        return {"status": "ok", "llm_backend": backend, "model": settings.llm_model}

    # ----------------------------------------------------------------- sessions
    @app.post("/sessions", dependencies=[Depends(require_api_key)])
    async def create_session(req: CreateSessionRequest) -> dict:
        session_id = f"session-{uuid.uuid4().hex}"
        bus.publish(session_id, "session.creating", {"user_id": req.user_id})
        try:
            await pipeline._vault.create_session(session_id)
        except Exception as e:
            bus.publish(session_id, "error",
                        {"op": "session.create", "kind": type(e).__name__, "message": str(e)})
            raise HTTPException(status_code=500, detail=f"create_session: {e}")
        bus.publish(session_id, "session.created", {"user_id": req.user_id})
        return {"session_id": session_id, "user_id": req.user_id}

    @app.delete("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
    async def destroy_session(session_id: str, user_id: str = "unknown") -> dict:
        bus.publish(session_id, "session.destroying", {"user_id": user_id})
        try:
            await pipeline.destroy_session(session_id, user_id=user_id)
        except Exception as e:
            bus.publish(session_id, "error",
                        {"op": "session.destroy", "kind": type(e).__name__, "message": str(e)})
            raise HTTPException(status_code=500, detail=f"destroy_session: {e}")
        bus.publish(session_id, "session.destroyed", {"user_id": user_id})
        # Give the UI one tick to drain, then forget. (Don't forget synchronously —
        # subscribers may not have consumed the destroyed event yet.)
        async def _forget_later():
            await asyncio.sleep(5)
            bus.forget(session_id)
        asyncio.create_task(_forget_later())
        return {"session_id": session_id, "destroyed": True}

    # ---------------------------------------------------------------- documents
    @app.post("/documents", dependencies=[Depends(require_api_key)])
    async def upload_document(
        user_id: str = Form(...),
        file: UploadFile = File(...),
        session_id: str | None = Form(default=None),
    ) -> dict:
        sid = session_id or f"_user-{user_id}"
        content = await file.read()
        bus.publish(sid, "document.uploading",
                    {"user_id": user_id, "mime": file.content_type, "bytes": len(content),
                     "filename": file.filename})
        try:
            doc_id = await store.upload(user_id, content, file.content_type or "text/plain")
        except UnsupportedFileTypeError as e:
            bus.publish(sid, "error",
                        {"op": "document.upload", "kind": "UnsupportedFileType", "message": str(e)})
            raise HTTPException(status_code=415, detail=str(e))
        except FileTooLargeError as e:
            bus.publish(sid, "error",
                        {"op": "document.upload", "kind": "FileTooLarge", "message": str(e)})
            raise HTTPException(status_code=413, detail=str(e))
        except Exception as e:
            bus.publish(sid, "error",
                        {"op": "document.upload", "kind": type(e).__name__, "message": str(e)})
            raise HTTPException(status_code=500, detail=str(e))
        bus.publish(sid, "document.uploaded",
                    {"document_id": doc_id, "bytes": len(content), "mime": file.content_type})
        return {"document_id": doc_id, "bytes": len(content)}

    @app.get("/documents", dependencies=[Depends(require_api_key)])
    async def list_documents(user_id: str = Query(...), session_id: str | None = None) -> dict:
        sid = session_id or f"_user-{user_id}"
        bus.publish(sid, "document.listing", {"user_id": user_id})
        try:
            items = await store.list_documents(user_id)
        except Exception as e:
            bus.publish(sid, "error",
                        {"op": "document.list", "kind": type(e).__name__, "message": str(e)})
            raise HTTPException(status_code=500, detail=str(e))
        bus.publish(sid, "document.listed", {"count": len(items)})
        return {"documents": items, "count": len(items)}

    @app.delete("/documents/{document_id}", dependencies=[Depends(require_api_key)])
    async def delete_document(
        document_id: str,
        user_id: str = Query(...),
        session_id: str | None = None,
    ) -> dict:
        sid = session_id or f"_user-{user_id}"
        bus.publish(sid, "document.deleting", {"document_id": document_id, "user_id": user_id})
        try:
            await store.delete(user_id, document_id)
        except Exception as e:
            bus.publish(sid, "error",
                        {"op": "document.delete", "kind": type(e).__name__, "message": str(e)})
            raise HTTPException(status_code=500, detail=str(e))
        bus.publish(sid, "document.deleted", {"document_id": document_id})
        return {"document_id": document_id, "deleted": True}

    # --------------------------------------------------------------------- run
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
            # gate_aborted was already emitted inside the pipeline.
            raise HTTPException(status_code=422, detail=f"PII leak gate aborted call: {e}")
        except DocumentNotFoundError as e:
            bus.publish(req.session_id, "error",
                        {"op": "run", "kind": "DocumentNotFound", "message": str(e)})
            raise HTTPException(status_code=404, detail=str(e))
        return {
            "session_id": result.session_id,
            "restored_response": result.restored_response,
            "entities_detected": result.entities_detected,
            "entities_obfuscated": result.entities_obfuscated,
            "tokens_restored": result.tokens_restored,
            "pipeline_duration_ms": result.pipeline_duration_ms,
            "obfuscated_preview": result.obfuscated_preview,
            "llm_raw_response": result.llm_raw_response,
        }

    # ------------------------------------------------------ live event timeline
    @app.get("/events/history")
    async def events_history(session_id: str = Query(...), api_key: str | None = None) -> dict:
        _check_query_key(api_key)
        return {"session_id": session_id, "events": bus.history(session_id)}

    @app.get("/events")
    async def events_stream(session_id: str = Query(...), api_key: str | None = None):
        """Server-Sent Events stream of pipeline activity for ``session_id``."""
        _check_query_key(api_key)

        async def gen():
            # SSE preamble + initial replay so a late subscriber sees what already
            # happened. Each line follows the spec: ``data: <json>\n\n``.
            yield ": connected\n\n"
            for env in bus.history(session_id):
                yield f"data: {json.dumps(env)}\n\n"
            try:
                # 20s keepalive — comfortably under the ALB 60s idle timeout.
                async for env in bus.subscribe(session_id, idle_keepalive_seconds=20):
                    if env is None:
                        yield ": keepalive\n\n"
                    else:
                        yield f"data: {json.dumps(env)}\n\n"
            except asyncio.CancelledError:  # pragma: no cover — client closed
                return

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",  # disable proxy buffering (nginx/ALB)
                "Connection": "keep-alive",
            },
        )

    return app


# Module-level app for `uvicorn secure_context_pipeline.api.app:app`.
try:  # pragma: no cover - only when FastAPI is installed
    app = create_app()
except Exception:  # pragma: no cover
    app = None
