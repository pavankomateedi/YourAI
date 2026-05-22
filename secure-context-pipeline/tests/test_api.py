"""Tests for the FastAPI service layer (skipped if FastAPI isn't installed)."""

import os

import pytest

from conftest import TOKEN_PATTERN, FIXTURE_PII_VALUES, assert_no_pii_in_text

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from secure_context_pipeline.api.app import create_app  # noqa: E402

MED_TEXT = (
    "Patient: Dr. Eleanor Hartwell\nSSN: 543-67-8901\n"
    "Email: eleanor.hartwell@example-clinic.org\nPhone: (512) 555-0147\n"
)


@pytest.fixture
def client():
    return TestClient(create_app())


class TestServiceAPI:
    @pytest.mark.integration
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    @pytest.mark.integration
    def test_session_and_run_roundtrip(self, client):
        sid = client.post("/sessions", json={"user_id": "u1"}).json()["session_id"]
        r = client.post("/run", json={
            "user_id": "u1", "session_id": sid,
            "text": MED_TEXT, "user_query": "Summarize.",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        # Mock LLM echoes tokens; restored response brings originals back.
        assert "Eleanor Hartwell" in body["restored_response"]
        assert not TOKEN_PATTERN.search(body["restored_response"])
        assert body["entities_detected"] >= 4

    @pytest.mark.integration
    def test_upload_then_run_by_document_id(self, client):
        files = {"file": ("rec.txt", MED_TEXT, "text/plain")}
        up = client.post("/documents", data={"user_id": "u2"}, files=files)
        assert up.status_code == 200, up.text
        doc_id = up.json()["document_id"]

        sid = client.post("/sessions", json={"user_id": "u2"}).json()["session_id"]
        r = client.post("/run", json={
            "user_id": "u2", "session_id": sid,
            "document_id": doc_id, "user_query": "Summarize.",
        })
        assert r.status_code == 200, r.text
        assert "543-67-8901" in r.json()["restored_response"]

    @pytest.mark.security
    @pytest.mark.integration
    def test_api_key_enforced(self, monkeypatch):
        monkeypatch.setenv("SERVICE_API_KEY", "secret-123")
        c = TestClient(create_app())
        # Missing key -> 401
        assert c.post("/sessions", json={"user_id": "u"}).status_code == 401
        # Correct key -> allowed
        ok = c.post("/sessions", json={"user_id": "u"}, headers={"X-API-Key": "secret-123"})
        assert ok.status_code == 200

    @pytest.mark.security
    @pytest.mark.integration
    def test_unsupported_mime_rejected(self, client):
        files = {"file": ("x.exe", b"MZ\x00\x00", "application/x-msdownload")}
        r = client.post("/documents", data={"user_id": "u3"}, files=files)
        assert r.status_code == 415
