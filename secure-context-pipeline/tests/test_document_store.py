"""Tests: Secure Document Store (encryption at rest, extraction, validation)."""

import pytest

from conftest import _make_minimal_docx_bytes, _make_minimal_pdf_bytes, make_user_id


class TestSecureDocumentStore:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_upload_and_retrieve_with_correct_key(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        content = b"Patient: Eleanor Hartwell\nSSN: 543-67-8901\n"
        doc_id = await store.upload(user_id, content, "text/plain")
        assert await store.retrieve(user_id, doc_id) == content

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_retrieve_with_wrong_user_fails(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        doc_id = await store.upload(user_id, b"Sensitive content", "text/plain")
        with pytest.raises(Exception):
            await store.retrieve(make_user_id(), doc_id)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stored_content_is_not_plaintext(self, user_id, tmp_path):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore(base_path=str(tmp_path))
        await store.upload(user_id, b"Eleanor Hartwell SSN: 543-67-8901", "text/plain")
        all_content = b""
        for f in tmp_path.rglob("*"):
            if f.is_file():
                all_content += f.read_bytes()
        assert b"Eleanor Hartwell" not in all_content, "Plaintext found in storage"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_pdf_upload_and_text_extraction(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        pdf_bytes = _make_minimal_pdf_bytes("Patient: Dr. Eleanor Hartwell")
        doc_id = await store.upload(user_id, pdf_bytes, "application/pdf")
        assert hasattr(store, "extract_text")
        extracted = await store.extract_text(user_id, doc_id)
        assert isinstance(extracted, str) and len(extracted) > 0
        assert "Hartwell" in extracted or "Eleanor" in extracted

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_docx_upload_and_text_extraction(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        docx_bytes = _make_minimal_docx_bytes("Legal client: Martinez Family Trust. Strategy: settlement.")
        doc_id = await store.upload(
            user_id, docx_bytes,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        extracted = await store.extract_text(user_id, doc_id)
        assert isinstance(extracted, str) and len(extracted) > 0
        assert "Martinez" in extracted or "settlement" in extracted

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_mime_type_rejection(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
            from secure_context_pipeline.store.exceptions import UnsupportedFileTypeError
        except ImportError:
            pytest.skip("SecureDocumentStore or UnsupportedFileTypeError not implemented")

        store = SecureDocumentStore()
        with pytest.raises(UnsupportedFileTypeError):
            await store.upload(user_id, b"MZ" + b"\x00" * 254, "application/x-msdownload")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_file_size_limit(self, user_id):
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
            from secure_context_pipeline.store.exceptions import FileTooLargeError
        except ImportError:
            pytest.skip("SecureDocumentStore or FileTooLargeError not implemented")

        store = SecureDocumentStore()
        with pytest.raises(FileTooLargeError):
            await store.upload(user_id, b"\x00" * (51 * 1024 * 1024), "text/plain")
