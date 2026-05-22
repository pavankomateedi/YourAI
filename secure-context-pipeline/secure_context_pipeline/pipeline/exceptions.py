"""Custom exceptions for the Secure Context Pipeline.

This module is the single source of truth for every pipeline exception. It is a
dependency leaf (nothing here imports other package modules) so any component can
import it without risking a circular import. ``store.exceptions`` re-exports the
storage-related subset for ergonomic imports.
"""

from __future__ import annotations


class SecurePipelineError(Exception):
    """Base class for every error raised by the pipeline."""


class PIILeakError(SecurePipelineError):
    """Raised when an outbound LLM payload still contains an original PII value.

    The original value is *never* included in the message — only the entity type —
    so the exception itself can be logged safely (HF-002).
    """

    def __init__(self, entity_type: str | None = None, stage: str = "pre_llm_call") -> None:
        self.entity_type = entity_type
        self.stage = stage
        detail = f" (entity_type={entity_type})" if entity_type else ""
        super().__init__(f"PII leak detected at {stage}{detail} — LLM call aborted")


class VaultMissError(SecurePipelineError, KeyError):
    """Raised when a token is not present in the session vault.

    Subclasses both ``SecurePipelineError`` and ``KeyError`` so callers may catch
    either — the test harness expects vault misses to surface as ``KeyError``.
    """


class DocumentNotFoundError(SecurePipelineError):
    """Raised when a document id is not found for the given user."""


class UnsupportedFileTypeError(SecurePipelineError):
    """Raised when an uploaded file's MIME type is not allowed."""


class FileTooLargeError(SecurePipelineError):
    """Raised when an uploaded file exceeds the configured maximum size."""
