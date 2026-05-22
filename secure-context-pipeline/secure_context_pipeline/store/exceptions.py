"""Storage-related exceptions.

Re-exported from :mod:`secure_context_pipeline.pipeline.exceptions` so storage code
and tests can import them from the ``store`` namespace without duplicating class
definitions.
"""

from ..pipeline.exceptions import (
    DocumentNotFoundError,
    FileTooLargeError,
    UnsupportedFileTypeError,
)

__all__ = [
    "DocumentNotFoundError",
    "FileTooLargeError",
    "UnsupportedFileTypeError",
]
