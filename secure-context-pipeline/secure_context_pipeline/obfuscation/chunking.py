"""Vault-aware chunking for documents larger than the LLM context window.

Splitting is done on line boundaries with ``keepends`` so the concatenation of the
chunks is byte-identical to the original document. Each chunk is detected and
obfuscated against the *same* session vault, so cross-chunk token consistency is
guaranteed for free: the second occurrence of a value in a later chunk resolves to
the same token via ``vault.lookup_by_original``.
"""

from __future__ import annotations


def chunk_text(text: str, max_chars: int = 12000) -> list[str]:
    """Split text into <= max_chars chunks on line boundaries.

    ``"".join(chunk_text(t)) == t`` always holds. A single line longer than
    ``max_chars`` is emitted as its own (oversized) chunk rather than being split
    mid-line, so entity spans are never broken across a chunk boundary.
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if current and len(current) + len(line) > max_chars:
            chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks or [text]
