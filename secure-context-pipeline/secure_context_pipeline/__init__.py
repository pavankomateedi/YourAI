"""Secure Context Pipeline — PII/PHI obfuscation for external LLM providers.

A Python 3.11+ async pipeline that detects PII/PHI/privileged entities, replaces
them with opaque tokens or pseudonyms before sending text to an external LLM, and
restores the original values in the LLM response. The token<->original mapping lives
in an encrypted, per-session vault that is destroyed on session end.
"""

__version__ = "2.0.0"
