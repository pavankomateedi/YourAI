"""Master-key provisioning and KMS key-wrapping.

Two production concerns the dev defaults must not silently violate:

1. **Master key durability.** If the document-store master key is ephemeral,
   every restart orphans previously stored ciphertext. In production we therefore
   *fail closed*: a persistent ``STORE_ENCRYPTION_KEY_PATH`` is required.
2. **Key wrapping (envelope encryption).** A data key should be stored *wrapped*
   by a key-encryption-key (KEK), never in plaintext. Three providers implement the
   :class:`KeyWrappingProvider` protocol:
     * ``LocalKeyWrapping`` — no-op (development default).
     * ``LocalEnvelopeWrapping`` — real AES-256-GCM wrap/unwrap under a local KEK
       (``SCP_KEK`` base64 or ``SCP_KEK_PATH`` file). Works with zero cloud deps.
     * ``AwsKmsWrapping`` — wraps via AWS KMS Encrypt/Decrypt (needs boto3 + creds).

   ``KEY_WRAPPING`` selects the provider: ``none`` | ``local`` | ``kms``.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12


class KeyManagementError(Exception):
    """Raised when a key cannot be provisioned safely (e.g. fail-closed in prod)."""


class KeyWrappingProvider(Protocol):
    """Wrap/unwrap data keys. Production impls back this with a KMS."""

    def wrap(self, plaintext_key: bytes) -> bytes: ...
    def unwrap(self, wrapped_key: bytes) -> bytes: ...


class LocalKeyWrapping:
    """Development no-op wrapper. Replace with envelope or KMS wrapping in prod."""

    def wrap(self, plaintext_key: bytes) -> bytes:
        return plaintext_key

    def unwrap(self, wrapped_key: bytes) -> bytes:
        return wrapped_key


class LocalEnvelopeWrapping:
    """Real envelope encryption under a local KEK (AES-256-GCM).

    The KEK comes from ``SCP_KEK`` (base64 of 32 bytes) or a file at
    ``SCP_KEK_PATH``. This gives genuine wrap/unwrap with no cloud dependency —
    suitable for on-prem deployments or as the dev stand-in for a real KMS.
    """

    def __init__(self, kek: bytes | None = None) -> None:
        self._kek = kek or self._load_kek()

    @staticmethod
    def _load_kek() -> bytes:
        b64 = os.environ.get("SCP_KEK")
        if b64:
            kek = base64.b64decode(b64)
        else:
            path = os.environ.get("SCP_KEK_PATH")
            if not path or not os.path.exists(path):
                raise KeyManagementError(
                    "LocalEnvelopeWrapping requires SCP_KEK (base64) or SCP_KEK_PATH"
                )
            with open(path, "rb") as fh:
                kek = fh.read()
        if len(kek) < _KEY_BYTES:
            raise KeyManagementError("KEK must be at least 32 bytes")
        return kek[:_KEY_BYTES]

    def wrap(self, plaintext_key: bytes) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + AESGCM(self._kek).encrypt(nonce, plaintext_key, b"scp-data-key")

    def unwrap(self, wrapped_key: bytes) -> bytes:
        nonce, ct = wrapped_key[:_NONCE_BYTES], wrapped_key[_NONCE_BYTES:]
        return AESGCM(self._kek).decrypt(nonce, ct, b"scp-data-key")


class AwsKmsWrapping:
    """Wrap/unwrap a data key via AWS KMS. Requires boto3 and AWS credentials.

    ``KMS_KEY_ID`` selects the customer master key. ``wrap`` returns the KMS
    ciphertext blob; ``unwrap`` calls Decrypt.
    """

    def __init__(self, key_id: str | None = None) -> None:
        self._key_id = key_id or os.environ.get("KMS_KEY_ID")
        if not self._key_id:
            raise KeyManagementError("AwsKmsWrapping requires KMS_KEY_ID")
        import boto3  # imported lazily so the dependency is optional

        self._kms = boto3.client("kms")

    def wrap(self, plaintext_key: bytes) -> bytes:
        resp = self._kms.encrypt(KeyId=self._key_id, Plaintext=plaintext_key)
        return resp["CiphertextBlob"]

    def unwrap(self, wrapped_key: bytes) -> bytes:
        resp = self._kms.decrypt(KeyId=self._key_id, CiphertextBlob=wrapped_key)
        return resp["Plaintext"]


def get_key_wrapping_provider(mode: str | None = None) -> KeyWrappingProvider:
    """Select a wrapping provider from ``KEY_WRAPPING`` (none|local|kms)."""
    mode = (mode or os.environ.get("KEY_WRAPPING", "none")).lower()
    if mode == "local":
        return LocalEnvelopeWrapping()
    if mode == "kms":
        return AwsKmsWrapping()
    return LocalKeyWrapping()


class MasterKeyProvider:
    """Provision the document-store master key according to the environment.

    When a wrapping provider other than the no-op is configured, the key file
    stores the *wrapped* master key; it is unwrapped into memory on load and the
    on-disk bytes are never the plaintext key.
    """

    def __init__(
        self,
        key_path: str | None = None,
        environment: str | None = None,
        wrapping: KeyWrappingProvider | None = None,
    ) -> None:
        self._key_path = key_path or os.environ.get("STORE_ENCRYPTION_KEY_PATH")
        self._environment = (environment or os.environ.get("SCP_ENV", "development")).lower()
        self._wrapping = wrapping if wrapping is not None else get_key_wrapping_provider()
        self._wrapped = not isinstance(self._wrapping, LocalKeyWrapping)

    @property
    def is_production(self) -> bool:
        return self._environment in {"production", "prod"}

    def _finalize(self, data: bytes, source: str) -> bytes:
        """Unwrap (if a wrapper is configured) and validate a loaded key."""
        key = self._wrapping.unwrap(data) if self._wrapped else data
        if len(key) < _KEY_BYTES:
            raise KeyManagementError(f"Master key from {source} is too short ({len(key)} bytes)")
        return key[:_KEY_BYTES]

    def get_master_key(self) -> bytes:
        # 1. Persistent key file present — the normal Kubernetes (mounted secret) path.
        if self._key_path and os.path.exists(self._key_path):
            with open(self._key_path, "rb") as fh:
                data = fh.read()
            return self._finalize(data, source=self._key_path)

        # 2. Key from an environment secret (base64) — the cloud/ECS path where the
        #    key comes from a secret manager rather than a mounted file.
        env_b64 = os.environ.get("STORE_ENCRYPTION_KEY_B64")
        if env_b64:
            return self._finalize(base64.b64decode(env_b64), source="STORE_ENCRYPTION_KEY_B64")

        # 3. Production with no durable key — refuse to run (fail closed).
        if self.is_production:
            raise KeyManagementError(
                "Refusing to start in production without a persistent master key. "
                "Set STORE_ENCRYPTION_KEY_PATH to a 32-byte key file (ideally KMS-wrapped)."
            )

        # 3. Development: generate, persisting (wrapped, if configured) to the path.
        key = os.urandom(_KEY_BYTES)
        if self._key_path:
            os.makedirs(os.path.dirname(os.path.abspath(self._key_path)), exist_ok=True)
            on_disk = self._wrapping.wrap(key) if self._wrapped else key
            with open(self._key_path, "wb") as fh:
                fh.write(on_disk)
            log.warning("Generated a new development master key at %s", self._key_path)
        else:
            log.warning(
                "No STORE_ENCRYPTION_KEY_PATH set — using an EPHEMERAL master key "
                "(development only). Stored documents will be unreadable after restart."
            )
        return key
