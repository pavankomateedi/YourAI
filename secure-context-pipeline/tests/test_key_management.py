"""Key management: fail-closed master key + dev provisioning."""

import os

import pytest

from secure_context_pipeline.security.keys import (
    KeyManagementError,
    LocalEnvelopeWrapping,
    LocalKeyWrapping,
    MasterKeyProvider,
)


class TestMasterKeyProvider:
    @pytest.mark.security
    def test_production_without_key_path_fails_closed(self):
        provider = MasterKeyProvider(key_path=None, environment="production")
        with pytest.raises(KeyManagementError):
            provider.get_master_key()

    @pytest.mark.security
    def test_production_with_persistent_key_succeeds(self, tmp_path):
        key_file = tmp_path / "master.key"
        key_file.write_bytes(os.urandom(32))
        provider = MasterKeyProvider(key_path=str(key_file), environment="production")
        assert len(provider.get_master_key()) == 32

    @pytest.mark.unit
    def test_dev_generates_and_persists_stable_key(self, tmp_path):
        key_file = str(tmp_path / "master.key")
        first = MasterKeyProvider(key_path=key_file, environment="development").get_master_key()
        second = MasterKeyProvider(key_path=key_file, environment="development").get_master_key()
        assert first == second, "Dev key must persist and be stable across instances"

    @pytest.mark.unit
    def test_short_key_rejected(self, tmp_path):
        key_file = tmp_path / "master.key"
        key_file.write_bytes(b"too-short")
        provider = MasterKeyProvider(key_path=str(key_file), environment="production")
        with pytest.raises(KeyManagementError):
            provider.get_master_key()

    @pytest.mark.unit
    def test_local_wrapping_roundtrip(self):
        w = LocalKeyWrapping()
        key = os.urandom(32)
        assert w.unwrap(w.wrap(key)) == key

    @pytest.mark.security
    def test_envelope_wrapping_roundtrip_and_ciphertext(self):
        w = LocalEnvelopeWrapping(kek=os.urandom(32))
        key = os.urandom(32)
        wrapped = w.wrap(key)
        assert wrapped != key, "wrapped key must not equal the plaintext key"
        assert w.unwrap(wrapped) == key

    @pytest.mark.security
    def test_master_key_from_env_secret_satisfies_production(self, monkeypatch):
        import base64

        key = os.urandom(32)
        monkeypatch.setenv("STORE_ENCRYPTION_KEY_B64", base64.b64encode(key).decode())
        # No key_path, production: the env secret must satisfy the fail-closed gate.
        got = MasterKeyProvider(key_path=None, environment="production").get_master_key()
        assert got == key

    @pytest.mark.security
    def test_master_key_persisted_wrapped_not_plaintext(self, tmp_path, monkeypatch):
        import base64

        kek = os.urandom(32)
        monkeypatch.setenv("SCP_KEK", base64.b64encode(kek).decode())
        key_file = str(tmp_path / "master.key")
        wrap = LocalEnvelopeWrapping(kek=kek)

        first = MasterKeyProvider(key_path=key_file, environment="development", wrapping=wrap).get_master_key()
        # On-disk bytes are the wrapped form, never the plaintext key.
        on_disk = (tmp_path / "master.key").read_bytes()
        assert on_disk != first
        # Reloading unwraps to the same key (durable across restarts).
        second = MasterKeyProvider(key_path=key_file, environment="development", wrapping=wrap).get_master_key()
        assert first == second
