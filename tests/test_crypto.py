"""
tests/test_crypto.py
=====================
pytest unit tests for crypto/classical.py, pqc.py, and symmetric.py.

Every test calls the REAL library functions — no mocking, no stubs, no
hardcoded return values.

Run with:
    docker build -t pqctunnel-test .
    docker run --rm pqctunnel-test python -m pytest tests/test_crypto.py -v
"""

import hashlib
import pytest

from crypto.classical import generate_x25519_keypair, x25519_exchange, hkdf_derive
from crypto.pqc import (
    kem_generate_keypair,
    kem_encapsulate,
    kem_decapsulate,
    sign_generate_keypair,
    sign_message,
    verify_signature,
    SignatureVerificationError,
)
from crypto.symmetric import encrypt, decrypt, DecryptionError


# ── X25519 ───────────────────────────────────────────────────────────────────

class TestX25519:
    def test_keypair_sizes(self):
        """Public key must be exactly 32 bytes (X25519 raw format)."""
        _, pub = generate_x25519_keypair()
        assert len(pub) == 32

    def test_shared_secret_agreement(self):
        """Both sides must derive the same 32-byte shared secret."""
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()

        secret_a = x25519_exchange(priv_a, pub_b)
        secret_b = x25519_exchange(priv_b, pub_a)

        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_different_keys_different_secrets(self):
        """Unrelated keypairs must not produce the same shared secret."""
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        priv_c, pub_c = generate_x25519_keypair()

        s_ab = x25519_exchange(priv_a, pub_b)
        s_ac = x25519_exchange(priv_a, pub_c)
        assert s_ab != s_ac


# ── HKDF ─────────────────────────────────────────────────────────────────────

class TestHKDF:
    def test_output_length(self):
        """Default output is 32 bytes (AES-256 key size)."""
        key = hkdf_derive(b"\x01" * 32, b"\x02" * 32, b"test")
        assert len(key) == 32

    def test_custom_length(self):
        key = hkdf_derive(b"\x01" * 32, b"\x02" * 32, b"test", length=64)
        assert len(key) == 64

    def test_deterministic(self):
        """Same inputs → same output."""
        s1 = b"\xAB" * 32
        s2 = b"\xCD" * 32
        k1 = hkdf_derive(s1, s2, b"ctx")
        k2 = hkdf_derive(s1, s2, b"ctx")
        assert k1 == k2

    def test_different_inputs_different_output(self):
        """Flipping one secret must change the derived key."""
        s1 = b"\xAB" * 32
        s2 = b"\xCD" * 32
        k1 = hkdf_derive(s1, s2, b"ctx")
        k2 = hkdf_derive(s1, b"\xEE" * 32, b"ctx")
        assert k1 != k2

    def test_different_info_different_output(self):
        """Different info strings must produce different keys."""
        s1, s2 = b"\x01" * 32, b"\x02" * 32
        k1 = hkdf_derive(s1, s2, b"context-a")
        k2 = hkdf_derive(s1, s2, b"context-b")
        assert k1 != k2


# ── ML-KEM-768 ───────────────────────────────────────────────────────────────

class TestMLKEM:
    def test_keypair_sizes(self):
        """ML-KEM-768 public key: 1184 bytes; secret key: 2400 bytes."""
        pk, sk = kem_generate_keypair()
        assert len(pk) == 1184
        assert len(sk) == 2400

    def test_encapsulate_decapsulate_agree(self):
        """Encapsulate and decapsulate must produce the same shared secret."""
        pk, sk = kem_generate_keypair()
        ct, ss_enc = kem_encapsulate(pk)
        ss_dec = kem_decapsulate(sk, ct)
        assert ss_enc == ss_dec
        assert len(ss_enc) == 32  # ML-KEM-768 shared secret is 32 bytes

    def test_wrong_sk_produces_different_secret(self):
        """Decapsulating with a different secret key must not agree."""
        pk, sk = kem_generate_keypair()
        _, wrong_sk = kem_generate_keypair()
        ct, ss_enc = kem_encapsulate(pk)
        ss_wrong = kem_decapsulate(wrong_sk, ct)
        assert ss_wrong != ss_enc

    def test_ciphertext_size(self):
        """ML-KEM-768 ciphertext must be 1088 bytes."""
        pk, _ = kem_generate_keypair()
        ct, _ = kem_encapsulate(pk)
        assert len(ct) == 1088


# ── ML-DSA-65 ────────────────────────────────────────────────────────────────

class TestMLDSA:
    def test_sign_verify_roundtrip(self):
        """A freshly signed message must verify without raising."""
        pk, sk = sign_generate_keypair()
        msg = b"transcript-hash-bytes-go-here"
        sig = sign_message(sk, msg)
        # Must not raise
        verify_signature(pk, msg, sig)

    def test_corrupted_signature_raises(self):
        """Flipping one byte in the signature must raise SignatureVerificationError."""
        pk, sk = sign_generate_keypair()
        msg = b"some handshake transcript"
        sig = bytearray(sign_message(sk, msg))
        sig[42] ^= 0xFF          # flip a byte in the middle
        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_signature(pk, msg, bytes(sig))
        assert "ML-DSA signature verification failed" in str(exc_info.value)

    def test_wrong_message_raises(self):
        """Verifying a signature against a different message must fail."""
        pk, sk = sign_generate_keypair()
        sig = sign_message(sk, b"original message")
        with pytest.raises(SignatureVerificationError):
            verify_signature(pk, b"tampered message", sig)

    def test_wrong_pk_raises(self):
        """Verifying with a different public key must fail."""
        pk, sk = sign_generate_keypair()
        wrong_pk, _ = sign_generate_keypair()
        msg = b"message"
        sig = sign_message(sk, msg)
        with pytest.raises(SignatureVerificationError):
            verify_signature(wrong_pk, msg, sig)

    def test_verify_returns_none_on_success(self):
        """verify_signature must return None (not a bool) on success."""
        pk, sk = sign_generate_keypair()
        msg = b"hello"
        sig = sign_message(sk, msg)
        result = verify_signature(pk, msg, sig)
        assert result is None


# ── AES-256-GCM ──────────────────────────────────────────────────────────────

class TestAESGCM:
    @pytest.fixture()
    def key(self):
        return bytes(range(32))  # deterministic 32-byte key for tests

    def test_roundtrip(self, key):
        """Encrypt then decrypt must recover the exact original plaintext."""
        plaintext = b"Hello, post-quantum world!"
        nonce, ct, tag = encrypt(key, plaintext)
        recovered = decrypt(key, nonce, ct, tag)
        assert recovered == plaintext

    def test_roundtrip_with_aad(self, key):
        """AAD is authenticated — correct AAD must succeed."""
        plaintext = b"authenticated payload"
        aad = b"sequence-number-42"
        nonce, ct, tag = encrypt(key, plaintext, aad=aad)
        recovered = decrypt(key, nonce, ct, tag, aad=aad)
        assert recovered == plaintext

    def test_tampered_ciphertext_raises(self, key):
        """Flipping one byte in the ciphertext must raise DecryptionError."""
        plaintext = b"secret message"
        nonce, ct, tag = encrypt(key, plaintext)
        ct_bad = bytearray(ct)
        ct_bad[0] ^= 0xFF
        with pytest.raises(DecryptionError) as exc_info:
            decrypt(key, nonce, bytes(ct_bad), tag)
        assert "GCM auth tag mismatch" in str(exc_info.value)

    def test_tampered_tag_raises(self, key):
        """Flipping one byte in the tag must raise DecryptionError."""
        plaintext = b"secret"
        nonce, ct, tag = encrypt(key, plaintext)
        tag_bad = bytearray(tag)
        tag_bad[0] ^= 0x01
        with pytest.raises(DecryptionError) as exc_info:
            decrypt(key, nonce, ct, bytes(tag_bad))
        assert "GCM auth tag mismatch" in str(exc_info.value)

    def test_tampered_aad_raises(self, key):
        """Wrong AAD must raise DecryptionError."""
        plaintext = b"payload"
        aad = b"seq-1"
        nonce, ct, tag = encrypt(key, plaintext, aad=aad)
        with pytest.raises(DecryptionError):
            decrypt(key, nonce, ct, tag, aad=b"seq-2")

    def test_nonce_freshness(self, key):
        """Two encryptions of the same plaintext must use different nonces."""
        pt = b"same message"
        n1, _, _ = encrypt(key, pt)
        n2, _, _ = encrypt(key, pt)
        assert n1 != n2

    def test_key_length_validation(self):
        """Wrong key length must raise ValueError, not a silent failure."""
        with pytest.raises(ValueError):
            encrypt(b"short", b"data")

    def test_empty_plaintext(self, key):
        """Empty plaintext must encrypt/decrypt cleanly."""
        nonce, ct, tag = encrypt(key, b"")
        assert ct == b""
        recovered = decrypt(key, nonce, ct, tag)
        assert recovered == b""
