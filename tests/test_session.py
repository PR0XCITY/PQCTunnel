"""
tests/test_session.py
======================
Integration tests for network/protocol.py and network/session.py.

Every test exercises real crypto — no mocking, no stubs.

Coverage
--------
Protocol
  - ClientHello / KemResponse / DataMessage round-trip serialisation
  - validate_client_hello: downgrade detection (missing PQC fields)
  - validate_client_hello: MITM detection (substituted public keys)
  - compute_transcript: determinism and sensitivity to changes

Session
  - Full handshake: Alice + Bob arrive at identical session keys
  - SecureSession encrypt/decrypt round-trip
  - Replay attack: repeated seq raises ReplayError with exact reason string
  - Tamper attack: flipped ciphertext byte raises DecryptionError
  - Seq bound in AAD: altered seq on received message raises DecryptionError
  - Downgrade attack: ClientHello with PQC fields stripped raises ProtocolError
  - MITM attack: substituted keys raise ProtocolError before any crypto

Run inside Docker:
    docker run --rm -e PYTHONPATH=/app pqctunnel-test \\
        python -m pytest tests/test_session.py -v
"""

from __future__ import annotations

import hashlib
import pytest

from crypto.pqc import SignatureVerificationError
from crypto.symmetric import DecryptionError

from network.protocol import (
    ClientHello,
    KemResponse,
    DataMessage,
    Rejection,
    ProtocolError,
    ReplayError,
    ML_KEM_768_PK_SIZE,
    ML_KEM_768_CT_SIZE,
    ML_DSA_65_PK_SIZE,
    X25519_PK_SIZE,
    compute_transcript,
    validate_client_hello,
    make_envelope,
    parse_envelope,
    MSG_CLIENT_HELLO,
    MSG_KEM_RESPONSE,
    MSG_DATA,
    MSG_REJECTION,
)
from network.session import (
    SessionInitiator,
    SessionResponder,
    SecureSession,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def handshake():
    """
    Perform a complete Alice–Bob handshake once for the whole module.
    Returns (initiator, responder, alice_session, bob_session).
    """
    alice = SessionInitiator()
    bob   = SessionResponder()

    hello    = alice.build_client_hello()
    response = bob.process_client_hello(hello)

    alice_session = alice.process_kem_response(response)
    bob_session   = bob.session

    return alice, bob, alice_session, bob_session


# ── Protocol serialisation ────────────────────────────────────────────────────

class TestClientHelloSerialisation:
    def test_roundtrip(self):
        """ClientHello serialises to dict and deserialises back identically."""
        alice = SessionInitiator()
        hello = alice.build_client_hello()
        d     = hello.to_dict()
        hello2 = ClientHello.from_dict(d)
        assert hello2.version   == hello.version
        assert hello2.role      == hello.role
        assert hello2.x25519_pk == hello.x25519_pk
        assert hello2.kem_pk    == hello.kem_pk
        assert hello2.sig_pk    == hello.sig_pk

    def test_sizes(self):
        """Serialised ClientHello carries correct-sized byte fields."""
        alice = SessionInitiator()
        hello = alice.build_client_hello()
        assert len(hello.x25519_pk) == X25519_PK_SIZE
        assert len(hello.kem_pk)    == ML_KEM_768_PK_SIZE
        assert len(hello.sig_pk)    == ML_DSA_65_PK_SIZE

    def test_malformed_raises(self):
        """from_dict with missing field raises ProtocolError."""
        with pytest.raises(ProtocolError):
            ClientHello.from_dict({"version": "1"})  # missing all other fields


class TestKemResponseSerialisation:
    def test_roundtrip(self, handshake):
        alice, bob, _, _ = handshake
        hello    = alice.build_client_hello()
        response = bob.process_client_hello(hello)
        d        = response.to_dict()
        r2       = KemResponse.from_dict(d)
        assert r2.kem_ct    == response.kem_ct
        assert r2.x25519_pk == response.x25519_pk
        assert r2.sig_pk    == response.sig_pk
        assert r2.signature == response.signature

    def test_kem_ciphertext_size(self, handshake):
        alice, bob, _, _ = handshake
        hello    = alice.build_client_hello()
        response = bob.process_client_hello(hello)
        assert len(response.kem_ct) == ML_KEM_768_CT_SIZE


class TestDataMessageSerialisation:
    def test_roundtrip(self, handshake):
        _, _, alice_session, _ = handshake
        msg = alice_session.encrypt(b"test payload")
        d   = msg.to_dict()
        m2  = DataMessage.from_dict(d)
        assert m2.seq        == msg.seq
        assert m2.nonce      == msg.nonce
        assert m2.ciphertext == msg.ciphertext
        assert m2.tag        == msg.tag


class TestEnvelope:
    def test_make_parse_roundtrip(self):
        alice = SessionInitiator()
        hello = alice.build_client_hello()
        env = make_envelope(MSG_CLIENT_HELLO, hello)
        t, p = parse_envelope(env)
        assert t == MSG_CLIENT_HELLO
        hello2 = ClientHello.from_dict(p)
        assert hello2.x25519_pk == hello.x25519_pk

    def test_unknown_type_raises(self):
        with pytest.raises(ProtocolError, match="unknown message type"):
            parse_envelope({"type": "bogus", "payload": {}})

    def test_malformed_envelope_raises(self):
        with pytest.raises(ProtocolError):
            parse_envelope({"no_type_key": "x"})


# ── Transcript ────────────────────────────────────────────────────────────────

class TestTranscript:
    def test_deterministic(self):
        """Same inputs → same 32-byte hash."""
        args = dict(
            initiator_x25519_pk=b"\x01" * 32,
            initiator_kem_pk=b"\x02" * 1184,
            initiator_sig_pk=b"\x03" * 1952,
            responder_x25519_pk=b"\x04" * 32,
            responder_sig_pk=b"\x05" * 1952,
            kem_ct=b"\x06" * 1088,
        )
        t1 = compute_transcript(**args)
        t2 = compute_transcript(**args)
        assert t1 == t2
        assert len(t1) == 32

    def test_sensitive_to_each_field(self):
        """Changing any single field changes the transcript."""
        base = dict(
            initiator_x25519_pk=b"\x01" * 32,
            initiator_kem_pk=b"\x02" * 1184,
            initiator_sig_pk=b"\x03" * 1952,
            responder_x25519_pk=b"\x04" * 32,
            responder_sig_pk=b"\x05" * 1952,
            kem_ct=b"\x06" * 1088,
        )
        t_base = compute_transcript(**base)
        for key in base:
            modified = {**base, key: b"\xFF" * len(base[key])}
            assert compute_transcript(**modified) != t_base, \
                f"Transcript did not change when {key} was modified"


# ── Handshake ─────────────────────────────────────────────────────────────────

class TestHandshake:
    def test_session_keys_match(self, handshake):
        """Alice and Bob must derive the same 32-byte session key."""
        _, _, alice_session, bob_session = handshake
        # Both sessions were created from the same handshake — their keys
        # must agree (we verify indirectly: a message encrypted by Alice
        # must decrypt on Bob's side, see test_encrypt_decrypt_roundtrip).
        # Direct key comparison via a known-plaintext:
        pt = b"key agreement proof"
        msg = alice_session.encrypt(pt)
        # Bob decrypts with his session (same key if handshake succeeded)
        recovered = bob_session.decrypt(msg)
        assert recovered == pt

    def test_encrypt_decrypt_alice_to_bob(self, handshake):
        """Alice encrypts, Bob decrypts."""
        _, _, alice_session, bob_session = handshake
        plaintext = b"Hello Bob, from Alice."
        msg       = alice_session.encrypt(plaintext)
        recovered = bob_session.decrypt(msg)
        assert recovered == plaintext

    def test_encrypt_decrypt_bob_to_alice(self, handshake):
        """Bob encrypts, Alice decrypts."""
        _, _, alice_session, bob_session = handshake
        plaintext = b"Hello Alice, from Bob."
        msg       = bob_session.encrypt(plaintext)
        recovered = alice_session.decrypt(msg)
        assert recovered == plaintext

    def test_multiple_messages_in_order(self, handshake):
        """Multiple messages decrypt in order with incrementing seq numbers."""
        _, _, alice_s, bob_s = handshake
        messages = [f"message {i}".encode() for i in range(5)]
        encrypted = [alice_s.encrypt(m) for m in messages]
        for i, (enc, orig) in enumerate(zip(encrypted, messages)):
            assert enc.seq == alice_s.next_send_seq - (5 - i)
            assert bob_s.decrypt(enc) == orig

    def test_timing_recorded(self, handshake):
        """HandshakeTiming is populated with non-zero values."""
        alice, bob, _, _ = handshake
        assert alice.timing.total_ms > 0
        assert bob.timing.total_ms   > 0
        # All individual phases should be positive
        for attr in ("keygen_ms", "x25519_ms", "kem_ms", "hkdf_ms"):
            assert getattr(alice.timing, attr) >= 0
            assert getattr(bob.timing, attr)   >= 0

    def test_fresh_handshake_each_time(self):
        """Each handshake produces a different session key (freshness)."""
        alice1, bob1 = SessionInitiator(), SessionResponder()
        alice2, bob2 = SessionInitiator(), SessionResponder()

        h1 = alice1.build_client_hello()
        h2 = alice2.build_client_hello()

        r1 = bob1.process_client_hello(h1)
        r2 = bob2.process_client_hello(h2)

        s1 = alice1.process_kem_response(r1)
        s2 = alice2.process_kem_response(r2)

        # Different sessions → different session keys
        pt = b"probe"
        m1 = s1.encrypt(pt)
        # Attempting to decrypt m1 with s2's key should fail (GCM tag mismatch)
        with pytest.raises(DecryptionError):
            s2.decrypt(m1)


# ── Attack simulations ────────────────────────────────────────────────────────

class TestReplayAttack:
    def test_replay_raises_replay_error(self, handshake):
        """Replaying a DataMessage with the same seq raises ReplayError."""
        _, _, alice_s, bob_s = handshake
        msg = alice_s.encrypt(b"attack target")
        bob_s.decrypt(msg)        # first receive: OK
        with pytest.raises(ReplayError) as exc_info:
            bob_s.decrypt(msg)    # second receive: REJECTED
        reason = str(exc_info.value)
        assert "sequence number" in reason
        assert "already used" in reason

    def test_replay_error_contains_seq_number(self, handshake):
        """Rejection reason must include the specific sequence number."""
        _, _, alice_s, bob_s = handshake
        msg = alice_s.encrypt(b"probe")
        bob_s.decrypt(msg)
        seq = msg.seq
        with pytest.raises(ReplayError) as exc_info:
            bob_s.decrypt(msg)
        assert str(seq) in str(exc_info.value)


class TestTamperAttack:
    def test_tampered_ciphertext_raises(self, handshake):
        """Flipping a ciphertext byte raises DecryptionError."""
        _, _, alice_s, bob_s = handshake
        msg = alice_s.encrypt(b"tamper me")
        bad_ct = bytearray(msg.ciphertext)
        bad_ct[0] ^= 0xFF
        bad_msg = DataMessage(
            seq=msg.seq, nonce=msg.nonce,
            ciphertext=bytes(bad_ct), tag=msg.tag
        )
        with pytest.raises(DecryptionError) as exc_info:
            bob_s.decrypt(bad_msg)
        assert "GCM auth tag mismatch" in str(exc_info.value)

    def test_tampered_tag_raises(self, handshake):
        """Flipping a tag byte raises DecryptionError."""
        _, _, alice_s, bob_s = handshake
        msg = alice_s.encrypt(b"tamper tag")
        bad_tag = bytearray(msg.tag)
        bad_tag[0] ^= 0x01
        bad_msg = DataMessage(
            seq=msg.seq, nonce=msg.nonce,
            ciphertext=msg.ciphertext, tag=bytes(bad_tag)
        )
        with pytest.raises(DecryptionError):
            bob_s.decrypt(bad_msg)

    def test_altered_seq_raises(self, handshake):
        """
        Changing the seq on a received message raises DecryptionError because
        the seq is bound into GCM AAD and the tag no longer authenticates.
        """
        _, _, alice_s, bob_s = handshake
        msg = alice_s.encrypt(b"seq is in AAD")
        bad_msg = DataMessage(
            seq=msg.seq + 999,     # alter the seq
            nonce=msg.nonce,
            ciphertext=msg.ciphertext,
            tag=msg.tag,
        )
        with pytest.raises((DecryptionError, ReplayError)):
            bob_s.decrypt(bad_msg)


class TestDowngradeAttack:
    def test_missing_kem_pk_raises(self):
        """
        ClientHello with empty kem_pk (PQC field stripped) raises ProtocolError.
        Rejection reason must clearly say 'PQC fields missing'.
        """
        alice = SessionInitiator()
        hello = alice.build_client_hello()
        # Strip the KEM public key (downgrade attack)
        downgraded = ClientHello(
            version=hello.version,
            role=hello.role,
            x25519_pk=hello.x25519_pk,
            kem_pk=b"",           # stripped
            sig_pk=hello.sig_pk,
        )
        with pytest.raises(ProtocolError) as exc_info:
            validate_client_hello(downgraded)
        assert "PQC fields missing" in str(exc_info.value)

    def test_missing_sig_pk_raises(self):
        """Empty sig_pk also triggers the PQC fields missing rejection."""
        alice = SessionInitiator()
        hello = alice.build_client_hello()
        downgraded = ClientHello(
            version=hello.version,
            role=hello.role,
            x25519_pk=hello.x25519_pk,
            kem_pk=hello.kem_pk,
            sig_pk=b"",           # stripped
        )
        with pytest.raises(ProtocolError) as exc_info:
            validate_client_hello(downgraded)
        assert "PQC fields missing" in str(exc_info.value)

    def test_downgrade_rejected_by_responder(self):
        """
        process_client_hello raises ProtocolError when given a downgraded hello.
        The relay feeds this hello to Bob — Bob must reject it before any crypto.
        """
        alice = SessionInitiator()
        bob   = SessionResponder()
        hello = alice.build_client_hello()
        downgraded = ClientHello(
            version=hello.version, role=hello.role,
            x25519_pk=hello.x25519_pk,
            kem_pk=b"",   # PQC stripped
            sig_pk=b"",
        )
        with pytest.raises(ProtocolError) as exc_info:
            bob.process_client_hello(downgraded)
        assert "PQC fields missing" in str(exc_info.value)


class TestMITMAttack:
    def test_substituted_keys_detected(self):
        """
        validate_client_hello with original raises ProtocolError when keys differ.
        Rejection reason: 'public key does not match session identity'.
        """
        alice = SessionInitiator()
        eve   = SessionInitiator()   # Eve generates her own keypair

        original = alice.build_client_hello()
        # Eve substitutes her keys into the ClientHello
        substituted = ClientHello(
            version=original.version,
            role=original.role,
            x25519_pk=eve.x_pub,      # Eve's X25519 key
            kem_pk=eve.kem_pk,         # Eve's KEM key
            sig_pk=original.sig_pk,    # keeps Alice's sig_pk (common MITM pattern)
        )
        with pytest.raises(ProtocolError) as exc_info:
            validate_client_hello(substituted, original=original)
        assert "public key does not match session identity" in str(exc_info.value)

    def test_valid_hello_passes_mitm_check(self):
        """Unmodified ClientHello passes the key-substitution check."""
        alice    = SessionInitiator()
        original = alice.build_client_hello()
        # Same object as original → must not raise
        validate_client_hello(original, original=original)

    def test_mitm_rejected_by_responder(self):
        """
        Bob's process_client_hello rejects a MITMed ClientHello when given
        the original as reference.
        """
        alice = SessionInitiator()
        eve   = SessionInitiator()
        bob   = SessionResponder()

        original   = alice.build_client_hello()
        substituted = ClientHello(
            version=original.version, role=original.role,
            x25519_pk=eve.x_pub, kem_pk=eve.kem_pk, sig_pk=original.sig_pk,
        )
        with pytest.raises(ProtocolError) as exc_info:
            bob.process_client_hello(substituted, original_hello=original)
        assert "public key does not match session identity" in str(exc_info.value)

    def test_mitm_without_original_falls_through_to_sig_failure(self):
        """
        If the relay doesn't supply original_hello, the MITM structural check
        is skipped. The handshake then fails at ML-DSA verification because
        the transcript Alice computes differs from what Bob signed.
        """
        alice = SessionInitiator()
        eve   = SessionInitiator()
        bob   = SessionResponder()

        original_hello = alice.build_client_hello()
        substituted = ClientHello(
            version=original_hello.version,
            role=original_hello.role,
            x25519_pk=eve.x_pub,
            kem_pk=eve.kem_pk,
            sig_pk=original_hello.sig_pk,
        )

        # Bob processes the substituted hello (no original supplied)
        response = bob.process_client_hello(substituted)
        # Bob's KemResponse is signed over the substituted keys' transcript.
        # Alice tries to verify using HER original keys — transcript mismatch.
        with pytest.raises(SignatureVerificationError) as exc_info:
            alice.process_kem_response(response)
        assert "ML-DSA signature verification failed" in str(exc_info.value)


# ── validate_client_hello edge cases ─────────────────────────────────────────

class TestValidateClientHello:
    def test_valid_passes(self):
        alice = SessionInitiator()
        validate_client_hello(alice.build_client_hello())   # must not raise

    def test_wrong_version(self):
        alice = SessionInitiator()
        h = alice.build_client_hello()
        bad = ClientHello(version="99", role=h.role,
                          x25519_pk=h.x25519_pk, kem_pk=h.kem_pk, sig_pk=h.sig_pk)
        with pytest.raises(ProtocolError, match="unsupported protocol version"):
            validate_client_hello(bad)

    def test_invalid_role(self):
        alice = SessionInitiator()
        h = alice.build_client_hello()
        bad = ClientHello(version=h.version, role="eve",
                          x25519_pk=h.x25519_pk, kem_pk=h.kem_pk, sig_pk=h.sig_pk)
        with pytest.raises(ProtocolError, match="invalid role"):
            validate_client_hello(bad)

    def test_short_x25519_key(self):
        alice = SessionInitiator()
        h = alice.build_client_hello()
        bad = ClientHello(version=h.version, role=h.role,
                          x25519_pk=b"\x00" * 16,  # too short
                          kem_pk=h.kem_pk, sig_pk=h.sig_pk)
        with pytest.raises(ProtocolError, match="classical fields missing"):
            validate_client_hello(bad)
