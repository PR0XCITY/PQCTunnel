"""
network/session.py
===================
Full hybrid handshake and post-handshake secure session.

Roles
-----
SessionInitiator  Alice's side — builds ClientHello, processes KemResponse.
SessionResponder  Bob's side   — validates ClientHello, builds KemResponse.
SecureSession     Post-handshake — encrypt/decrypt with replay protection.

Handshake flow
--------------
  Alice                                     Bob
  ─────                                     ───
  generate X25519, ML-KEM-768, ML-DSA-65
  build ClientHello ──────────────────────► validate_client_hello()
                                            X25519 exchange
                                            ML-KEM encapsulate → (ct, kem_ss)
                                            HKDF(x_ss ‖ kem_ss) → session_key
                                            compute_transcript(...)
                                            sign transcript with sig_sk
                                            build KemResponse ◄───────────────
  X25519 exchange
  ML-KEM decapsulate(ct) → kem_ss
  HKDF(x_ss ‖ kem_ss) → session_key
  compute_transcript(...)
  verify Bob's sig_pk over transcript
  ── handshake complete ──

Replay protection
-----------------
SecureSession keeps a set of seen sequence numbers.  A re-used seq raises
ReplayError("sequence number N already used") before any decryption is attempted.
The seq is also bound into AES-GCM AAD so altering it breaks the tag.

Attack detection layer
----------------------
validate_client_hello (from protocol.py) is the pre-crypto gating step:
  - Missing/short PQC fields  → ProtocolError("malformed ClientHello: PQC fields missing")
  - Substituted public keys   → ProtocolError("public key does not match session identity")
These fire BEFORE signature verification, giving distinct reasons for downgrade
vs MITM attacks.  SignatureVerificationError is the backstop for anything that
passes structural checks but has an invalid transcript signature.
"""

from __future__ import annotations

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

from network.protocol import (
    ClientHello,
    KemResponse,
    DataMessage,
    ProtocolError,
    ReplayError,
    HKDF_INFO,
    compute_transcript,
    validate_client_hello,
)


# ── Handshake timing record ───────────────────────────────────────────────────

import time
from dataclasses import dataclass, field


@dataclass
class HandshakeTiming:
    """
    Wall-clock timing for each handshake phase (milliseconds).
    Populated by the session classes and consumed by the frontend timing panel.
    """

    keygen_ms:        float = 0.0
    x25519_ms:        float = 0.0
    kem_ms:           float = 0.0
    hkdf_ms:          float = 0.0
    sign_ms:          float = 0.0
    verify_ms:        float = 0.0
    total_ms:         float = 0.0

    def to_dict(self) -> dict:
        return {
            "keygen_ms":  round(self.keygen_ms, 3),
            "x25519_ms":  round(self.x25519_ms, 3),
            "kem_ms":     round(self.kem_ms, 3),
            "hkdf_ms":    round(self.hkdf_ms, 3),
            "sign_ms":    round(self.sign_ms, 3),
            "verify_ms":  round(self.verify_ms, 3),
            "total_ms":   round(self.total_ms, 3),
        }


def _ms() -> float:
    return time.perf_counter() * 1000.0


# ── SessionInitiator (Alice) ──────────────────────────────────────────────────

class SessionInitiator:
    """
    Alice's side of the handshake.

    Usage
    -----
    initiator = SessionInitiator()
    hello = initiator.build_client_hello()
    # ... send hello over the wire ...
    # ... receive kem_response from Bob ...
    session = initiator.process_kem_response(kem_response)
    # session is a SecureSession ready for encrypt/decrypt
    """

    def __init__(self) -> None:
        t0 = _ms()

        self._x_priv, self.x_pub = generate_x25519_keypair()
        self.kem_pk, self._kem_sk = kem_generate_keypair()
        self.sig_pk, self._sig_sk = sign_generate_keypair()

        self.timing = HandshakeTiming(keygen_ms=_ms() - t0)
        self._session: SecureSession | None = None

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def session(self) -> "SecureSession":
        if self._session is None:
            raise RuntimeError("Handshake not yet complete")
        return self._session

    def build_client_hello(self) -> ClientHello:
        """Build the ClientHello to send to the responder."""
        return ClientHello(
            version="1",
            role="alice",
            x25519_pk=self.x_pub,
            kem_pk=self.kem_pk,
            sig_pk=self.sig_pk,
        )

    def process_kem_response(self, response: KemResponse) -> "SecureSession":
        """
        Receive Bob's KemResponse, derive session key, verify his signature.

        Parameters
        ----------
        response : KemResponse
            The KemResponse as received from Bob (possibly tampered by Eve).

        Returns
        -------
        SecureSession
            A ready-to-use session for encrypting/decrypting data.

        Raises
        ------
        SignatureVerificationError
            If Bob's ML-DSA-65 signature over the transcript is invalid.
            Message: "ML-DSA signature verification failed: transcript hash mismatch"
        DecryptionError
            If KEM decapsulation produces a session key that wouldn't match
            (caught indirectly via GCM tag failures on the first data message).
        """
        t0 = _ms()

        # X25519 exchange
        t_x = _ms()
        x_ss = x25519_exchange(self._x_priv, response.x25519_pk)
        self.timing.x25519_ms = _ms() - t_x

        # ML-KEM decapsulate
        t_k = _ms()
        kem_ss = kem_decapsulate(self._kem_sk, response.kem_ct)
        self.timing.kem_ms = _ms() - t_k

        # HKDF hybrid derivation
        t_h = _ms()
        session_key = hkdf_derive(x_ss, kem_ss, HKDF_INFO)
        self.timing.hkdf_ms = _ms() - t_h

        # Compute transcript — over the keys WE sent and the keys Bob sent
        transcript = compute_transcript(
            initiator_x25519_pk=self.x_pub,
            initiator_kem_pk=self.kem_pk,
            initiator_sig_pk=self.sig_pk,
            responder_x25519_pk=response.x25519_pk,
            responder_sig_pk=response.sig_pk,
            kem_ct=response.kem_ct,
        )

        # Verify Bob's signature
        t_v = _ms()
        verify_signature(response.sig_pk, transcript, response.signature)
        self.timing.verify_ms = _ms() - t_v

        self.timing.total_ms = _ms() - t0

        self._session = SecureSession(session_key=session_key, role="alice")
        return self._session


# ── SessionResponder (Bob) ────────────────────────────────────────────────────

class SessionResponder:
    """
    Bob's side of the handshake.

    Usage
    -----
    responder = SessionResponder()
    # ... receive client_hello from Alice ...
    kem_response = responder.process_client_hello(client_hello)
    # ... send kem_response over the wire ...
    session = responder.session   # SecureSession ready for use
    """

    def __init__(self) -> None:
        t0 = _ms()

        self._x_priv, self.x_pub = generate_x25519_keypair()
        self.sig_pk, self._sig_sk = sign_generate_keypair()
        # Bob does not need a KEM keypair — he encapsulates to Alice's KEM pk

        self.timing = HandshakeTiming(keygen_ms=_ms() - t0)
        self._session: SecureSession | None = None

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def session(self) -> "SecureSession":
        if self._session is None:
            raise RuntimeError("Handshake not yet complete")
        return self._session

    def process_client_hello(
        self,
        hello: ClientHello,
        original_hello: ClientHello | None = None,
    ) -> KemResponse:
        """
        Validate ClientHello, encapsulate, derive session key, sign transcript.

        Parameters
        ----------
        hello : ClientHello
            The ClientHello as received (may be tampered by Eve).
        original_hello : ClientHello | None
            If provided, the genuine ClientHello Alice sent (stored by the
            relay).  Enables MITM key-substitution detection.

        Returns
        -------
        KemResponse
            Ready to serialise and send back to Alice.

        Raises
        ------
        ProtocolError
            "malformed ClientHello: PQC fields missing"       — downgrade
            "public key does not match session identity"       — MITM
        SignatureVerificationError
            Backstop: would fire if structural checks pass but the transcript
            signature is somehow invalid (should not happen in normal flow
            since Bob signs the transcript himself here).
        """
        t0 = _ms()

        # ── Pre-crypto validation (catches downgrade and MITM before any crypto)
        validate_client_hello(hello, original=original_hello)

        # ── X25519 exchange
        t_x = _ms()
        x_ss = x25519_exchange(self._x_priv, hello.x25519_pk)
        self.timing.x25519_ms = _ms() - t_x

        # ── ML-KEM encapsulate to Alice's KEM public key
        t_k = _ms()
        kem_ct, kem_ss = kem_encapsulate(hello.kem_pk)
        self.timing.kem_ms = _ms() - t_k

        # ── HKDF hybrid derivation
        t_h = _ms()
        session_key = hkdf_derive(x_ss, kem_ss, HKDF_INFO)
        self.timing.hkdf_ms = _ms() - t_h

        # ── Compute transcript
        transcript = compute_transcript(
            initiator_x25519_pk=hello.x25519_pk,
            initiator_kem_pk=hello.kem_pk,
            initiator_sig_pk=hello.sig_pk,
            responder_x25519_pk=self.x_pub,
            responder_sig_pk=self.sig_pk,
            kem_ct=kem_ct,
        )

        # ── Sign transcript with our ML-DSA-65 key
        t_s = _ms()
        signature = sign_message(self._sig_sk, transcript)
        self.timing.sign_ms = _ms() - t_s

        self.timing.total_ms = _ms() - t0
        self._session = SecureSession(session_key=session_key, role="bob")

        return KemResponse(
            kem_ct=kem_ct,
            x25519_pk=self.x_pub,
            sig_pk=self.sig_pk,
            signature=signature,
        )


# ── SecureSession ─────────────────────────────────────────────────────────────

class SecureSession:
    """
    Post-handshake secure session with AES-256-GCM and replay protection.

    Both Alice and Bob hold a SecureSession after the handshake completes.
    They use it to encrypt/decrypt DataMessages.

    Replay protection
    -----------------
    Outgoing sequence numbers start at 0 and increment monotonically.
    Incoming sequence numbers are tracked in a set; any repeated number raises
    ReplayError BEFORE decryption is attempted.
    The seq is also bound into GCM AAD so altering the seq breaks the tag.

    Thread safety
    -------------
    Not thread-safe.  For the relay use case, each session lives on a single
    asyncio task.
    """

    def __init__(self, session_key: bytes, role: str) -> None:
        if len(session_key) != 32:
            raise ValueError("Session key must be 32 bytes")
        self._key: bytes = session_key
        self._role: str = role
        self._send_seq: int = 0
        self._recv_seen: set[int] = set()

    # ── Encrypt ───────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> DataMessage:
        """
        Encrypt plaintext, bind the sequence number into AAD.

        Returns a DataMessage ready for serialisation and transmission.
        """
        seq = self._send_seq
        self._send_seq += 1
        aad = _seq_aad(seq)
        nonce, ciphertext, tag = encrypt(self._key, plaintext, aad=aad)
        return DataMessage(seq=seq, nonce=nonce, ciphertext=ciphertext, tag=tag)

    # ── Decrypt ───────────────────────────────────────────────────────────

    def decrypt(self, msg: DataMessage) -> bytes:
        """
        Verify replay protection, then decrypt and authenticate the message.

        Raises
        ------
        ReplayError
            If msg.seq has already been seen.
            Message: "sequence number N already used"
        DecryptionError
            If the GCM authentication tag does not match.
            Message: "GCM auth tag mismatch"
        """
        if msg.seq in self._recv_seen:
            raise ReplayError(f"sequence number {msg.seq} already used")

        aad = _seq_aad(msg.seq)
        plaintext = decrypt(self._key, msg.nonce, msg.ciphertext, msg.tag, aad=aad)

        # Only mark as seen AFTER successful authentication
        self._recv_seen.add(msg.seq)
        return plaintext

    # ── Accessors ─────────────────────────────────────────────────────────

    @property
    def next_send_seq(self) -> int:
        return self._send_seq

    @property
    def seen_seqs(self) -> frozenset[int]:
        return frozenset(self._recv_seen)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _seq_aad(seq: int) -> bytes:
    """Encode sequence number as 8-byte big-endian AAD."""
    return seq.to_bytes(8, "big")
