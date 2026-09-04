"""
network/protocol.py
====================
Wire-format message definitions for the PQCTunnel handshake and data channel.

All messages are serialised to/from plain Python dicts (ready for JSON over
WebSocket). Bytes fields are base64-encoded in the wire format.

Message types
-------------
ClientHello    — sent by initiator (Alice) to start the handshake.
KemResponse    — sent by responder (Bob) to complete the handshake.
DataMessage    — encrypted application data after handshake.
Rejection      — structured refusal returned to any sender on error.
Envelope       — outer wrapper: {"type": <str>, "payload": <dict>}

Exceptions
----------
ProtocolError
    Raised when a received message is structurally malformed or fails a
    pre-crypto validity check.  The message string IS the structured reason
    shown in the Eve console, e.g.:
      "malformed ClientHello: PQC fields missing"
      "public key does not match session identity"
      "unknown message type: 'bogus'"

Constants
---------
ML-KEM-768 sizes:  public_key=1184 bytes, ciphertext=1088 bytes
ML-DSA-65  sizes:  public_key=1952 bytes
X25519     size:   public_key=32 bytes
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any


# ── Protocol constants ───────────────────────────────────────────────────────

PROTOCOL_VERSION       = "1"
HKDF_INFO              = b"pqctunnel-session-v1"
TRANSCRIPT_DOMAIN_SEP  = b"pqctunnel-handshake-v1\x00"

# Expected byte sizes — used for pre-crypto structural validation
X25519_PK_SIZE         = 32
ML_KEM_768_PK_SIZE     = 1184
ML_KEM_768_CT_SIZE     = 1088
ML_DSA_65_PK_SIZE      = 1952

VALID_ROLES            = frozenset({"alice", "bob"})
MSG_CLIENT_HELLO       = "client_hello"
MSG_KEM_RESPONSE       = "kem_response"
MSG_DATA               = "data"
MSG_REJECTION          = "rejection"


# ── Exceptions ───────────────────────────────────────────────────────────────

class ProtocolError(Exception):
    """
    Raised for structurally invalid or pre-crypto-rejected messages.

    The message string is the exact structured reason surfaced in Eve's console:
      - "malformed ClientHello: PQC fields missing"
      - "public key does not match session identity"
      - "malformed ClientHello: classical fields missing"
      - "unknown message type: '<t>'"
    """


class ReplayError(Exception):
    """
    Raised when a DataMessage sequence number has already been seen.

    Message format: "sequence number <N> already used"
    """


# ── Helpers ──────────────────────────────────────────────────────────────────

def _b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64dec(s: str | bytes) -> bytes:
    return base64.b64decode(s)


# ── ClientHello ──────────────────────────────────────────────────────────────

@dataclass
class ClientHello:
    """
    Initiator → Responder.  First message of the handshake.

    Fields
    ------
    version    Protocol version string (must be PROTOCOL_VERSION).
    role       "alice" or "bob" — who is sending this hello.
    x25519_pk  Initiator's X25519 public key (32 bytes).
    kem_pk     Initiator's ML-KEM-768 public key (1184 bytes).
               ABSENT (empty bytes) in a downgrade attack.
    sig_pk     Initiator's ML-DSA-65 signing public key (1952 bytes).
               ABSENT (empty bytes) in a downgrade attack.
    """

    version:   str
    role:      str
    x25519_pk: bytes
    kem_pk:    bytes
    sig_pk:    bytes

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "version":   self.version,
            "role":      self.role,
            "x25519_pk": _b64enc(self.x25519_pk),
            "kem_pk":    _b64enc(self.kem_pk),
            "sig_pk":    _b64enc(self.sig_pk),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ClientHello":
        try:
            return cls(
                version=str(d["version"]),
                role=str(d["role"]),
                x25519_pk=_b64dec(d["x25519_pk"]),
                kem_pk=_b64dec(d["kem_pk"]),
                sig_pk=_b64dec(d["sig_pk"]),
            )
        except (KeyError, Exception) as exc:
            raise ProtocolError(f"malformed ClientHello: {exc}") from exc


# ── KemResponse ──────────────────────────────────────────────────────────────

@dataclass
class KemResponse:
    """
    Responder → Initiator.  Completes the handshake.

    Fields
    ------
    kem_ct      ML-KEM-768 ciphertext produced by encapsulating to initiator's
                kem_pk (1088 bytes).
    x25519_pk   Responder's X25519 public key (32 bytes).
    sig_pk      Responder's ML-DSA-65 signing public key (1952 bytes).
    signature   ML-DSA-65 signature of the handshake transcript (variable
                length, ≤ 3309 bytes for ML-DSA-65).
    """

    kem_ct:    bytes
    x25519_pk: bytes
    sig_pk:    bytes
    signature: bytes

    def to_dict(self) -> dict:
        return {
            "kem_ct":    _b64enc(self.kem_ct),
            "x25519_pk": _b64enc(self.x25519_pk),
            "sig_pk":    _b64enc(self.sig_pk),
            "signature": _b64enc(self.signature),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KemResponse":
        try:
            return cls(
                kem_ct=_b64dec(d["kem_ct"]),
                x25519_pk=_b64dec(d["x25519_pk"]),
                sig_pk=_b64dec(d["sig_pk"]),
                signature=_b64dec(d["signature"]),
            )
        except (KeyError, Exception) as exc:
            raise ProtocolError(f"malformed KemResponse: {exc}") from exc


# ── DataMessage ──────────────────────────────────────────────────────────────

@dataclass
class DataMessage:
    """
    Encrypted application data after handshake.

    Fields
    ------
    seq         Monotonic per-session sequence number (uint64). Replay
                protection: a repeated seq is rejected immediately.
    nonce       AES-256-GCM nonce (12 bytes, random per message).
    ciphertext  Encrypted payload (same length as plaintext).
    tag         AES-256-GCM authentication tag (16 bytes).

    AAD binding: the sequence number is bound into the GCM additional
    authenticated data as seq.to_bytes(8, 'big'), so altering seq also
    breaks the tag.
    """

    seq:        int
    nonce:      bytes
    ciphertext: bytes
    tag:        bytes

    def to_dict(self) -> dict:
        return {
            "seq":        self.seq,
            "nonce":      _b64enc(self.nonce),
            "ciphertext": _b64enc(self.ciphertext),
            "tag":        _b64enc(self.tag),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DataMessage":
        try:
            return cls(
                seq=int(d["seq"]),
                nonce=_b64dec(d["nonce"]),
                ciphertext=_b64dec(d["ciphertext"]),
                tag=_b64dec(d["tag"]),
            )
        except (KeyError, Exception) as exc:
            raise ProtocolError(f"malformed DataMessage: {exc}") from exc


# ── Rejection ────────────────────────────────────────────────────────────────

@dataclass
class Rejection:
    """
    Server/peer → sender.  Structured refusal with a specific reason string.
    This is what Eve's console displays for every blocked attack attempt.
    """

    reason: str

    def to_dict(self) -> dict:
        return {"reason": self.reason}

    @classmethod
    def from_dict(cls, d: dict) -> "Rejection":
        return cls(reason=str(d.get("reason", "unknown error")))


# ── Message envelope ─────────────────────────────────────────────────────────

def make_envelope(msg_type: str, payload_obj: Any) -> dict:
    """Wrap a message object in the outer {type, payload} envelope."""
    return {"type": msg_type, "payload": payload_obj.to_dict()}


def parse_envelope(envelope: dict) -> tuple[str, dict]:
    """
    Unpack an outer envelope.  Returns (msg_type, payload_dict).
    Raises ProtocolError if the envelope is malformed or the type is unknown.
    """
    try:
        t = str(envelope["type"])
        p = dict(envelope["payload"])
    except (KeyError, TypeError) as exc:
        raise ProtocolError(f"malformed envelope: {exc}") from exc

    valid_types = {
        MSG_CLIENT_HELLO, MSG_KEM_RESPONSE, MSG_DATA, MSG_REJECTION
    }
    if t not in valid_types:
        raise ProtocolError(f"unknown message type: {t!r}")
    return t, p


# ── Transcript hash ──────────────────────────────────────────────────────────

def compute_transcript(
    initiator_x25519_pk: bytes,
    initiator_kem_pk:    bytes,
    initiator_sig_pk:    bytes,
    responder_x25519_pk: bytes,
    responder_sig_pk:    bytes,
    kem_ct:              bytes,
) -> bytes:
    """
    Compute the handshake transcript hash that both sides sign and verify.

    The transcript binds:
      - domain separator (prevents cross-protocol attacks)
      - all public keys exchanged (catches key substitution after the fact)
      - the KEM ciphertext (prevents ciphertext replay/substitution)

    Both parties must arrive at the identical bytes for signature verification
    to pass.  Any tampering with any field causes a mismatch.

    Returns
    -------
    bytes
        32-byte SHA-256 digest of the transcript material.
    """
    material = (
        TRANSCRIPT_DOMAIN_SEP
        + initiator_x25519_pk
        + initiator_kem_pk
        + initiator_sig_pk
        + responder_x25519_pk
        + responder_sig_pk
        + kem_ct
    )
    return hashlib.sha256(material).digest()


# ── ClientHello validation ────────────────────────────────────────────────────

def validate_client_hello(
    hello: ClientHello,
    original: ClientHello | None = None,
) -> None:
    """
    Structural and identity pre-checks on a received ClientHello.

    These checks run BEFORE any crypto operation. They give distinct,
    actionable rejection reasons for the two handshake-phase attacks:

      Downgrade attack  — PQC fields stripped from ClientHello
      MITM attack       — Attacker's keys substituted for initiator's keys

    Parameters
    ----------
    hello    The ClientHello as received (possibly tampered by Eve).
    original If supplied, the genuine ClientHello the initiator sent earlier.
             Used to detect key substitution (MITM).

    Raises
    ------
    ProtocolError
        "malformed ClientHello: PQC fields missing"      — downgrade
        "malformed ClientHello: classical fields missing" — classical stripped
        "public key does not match session identity"      — key substitution
    """
    # ── Classical field check ─────────────────────────────────────────────
    if len(hello.x25519_pk) != X25519_PK_SIZE:
        raise ProtocolError("malformed ClientHello: classical fields missing")

    # ── PQC field checks (downgrade detection) ────────────────────────────
    if len(hello.kem_pk) != ML_KEM_768_PK_SIZE:
        raise ProtocolError("malformed ClientHello: PQC fields missing")

    if len(hello.sig_pk) != ML_DSA_65_PK_SIZE:
        raise ProtocolError("malformed ClientHello: PQC fields missing")

    # ── Version / role checks ─────────────────────────────────────────────
    if hello.version != PROTOCOL_VERSION:
        raise ProtocolError(
            f"unsupported protocol version: {hello.version!r}"
        )
    if hello.role not in VALID_ROLES:
        raise ProtocolError(f"invalid role: {hello.role!r}")

    # ── Key substitution check (MITM detection) ───────────────────────────
    # Only possible when we have the original ClientHello to compare against.
    if original is not None:
        keys_match = (
            hello.x25519_pk == original.x25519_pk
            and hello.kem_pk == original.kem_pk
            and hello.sig_pk == original.sig_pk
        )
        if not keys_match:
            raise ProtocolError("public key does not match session identity")
