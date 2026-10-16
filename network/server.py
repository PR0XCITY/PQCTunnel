"""
network/server.py
==================
Blind WebSocket relay for PQCTunnel.

This file contains ZERO cryptography. No imports from crypto/, no liboqs,
no openssl, no cryptography library of any kind. The relay forwards byte
payloads it cannot read. All X25519, ML-KEM-768, ML-DSA-65, HKDF-SHA-256,
and AES-256-GCM operations execute client-side in the browser.

────────────────────────────────────────────────────────────────────────────
Architecture
────────────────────────────────────────────────────────────────────────────

  ws://<host>/ws/{room_code}/{role}
    role ∈ {"alice", "bob", "eve"}

  Alice/Bob frames  →  relay  →  forwarded to peer verbatim
                              →  mirror copy pushed to Eve

  Eve inject frames →  relay  →  pre-checked (structural byte equality only)
                              →  delivered to target verbatim

────────────────────────────────────────────────────────────────────────────
Pre-checks the relay CAN perform without crypto (all on cleartext fields)
────────────────────────────────────────────────────────────────────────────

1. REPLAY pre-check
   DataMessage seq numbers travel in cleartext as GCM AAD. The relay tracks
   seen seqs per sender. A repeated seq is rejected before delivery, and a seq
   that is not a non-negative integer is rejected outright.
   Rejections: "sequence number N already used", "invalid sequence number: X"

2. DOWNGRADE pre-check
   ClientHello PQC field sizes are visible as base64 lengths. An empty or
   short kem_pk/sig_pk means the attacker stripped PQC.
   Rejection: "malformed ClientHello: PQC fields missing"

3. MITM pre-check
   The relay stores the first ClientHello from Alice and the first KemResponse
   from Bob. An injected handshake frame whose public keys differ from the
   stored ones for the peer it impersonates → key substitution.
   Rejection: "public key does not match session identity"

These are belt-and-suspenders checks. The client JS does its own validation
and signature checks, and the safety code exposes a MITM even when the relay
itself is malicious. To demonstrate that, Eve has two demo switches that model
a compromised relay:

  * inject {..., "bypass_relay_checks": true} — skip the pre-checks above, so
    the frame reaches the client and its crypto has to catch it.
  * {"type": "set_mitm", "payload": {"enabled": true}} — the relay stops
    forwarding Alice↔Bob frames and hands them only to Eve, who can then run
    a handshake with each side.

────────────────────────────────────────────────────────────────────────────
Room model
────────────────────────────────────────────────────────────────────────────

One room per room code. Exactly one Alice, one Bob, one Eve per room.
Duplicate role claims are rejected (WebSocket close code 4000).
All room state is in-memory — no persistence, no DB. Handshake and replay
state resets when Alice or Bob leaves, so a reconnecting peer starts clean.

────────────────────────────────────────────────────────────────────────────
Message envelope format (all JSON)
────────────────────────────────────────────────────────────────────────────

Client → relay:
  {"type": "client_hello",    "payload": {version, role, x25519_pk, kem_pk, sig_pk}}
  {"type": "kem_response",    "payload": {kem_ct, x25519_pk, sig_pk, signature}}
  {"type": "client_finished", "payload": {signature}}
  {"type": "data",            "payload": {seq, nonce, ciphertext, tag}}
  {"type": "alert",           "payload": {reason, frame_type}}   (receiver rejected a frame)
  {"type": "inject",          "payload": {target, frame, bypass_relay_checks?}}  (Eve only)
  {"type": "set_mitm",        "payload": {enabled}}                              (Eve only)

Relay → client:
  {"type": "joined",        "payload": {role, room, peers}}
  {"type": "peer_joined",   "payload": {role}}
  {"type": "peer_left",     "payload": {role}}
  {"type": "mirror",        "payload": {from, frame, ts, held}}                 (Eve only)
  {"type": "inject_ok",     "payload": {target, frame_type, bypassed}}          (Eve only)
  {"type": "mitm_status",   "payload": {enabled}}                               (Eve only)
  {"type": "rejection",     "payload": {reason}}
  {"type": "error",         "payload": {reason}}

GET /health → {"status": "ok"}
"""

from __future__ import annotations

import base64
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

app = FastAPI(title="PQCTunnel Relay", version="2.0.0")

# Allow all origins for the Vercel frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ── Expected field sizes for downgrade pre-check (byte counts) ───────────────
# These are the DECODED sizes; the relay checks base64-decoded length.
_ML_KEM_768_PK_BYTES = 1184
_ML_DSA_65_PK_BYTES  = 1952

_MAX_SEQ = 2**53 - 1   # largest seq the browser can represent exactly

VALID_ROLES = frozenset({"alice", "bob", "eve"})
PEER_MESSAGE_TYPES = frozenset({"client_hello", "kem_response", "client_finished", "data", "alert"})
_ROOM_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


# ── Room model ────────────────────────────────────────────────────────────────

@dataclass
class Room:
    code: str
    alice: Optional[WebSocket]    = None
    bob:   Optional[WebSocket]    = None
    eve:   Optional[WebSocket]    = None

    # First handshake frame seen from each side — stored as raw payload dicts
    # (cleartext public keys in base64) for the MITM byte-equality pre-check
    # only. The relay does not interpret, decode, or use these keys.
    alice_original_hello:    Optional[dict] = None
    bob_original_response:   Optional[dict] = None

    # Seq numbers seen FROM each role (cleartext field in DataMessage payload).
    # Used for replay pre-rejection: does not require decryption.
    alice_seen_seqs: set = field(default_factory=set)
    bob_seen_seqs:   set = field(default_factory=set)

    # Demo: compromised-relay MITM mode — Alice/Bob frames go only to Eve.
    mitm: bool = False

    def reset_session_state(self) -> None:
        self.alice_original_hello = None
        self.bob_original_response = None
        self.alice_seen_seqs.clear()
        self.bob_seen_seqs.clear()


# ── In-memory room registry ───────────────────────────────────────────────────

_rooms: dict[str, Room] = {}


def _get_or_create_room(code: str) -> Room:
    if code not in _rooms:
        _rooms[code] = Room(code=code)
    return _rooms[code]


def _maybe_destroy_room(code: str) -> None:
    room = _rooms.get(code)
    if room and room.alice is None and room.bob is None and room.eve is None:
        _rooms.pop(code, None)
        logger.info("Room %s destroyed (all peers left)", code)


# ── Helper: send JSON safely (ignore closed-socket errors) ───────────────────

async def _send(ws: WebSocket, data: dict) -> None:
    try:
        await ws.send_json(data)
    except Exception:
        pass  # peer disconnected; caller handles cleanup


def _rejection(reason: str) -> dict:
    return {"type": "rejection", "payload": {"reason": reason}}


def _error(reason: str) -> dict:
    return {"type": "error", "payload": {"reason": reason}}


def _other(role: str) -> str:
    return "bob" if role == "alice" else "alice"


# ── Seq helpers ───────────────────────────────────────────────────────────────

def _seen_seqs_for_sender(room: Room, sender_role: str) -> set:
    """Return the seen-seq set that belongs to sender_role."""
    return room.alice_seen_seqs if sender_role == "alice" else room.bob_seen_seqs


def _parse_seq(payload) -> Optional[int]:
    """
    Return the DataMessage seq if it is a JSON integer in [0, 2^53), else None.
    Strings, floats and booleans are refused: the browser would otherwise map
    some of them onto the AAD of an earlier seq.
    """
    if not isinstance(payload, dict):
        return None
    seq = payload.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq <= _MAX_SEQ:
        return None
    return seq


def _check_seq(room: Room, sender_role: str, payload) -> tuple[Optional[str], Optional[int]]:
    """Return (rejection reason, seq). Does not record the seq."""
    seq = _parse_seq(payload)
    if seq is None:
        raw = payload.get("seq") if isinstance(payload, dict) else None
        return f"invalid sequence number: {raw!r}", None
    if seq in _seen_seqs_for_sender(room, sender_role):
        return f"sequence number {seq} already used", seq
    return None, seq


# ── Cleartext pre-checks (no crypto) ─────────────────────────────────────────

def _base64_decoded_len(b64) -> int:
    """Return the byte length of a base64-encoded field, 0 if invalid."""
    if not isinstance(b64, str):
        return 0
    try:
        return len(base64.b64decode(b64, validate=True))
    except Exception:
        return 0


def _check_client_hello_pqc(payload: dict) -> Optional[str]:
    """
    Return a rejection reason string if PQC fields are missing/short,
    None if the hello is structurally valid.
    This is a pure size/presence check — no crypto.
    """
    kem_pk_len = _base64_decoded_len(payload.get("kem_pk", ""))
    sig_pk_len = _base64_decoded_len(payload.get("sig_pk", ""))

    if kem_pk_len != _ML_KEM_768_PK_BYTES or sig_pk_len != _ML_DSA_65_PK_BYTES:
        return "malformed ClientHello: PQC fields missing"
    return None


def _check_key_substitution(payload: dict, original: dict, fields: tuple[str, ...]) -> Optional[str]:
    """
    Compare public-key base64 strings byte-for-byte.
    Returns rejection reason if keys differ, None if they match.
    This is plain string equality — no crypto.
    """
    if any(payload.get(f) != original.get(f) for f in fields):
        return "public key does not match session identity"
    return None


def _precheck_inject(room: Room, target_role: str, frame_type, frame_payload) -> Optional[str]:
    """
    Pre-checks for a frame Eve injects at target_role. The frame impersonates
    the target's peer, so it is compared against what that peer really sent —
    never against anything the frame says about itself.
    """
    impersonated = _other(target_role)

    if frame_type == "client_hello":
        reason = _check_client_hello_pqc(frame_payload)
        if reason:
            return reason
        if room.alice_original_hello is not None:
            return _check_key_substitution(
                frame_payload, room.alice_original_hello, ("x25519_pk", "kem_pk", "sig_pk"))

    if frame_type == "kem_response" and room.bob_original_response is not None:
        return _check_key_substitution(
            frame_payload, room.bob_original_response, ("x25519_pk", "sig_pk", "kem_ct"))

    if frame_type == "data":
        reason, _ = _check_seq(room, impersonated, frame_payload)
        return reason

    return None


# ── HTTP endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    """
    Liveness check for Render.
    Returns {"status": "ok"} — no liboqs_version because this container
    contains zero crypto code.
    """
    return {"status": "ok"}


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws/{room_code}/{role}")
async def ws_endpoint(websocket: WebSocket, room_code: str, role: str) -> None:
    # ── Validate role and room before accepting ──────────────────────────────
    if role not in VALID_ROLES:
        await websocket.close(
            code=4000, reason=f"invalid role: {role!r}; must be alice, bob, or eve"
        )
        return
    if not _ROOM_CODE_RE.match(room_code):
        await websocket.close(code=4000, reason="invalid room code")
        return

    await websocket.accept()

    room = _get_or_create_room(room_code)

    # ── Reject duplicate role ─────────────────────────────────────────────────
    if getattr(room, role) is not None:
        await _send(websocket, _rejection(
            f"role {role!r} already taken in room {room_code!r}"
        ))
        await websocket.close(code=4000)
        return

    # ── Assign seat ───────────────────────────────────────────────────────────
    setattr(room, role, websocket)
    occupants = [r for r in ("alice", "bob", "eve") if getattr(room, r) is not None]
    logger.info("[ROOM %s] %s JOINED — occupants now: %s", room_code, role.upper(), occupants)

    # ── Confirm join, notify existing peers ───────────────────────────────────
    existing_peers = [
        r for r in ("alice", "bob", "eve")
        if r != role and getattr(room, r) is not None
    ]
    await _send(websocket, {
        "type": "joined",
        "payload": {"role": role, "room": room_code, "peers": existing_peers},
    })
    if role == "eve":
        await _send(websocket, {"type": "mitm_status", "payload": {"enabled": room.mitm}})
    for peer_role in existing_peers:
        peer_ws = getattr(room, peer_role)
        if peer_ws:
            await _send(peer_ws, {"type": "peer_joined", "payload": {"role": role}})

    # ── Message loop ──────────────────────────────────────────────────────────
    try:
        while True:
            try:
                envelope = await websocket.receive_json()
            except Exception:
                break   # parse error or disconnect
            if not isinstance(envelope, dict):
                await _send(websocket, _error("envelope must be a JSON object"))
                continue

            if role == "eve":
                await _handle_eve(room, websocket, envelope)
            else:
                await _handle_peer(room, role, websocket, envelope)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception("Unexpected error for %s in room %s: %s", role, room_code, exc)
    finally:
        setattr(room, role, None)
        if role in ("alice", "bob"):
            # The session is gone; a reconnecting peer starts at seq 0 again.
            room.reset_session_state()
        else:
            room.mitm = False
        logger.info("Room %s: %s left", room_code, role)
        # Notify remaining connected peers
        for other_role in VALID_ROLES - {role}:
            other_ws = getattr(room, other_role)
            if other_ws:
                await _send(other_ws, {"type": "peer_left", "payload": {"role": role}})
        _maybe_destroy_room(room_code)


# ── Alice / Bob message handler ───────────────────────────────────────────────

async def _handle_peer(
    room: Room,
    sender_role: str,
    sender_ws: WebSocket,
    envelope: dict,
) -> None:
    msg_type = envelope.get("type")
    payload  = envelope.get("payload")
    peer_ws  = getattr(room, _other(sender_role))

    if msg_type not in PEER_MESSAGE_TYPES:
        await _send(sender_ws, _error(f"unknown message type: {msg_type!r}"))
        return

    # ── Store the first handshake frame from each side for MITM pre-check ────
    if isinstance(payload, dict):
        if msg_type == "client_hello" and sender_role == "alice" and room.alice_original_hello is None:
            room.alice_original_hello = payload
        if msg_type == "kem_response" and sender_role == "bob" and room.bob_original_response is None:
            room.bob_original_response = payload

    # ── Relay-side replay pre-check for DataMessages ──────────────────────────
    if msg_type == "data":
        reason, seq = _check_seq(room, sender_role, payload)
        if reason:
            await _send(sender_ws, _rejection(reason))
            if room.eve:
                await _send(room.eve, _rejection(reason))
            return
        _seen_seqs_for_sender(room, sender_role).add(seq)

    # ── Forward to peer (unless a compromised relay hands it to Eve) ──────────
    if peer_ws and not room.mitm:
        await _send(peer_ws, envelope)

    # ── Mirror every frame to Eve ─────────────────────────────────────────────
    if room.eve:
        await _send(room.eve, {
            "type": "mirror",
            "payload": {
                "from":  sender_role,
                "frame": envelope,
                "ts":    time.time(),
                "held":  room.mitm,
            },
        })


# ── Eve message handler ───────────────────────────────────────────────────────

async def _handle_eve(
    room: Room,
    eve_ws: WebSocket,
    envelope: dict,
) -> None:
    msg_type = envelope.get("type")
    payload  = envelope.get("payload")
    if not isinstance(payload, dict):
        payload = {}

    if msg_type == "set_mitm":
        room.mitm = bool(payload.get("enabled"))
        logger.info("Room %s: MITM mode %s", room.code, "ON" if room.mitm else "OFF")
        await _send(eve_ws, {"type": "mitm_status", "payload": {"enabled": room.mitm}})
        return

    if msg_type != "inject":
        await _send(eve_ws, _rejection(
            f"Eve may only send 'inject' or 'set_mitm' messages; got {msg_type!r}"
        ))
        return

    target_role = payload.get("target")
    frame       = payload.get("frame")
    bypass      = bool(payload.get("bypass_relay_checks"))

    if not isinstance(frame, dict):
        await _send(eve_ws, _rejection("inject frame must be a JSON object"))
        return
    frame_type    = frame.get("type")
    frame_payload = frame.get("payload")
    if not isinstance(frame_payload, dict):
        frame_payload = {}

    # ── Validate target ───────────────────────────────────────────────────────
    if target_role not in ("alice", "bob"):
        await _send(eve_ws, _rejection(
            f"inject target must be 'alice' or 'bob'; got {target_role!r}"
        ))
        return

    target_ws = getattr(room, target_role)
    if target_ws is None:
        await _send(eve_ws, _rejection(f"{target_role} is not connected"))
        return

    # ── Cleartext pre-checks (downgrade, MITM, replay) ────────────────────────
    if not bypass:
        reason = _precheck_inject(room, target_role, frame_type, frame_payload)
        if reason:
            await _send(eve_ws, _rejection(reason))
            return

    # ── Deliver injected frame to target ──────────────────────────────────────
    await _send(target_ws, frame)
    await _send(eve_ws, {
        "type": "inject_ok",
        "payload": {"target": target_role, "frame_type": frame_type, "bypassed": bypass},
    })
    logger.info(
        "Room %s: Eve injected %r to %s%s", room.code, frame_type, target_role,
        " (relay checks bypassed)" if bypass else "",
    )
