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
   seen seqs per sender. A repeated seq is rejected before delivery.
   Rejection: "sequence number N already used"

2. DOWNGRADE pre-check
   ClientHello PQC field sizes are visible as base64 lengths. An empty or
   short kem_pk/sig_pk means the attacker stripped PQC.
   Rejection: "malformed ClientHello: PQC fields missing"

3. MITM pre-check
   The relay stores the first ClientHello seen per role. A later injected
   ClientHello whose public-key base64 strings differ → key substitution.
   Rejection: "public key does not match session identity"

These are belt-and-suspenders checks. The client JS does the same checks
(and additionally verifies ML-DSA signatures) — so even if the relay is
bypassed, the crypto still holds. The relay's checks just short-circuit
obviously invalid frames before they consume client-side crypto budget.

────────────────────────────────────────────────────────────────────────────
Room model
────────────────────────────────────────────────────────────────────────────

One room per room code. Exactly one Alice, one Bob, one Eve per room.
Duplicate role claims are rejected (WebSocket close code 4000).
All room state is in-memory — no persistence, no DB.

────────────────────────────────────────────────────────────────────────────
Message envelope format (all JSON)
────────────────────────────────────────────────────────────────────────────

Client → relay:
  {"type": "client_hello",  "payload": {version, role, x25519_pk, kem_pk, sig_pk}}
  {"type": "kem_response",  "payload": {kem_ct, x25519_pk, sig_pk, signature}}
  {"type": "data",          "payload": {seq, nonce, ciphertext, tag}}
  {"type": "inject",        "payload": {target: "alice"|"bob", frame: <any envelope>}}  (Eve only)

Relay → client:
  {"type": "joined",        "payload": {role, room, peers}}
  {"type": "peer_joined",   "payload": {role}}
  {"type": "peer_left",     "payload": {role}}
  {"type": "mirror",        "payload": {from, frame, ts}}                              (Eve only)
  {"type": "inject_ok",     "payload": {target, frame_type}}                           (Eve only)
  {"type": "rejection",     "payload": {reason}}
  {"type": "error",         "payload": {reason}}

GET /health → {"status": "ok"}
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

app = FastAPI(title="PQCTunnel Relay", version="1.0.0")

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

VALID_ROLES = frozenset({"alice", "bob", "eve"})


# ── Room model ────────────────────────────────────────────────────────────────

@dataclass
class Room:
    code: str
    alice: Optional[WebSocket]    = None
    bob:   Optional[WebSocket]    = None
    eve:   Optional[WebSocket]    = None

    # First ClientHello seen per role — stored as raw payload dict (cleartext
    # public keys in base64) for the MITM byte-equality pre-check only.
    # The relay does not interpret, decode, or use these keys cryptographically.
    alice_original_hello: Optional[dict] = None
    bob_original_hello:   Optional[dict] = None

    # Seq numbers seen FROM each role (cleartext field in DataMessage payload).
    # Used for replay pre-rejection: does not require decryption.
    alice_seen_seqs: set = field(default_factory=set)
    bob_seen_seqs:   set = field(default_factory=set)


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


# ── Seq helpers ───────────────────────────────────────────────────────────────

def _seen_seqs_for_sender(room: Room, sender_role: str) -> set:
    """Return the seen-seq set that belongs to sender_role."""
    return room.alice_seen_seqs if sender_role == "alice" else room.bob_seen_seqs


def _seen_seqs_for_inject_target(room: Room, target_role: str) -> set:
    """
    When Eve injects to target_role, the frame appears to come FROM the
    opposite peer. Return that peer's seen-seq set.
    """
    return room.alice_seen_seqs if target_role == "bob" else room.bob_seen_seqs


# ── Cleartext pre-checks (no crypto) ─────────────────────────────────────────

def _base64_decoded_len(b64: str) -> int:
    """Return the byte length of a base64-encoded field without full decoding."""
    try:
        return len(base64.b64decode(b64))
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


def _check_key_substitution(payload: dict, original: dict) -> Optional[str]:
    """
    Compare public-key base64 strings byte-for-byte.
    Returns rejection reason if keys differ, None if they match.
    This is plain string equality — no crypto.
    """
    fields = ("x25519_pk", "kem_pk", "sig_pk")
    if any(payload.get(f) != original.get(f) for f in fields):
        return "public key does not match session identity"
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
    # ── Validate role before accepting ───────────────────────────────────────
    if role not in VALID_ROLES:
        await websocket.close(
            code=4000, reason=f"invalid role: {role!r}; must be alice, bob, or eve"
        )
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
    logger.info("Room %s: %s joined", room_code, role)

    # ── Confirm join, notify existing peers ───────────────────────────────────
    existing_peers = [
        r for r in ("alice", "bob", "eve")
        if r != role and getattr(room, r) is not None
    ]
    await _send(websocket, {
        "type": "joined",
        "payload": {"role": role, "room": room_code, "peers": existing_peers},
    })
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
    payload  = envelope.get("payload", {})
    peer_role = "bob" if sender_role == "alice" else "alice"
    peer_ws   = getattr(room, peer_role)

    # ── Store the first ClientHello for MITM pre-check ────────────────────────
    if msg_type == "client_hello":
        hello_key = f"{sender_role}_original_hello"
        if getattr(room, hello_key) is None:
            setattr(room, hello_key, payload)
            logger.debug("Room %s: stored %s original ClientHello", room.code, sender_role)

    # ── Relay-side replay pre-check for DataMessages ──────────────────────────
    if msg_type == "data":
        try:
            seq = int(payload["seq"])
        except (KeyError, TypeError, ValueError):
            seq = -1

        if seq >= 0:
            seen = _seen_seqs_for_sender(room, sender_role)
            if seq in seen:
                reason = f"sequence number {seq} already used"
                await _send(sender_ws, _rejection(reason))
                # Also alert Eve so she sees the same rejection
                if room.eve:
                    await _send(room.eve, _rejection(reason))
                return
            seen.add(seq)

    # ── Forward to peer ───────────────────────────────────────────────────────
    if peer_ws:
        await _send(peer_ws, envelope)

    # ── Mirror every frame to Eve ─────────────────────────────────────────────
    if room.eve:
        await _send(room.eve, {
            "type": "mirror",
            "payload": {
                "from":  sender_role,
                "frame": envelope,
                "ts":    time.time(),
            },
        })


# ── Eve message handler ───────────────────────────────────────────────────────

async def _handle_eve(
    room: Room,
    eve_ws: WebSocket,
    envelope: dict,
) -> None:
    msg_type = envelope.get("type")
    payload  = envelope.get("payload", {})

    if msg_type != "inject":
        await _send(eve_ws, _rejection(
            f"Eve may only send 'inject' messages; got {msg_type!r}"
        ))
        return

    target_role  = payload.get("target")
    frame        = payload.get("frame", {})
    frame_type   = frame.get("type")
    frame_payload = frame.get("payload", {})

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

    # ── ClientHello pre-checks (downgrade + MITM) ─────────────────────────────
    if frame_type == "client_hello":
        # 1. Downgrade check — are PQC fields present and correctly sized?
        reason = _check_client_hello_pqc(frame_payload)
        if reason:
            await _send(eve_ws, _rejection(reason))
            return

        # 2. MITM check — do the public keys match the original ClientHello?
        sender_of_hello = frame_payload.get("role")
        original_key    = f"{sender_of_hello}_original_hello"
        original_hello  = getattr(room, original_key, None)
        if original_hello is not None:
            reason = _check_key_substitution(frame_payload, original_hello)
            if reason:
                await _send(eve_ws, _rejection(reason))
                return

    # ── DataMessage replay pre-check ──────────────────────────────────────────
    if frame_type == "data":
        try:
            seq = int(frame_payload["seq"])
        except (KeyError, TypeError, ValueError):
            seq = -1

        if seq >= 0:
            seen = _seen_seqs_for_inject_target(room, target_role)
            if seq in seen:
                reason = f"sequence number {seq} already used"
                await _send(eve_ws, _rejection(reason))
                return

    # ── Deliver injected frame to target ──────────────────────────────────────
    await _send(target_ws, frame)
    await _send(eve_ws, {
        "type": "inject_ok",
        "payload": {"target": target_role, "frame_type": frame_type},
    })
    logger.info(
        "Room %s: Eve injected %r to %s", room.code, frame_type, target_role
    )
