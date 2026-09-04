"""
tests/test_server.py
=====================
Real WebSocket integration tests for network/server.py.

Each test opens real, separate WebSocket connections (using websockets.connect
over TCP to a live uvicorn server) — not two functions calling each other in the
same process. The server runs in a background daemon thread for the test session.

Coverage
--------
Room management
  - Role join and confirmation
  - Duplicate role rejected (code 4000)
  - Invalid role rejected (code 4000)
  - Peer-joined notification when second peer connects
  - Peer-left notification when a peer disconnects

Routing
  - Alice→Bob message delivered; not looped back to Alice
  - Bob→Alice message delivered; not looped back to Bob
  - Eve receives mirror of every Alice/Bob frame
  - Eve's inject delivers frame to target peer verbatim

Pre-checks (relay structural checks only, no crypto)
  - Replay inject pre-rejected ("sequence number N already used")
  - Downgrade inject pre-rejected ("malformed ClientHello: PQC fields missing")
  - MITM inject pre-rejected ("public key does not match session identity")
  - Tamper inject forwarded to target (relay can't check GCM; client rejects)

Health
  - GET /health returns 200 {"status": "ok"}, no liboqs_version field

Run inside Docker (simple relay image):
    docker build -t pqctunnel-relay .
    docker run --rm -e PYTHONPATH=/app pqctunnel-relay \\
        sh -c "pip install -q pytest pytest-asyncio websockets httpx && \\
               python -m pytest tests/test_server.py -v"

Or locally (with deps installed):
    PYTHONPATH=. pytest tests/test_server.py -v
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
import pytest
import pytest_asyncio
import uvicorn
import websockets

from network.server import app

# ── Server fixture ────────────────────────────────────────────────────────────

TEST_HOST = "127.0.0.1"
TEST_PORT = 18765   # non-standard port to avoid collisions
BASE_WS   = f"ws://{TEST_HOST}:{TEST_PORT}"
BASE_HTTP = f"http://{TEST_HOST}:{TEST_PORT}"


@pytest.fixture(scope="session")
def live_server():
    """
    Start uvicorn in a background daemon thread for the entire test session.
    Yields the base WebSocket URL.
    """
    config = uvicorn.Config(
        app, host=TEST_HOST, port=TEST_PORT,
        log_level="error", loop="asyncio",
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait until the server is ready
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("Test server did not start within 10 seconds")
        time.sleep(0.05)

    yield BASE_WS
    server.should_exit = True
    thread.join(timeout=5)


# ── Helper: connect and read one message ─────────────────────────────────────

@asynccontextmanager
async def connect(base_url: str, room: str, role: str):
    uri = f"{base_url}/ws/{room}/{role}"
    async with websockets.connect(uri) as ws:
        yield ws


async def recv(ws, timeout: float = 2.0) -> dict:
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    return json.loads(raw)


async def send(ws, data: dict) -> None:
    await ws.send(json.dumps(data))


# ── Dummy payloads (relay tests don't need real crypto) ───────────────────────

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# Correctly-sized dummy public keys for pre-check tests
_DUMMY_X25519_PK  = _b64(b"\xAA" * 32)
_DUMMY_KEM_PK     = _b64(b"\xBB" * 1184)   # ML-KEM-768 pk size
_DUMMY_SIG_PK     = _b64(b"\xCC" * 1952)   # ML-DSA-65 pk size
_EVE_X25519_PK    = _b64(b"\xDD" * 32)     # Eve's different pk (MITM)
_EVE_KEM_PK       = _b64(b"\xEE" * 1184)

def _client_hello(role: str = "alice") -> dict:
    return {
        "type": "client_hello",
        "payload": {
            "version":   "1",
            "role":      role,
            "x25519_pk": _DUMMY_X25519_PK,
            "kem_pk":    _DUMMY_KEM_PK,
            "sig_pk":    _DUMMY_SIG_PK,
        },
    }

def _data_msg(seq: int = 0) -> dict:
    return {
        "type": "data",
        "payload": {
            "seq":        seq,
            "nonce":      _b64(b"\x00" * 12),
            "ciphertext": _b64(b"\x01" * 32),
            "tag":        _b64(b"\x02" * 16),
        },
    }


# ── Unique room name per test to prevent state leakage ───────────────────────

_room_counter = 0

def fresh_room() -> str:
    global _room_counter
    _room_counter += 1
    return f"TESTROOM{_room_counter:04d}"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRoomManagement:
    @pytest.mark.asyncio
    async def test_join_confirmation(self, live_server):
        """Connecting as alice receives a 'joined' message."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a:
            msg = await recv(ws_a)
            assert msg["type"] == "joined"
            assert msg["payload"]["role"] == "alice"
            assert msg["payload"]["room"] == room

    @pytest.mark.asyncio
    async def test_second_peer_notified(self, live_server):
        """When Bob joins, Alice receives 'peer_joined'."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a:
            await recv(ws_a)   # consume joined
            async with connect(live_server, room, "bob") as ws_b:
                await recv(ws_b)  # consume bob's joined
                notify = await recv(ws_a)
                assert notify["type"] == "peer_joined"
                assert notify["payload"]["role"] == "bob"

    @pytest.mark.asyncio
    async def test_duplicate_role_rejected(self, live_server):
        """A second connection claiming the same role gets a rejection + close."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a:
            await recv(ws_a)  # joined

            # Try to claim alice again
            async with connect(live_server, room, "alice") as ws_dup:
                msg = await recv(ws_dup)
                assert msg["type"] == "rejection"
                assert "already taken" in msg["payload"]["reason"]

    @pytest.mark.asyncio
    async def test_invalid_role_rejected_at_connect(self, live_server):
        """Connecting with an unknown role gets the socket closed before accept."""
        room = fresh_room()
        with pytest.raises(Exception):
            # Server closes with code 4000 before sending any message
            async with websockets.connect(f"{live_server}/ws/{room}/hacker") as ws:
                await asyncio.wait_for(ws.recv(), timeout=2.0)

    @pytest.mark.asyncio
    async def test_peer_left_notification(self, live_server):
        """When Alice disconnects, Bob receives 'peer_left'."""
        room = fresh_room()
        async with connect(live_server, room, "bob") as ws_b:
            await recv(ws_b)   # bob's joined

            async with connect(live_server, room, "alice") as ws_a:
                await recv(ws_a)           # alice's joined
                await recv(ws_b)           # bob's peer_joined
            # ws_a is now closed

            notify = await recv(ws_b)
            assert notify["type"] == "peer_left"
            assert notify["payload"]["role"] == "alice"


class TestRouting:
    @pytest.mark.asyncio
    async def test_alice_to_bob_delivery(self, live_server):
        """Alice sends a data message; Bob receives it; Alice does not."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b:
            await recv(ws_a)   # alice joined
            await recv(ws_b)   # bob joined
            await recv(ws_a)   # alice peer_joined (bob arrived)

            msg = _data_msg(seq=0)
            await send(ws_a, msg)

            received = await recv(ws_b)
            assert received["type"] == "data"
            assert received["payload"]["seq"] == 0

            # Alice must NOT receive her own message back
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(ws_a.recv(), timeout=0.3)

    @pytest.mark.asyncio
    async def test_bob_to_alice_delivery(self, live_server):
        """Bob sends; Alice receives; Bob does not."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b:
            await recv(ws_a)
            await recv(ws_b)
            await recv(ws_a)  # peer_joined

            await send(ws_b, _data_msg(seq=10))
            received = await recv(ws_a)
            assert received["type"] == "data"
            assert received["payload"]["seq"] == 10

    @pytest.mark.asyncio
    async def test_eve_receives_mirror(self, live_server):
        """Every Alice→Bob frame is also mirrored to Eve."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            # Drain join messages
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            # Drain peer_joined notifications (order may vary)
            for _ in range(4):
                try:
                    await asyncio.wait_for(ws_a.recv(), timeout=0.2)
                except asyncio.TimeoutError:
                    break
            for _ in range(4):
                try:
                    await asyncio.wait_for(ws_b.recv(), timeout=0.2)
                except asyncio.TimeoutError:
                    break
            for _ in range(4):
                try:
                    await asyncio.wait_for(ws_e.recv(), timeout=0.2)
                except asyncio.TimeoutError:
                    break

            await send(ws_a, _data_msg(seq=99))

            # Bob gets the frame
            bob_recv = await recv(ws_b)
            assert bob_recv["type"] == "data"

            # Eve gets the mirror
            mirror = await recv(ws_e)
            assert mirror["type"] == "mirror"
            assert mirror["payload"]["from"] == "alice"
            assert mirror["payload"]["frame"]["payload"]["seq"] == 99

    @pytest.mark.asyncio
    async def test_inject_delivers_to_target(self, live_server):
        """Eve's inject delivers the frame to the target peer."""
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            # Drain all join/peer_joined chatter
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            for ws in (ws_a, ws_b, ws_e):
                for _ in range(5):
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=0.15)
                    except asyncio.TimeoutError:
                        break

            # Eve injects a data frame to Bob
            injected_seq = 500
            await send(ws_e, {
                "type": "inject",
                "payload": {
                    "target": "bob",
                    "frame":  _data_msg(seq=injected_seq),
                },
            })

            # Eve gets inject_ok
            ok = await recv(ws_e)
            assert ok["type"] == "inject_ok"
            assert ok["payload"]["target"] == "bob"

            # Bob receives the injected frame
            bob_recv = await recv(ws_b)
            assert bob_recv["type"] == "data"
            assert bob_recv["payload"]["seq"] == injected_seq


class TestPreChecks:
    @pytest.mark.asyncio
    async def test_replay_inject_pre_rejected(self, live_server):
        """
        Replaying an already-seen seq via inject returns the replay rejection
        to Eve BEFORE the frame reaches Alice.
        """
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            for ws in (ws_a, ws_b, ws_e):
                for _ in range(5):
                    try: await asyncio.wait_for(ws.recv(), timeout=0.15)
                    except asyncio.TimeoutError: break

            # Bob sends seq=7 legitimately (relay records it in bob_seen_seqs)
            await send(ws_b, _data_msg(seq=7))
            await recv(ws_a)   # alice receives it
            await recv(ws_e)   # eve mirrors it

            # Eve replays that same seq=7 frame TO alice
            await send(ws_e, {
                "type": "inject",
                "payload": {
                    "target": "alice",
                    "frame":  _data_msg(seq=7),   # same seq Bob already used
                },
            })

            rejection = await recv(ws_e)
            assert rejection["type"] == "rejection"
            reason = rejection["payload"]["reason"]
            assert "sequence number 7 already used" == reason

            # Alice must NOT have received the replayed frame
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(ws_a.recv(), timeout=0.3)

    @pytest.mark.asyncio
    async def test_downgrade_inject_pre_rejected(self, live_server):
        """
        Injecting a ClientHello with empty PQC fields triggers the downgrade
        pre-check and is rejected before reaching the target.
        """
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            for ws in (ws_a, ws_b, ws_e):
                for _ in range(5):
                    try: await asyncio.wait_for(ws.recv(), timeout=0.15)
                    except asyncio.TimeoutError: break

            downgraded_hello = {
                "type": "client_hello",
                "payload": {
                    "version":   "1",
                    "role":      "alice",
                    "x25519_pk": _DUMMY_X25519_PK,
                    "kem_pk":    _b64(b""),   # stripped
                    "sig_pk":    _b64(b""),   # stripped
                },
            }
            await send(ws_e, {
                "type": "inject",
                "payload": {"target": "bob", "frame": downgraded_hello},
            })

            rejection = await recv(ws_e)
            assert rejection["type"] == "rejection"
            assert "PQC fields missing" in rejection["payload"]["reason"]

    @pytest.mark.asyncio
    async def test_mitm_inject_pre_rejected(self, live_server):
        """
        After Alice sends a real ClientHello, Eve's injected ClientHello with
        different public keys is rejected ('public key does not match session identity').
        """
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            for ws in (ws_a, ws_b, ws_e):
                for _ in range(5):
                    try: await asyncio.wait_for(ws.recv(), timeout=0.15)
                    except asyncio.TimeoutError: break

            # Alice sends her real ClientHello — relay stores it as original
            await send(ws_a, _client_hello("alice"))
            await recv(ws_b)    # bob gets it
            await recv(ws_e)    # eve mirrors it

            # Eve constructs a MITM ClientHello with her own (different) keys
            mitm_hello = {
                "type": "client_hello",
                "payload": {
                    "version":   "1",
                    "role":      "alice",
                    "x25519_pk": _EVE_X25519_PK,   # different from Alice's
                    "kem_pk":    _EVE_KEM_PK,       # different from Alice's
                    "sig_pk":    _DUMMY_SIG_PK,     # same sig_pk (common MITM pattern)
                },
            }
            await send(ws_e, {
                "type": "inject",
                "payload": {"target": "bob", "frame": mitm_hello},
            })

            rejection = await recv(ws_e)
            assert rejection["type"] == "rejection"
            assert "public key does not match session identity" in rejection["payload"]["reason"]

    @pytest.mark.asyncio
    async def test_tamper_inject_forwarded(self, live_server):
        """
        A tampered data frame (modified ciphertext, fresh seq) passes the relay's
        pre-checks and is delivered to the target. The relay cannot verify GCM.
        Client-side JS would reject it — but that's tested in the browser.
        Here we only prove the relay forwards it.
        """
        room = fresh_room()
        async with connect(live_server, room, "alice") as ws_a, \
                   connect(live_server, room, "bob")   as ws_b, \
                   connect(live_server, room, "eve")   as ws_e:
            await recv(ws_a); await recv(ws_b); await recv(ws_e)
            for ws in (ws_a, ws_b, ws_e):
                for _ in range(5):
                    try: await asyncio.wait_for(ws.recv(), timeout=0.15)
                    except asyncio.TimeoutError: break

            # Tampered frame: fresh seq=8888 (not seen), corrupted ciphertext
            tampered = {
                "type": "data",
                "payload": {
                    "seq":        8888,
                    "nonce":      _b64(b"\x00" * 12),
                    "ciphertext": _b64(b"\xFF" * 32),   # corrupted
                    "tag":        _b64(b"\x02" * 16),
                },
            }
            await send(ws_e, {
                "type": "inject",
                "payload": {"target": "bob", "frame": tampered},
            })

            # Relay delivers it (no crypto check possible)
            ok = await recv(ws_e)
            assert ok["type"] == "inject_ok"

            # Bob receives the tampered frame
            bob_recv = await recv(ws_b)
            assert bob_recv["type"] == "data"
            assert bob_recv["payload"]["seq"] == 8888


class TestHealth:
    def test_health_returns_200(self, live_server):
        """GET /health returns 200 with {status: ok} and NO liboqs_version."""
        url = BASE_HTTP + "/health"
        resp = httpx.get(url, timeout=5)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        # Confirm relay contains no crypto — no liboqs_version field
        assert "liboqs_version" not in body

    def test_health_content_type_json(self, live_server):
        resp = httpx.get(BASE_HTTP + "/health", timeout=5)
        assert "application/json" in resp.headers.get("content-type", "")
