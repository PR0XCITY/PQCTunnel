# PQCTunnel

A real-time secure messaging demo where three people connect from separate devices, two of them chat through a genuine post-quantum encrypted tunnel, and the third actively tries to break it.

The point of this project is that Eve's attacks fail against the actual cryptography, not a simulation of it. The rejection messages you see in the Eve console come from real ML-KEM and ML-DSA verification failures thrown by client-side JavaScript code running @noble/post-quantum. Nothing is mocked.

Built as a computer science college project and portfolio piece.

---

## What makes it "post-quantum"

Classical secure channels rely on problems like RSA factoring and elliptic curve discrete logs, which a sufficiently large quantum computer could solve. This project uses the two NIST post-quantum standards (finalized in 2024) alongside classical crypto, so the channel stays secure even if one of the two layers is broken.

| Layer | Algorithm | What it does |
|---|---|---|
| Key exchange (classical) | X25519 | Diffie-Hellman over Curve25519 |
| Key exchange (post-quantum) | ML-KEM-768 (FIPS 203) | Kyber-based key encapsulation |
| Key derivation | HKDF-SHA-256 | Combines both shared secrets into one session key |
| Authentication | ML-DSA-65 (FIPS 204) | Dilithium-based digital signatures on the handshake transcript |
| Symmetric encryption | AES-256-GCM | Encrypts all messages after the handshake |
| Replay protection | Monotonic sequence numbers in GCM AAD | Each message has a sequence number bound into the auth tag |

The session key comes from both X25519 and ML-KEM shared secrets fed into HKDF together. Breaking just one of them does not break the channel.

---

## Architecture

```
Alice (browser)                 Relay (Render)                Bob (browser)
      |                               |                              |
      |--- ClientHello (keys) ------->|--- ClientHello ------------->|
      |                               |                              |
      |<-- KemResponse (ct + sig) ----|<-- KemResponse --------------|
      |                               |                              |
      |=== ML-KEM decapsulate ========|                              |
      |=== HKDF derive session key ===|========= same session key ===|
      |=== verify ML-DSA signature ===|                              |
      |                               |                              |
      |--- AES-GCM encrypted msg ---->|--- forward ----------------->|
      |                               |--- mirror to Eve ----------->|
```

The relay is completely blind. It forwards bytes it cannot read and has no access to any private key or session key. All cryptography runs inside the browser using Web Crypto API and @noble/post-quantum.

Eve connects to the same room and receives a copy of every frame. She can attempt four attacks from the UI:

- **Replay** - resend a captured message to the same recipient
- **Tamper** - flip a byte in the ciphertext before replaying
- **Downgrade** - strip the post-quantum fields from the handshake
- **Key substitution** - replace the initiator's public keys with Eve's own

Every one of those attacks gets caught, either by the relay's structural pre-check (for downgrade and MITM) or by the client-side cryptography (for replay and tamper). The exact rejection reason appears in Eve's console.

---

## Tech stack

**Backend (relay server)**
- Python 3.12, FastAPI, uvicorn, websockets
- Docker (single-stage, ~24 second build, no C toolchain needed)
- Deployed on Render free tier

**Frontend**
- React + Vite
- @noble/post-quantum for ML-KEM-768 and ML-DSA-65
- Web Crypto API for AES-256-GCM, HKDF, X25519
- Deployed on Vercel

**Python reference implementation** (not used in the live demo, kept for verification)
- liboqs-python 0.16.0 for ML-KEM and ML-DSA
- PyCA cryptography for classical operations
- 73 tests, all passing, zero mocks

---

## Repository layout

```
PQCTunnel/
|-- crypto/                     Python reference implementation (Steps 1-2)
|   |-- classical.py            X25519 + HKDF
|   |-- pqc.py                  ML-KEM-768 + ML-DSA-65 via liboqs
|   `-- symmetric.py            AES-256-GCM
|-- network/
|   |-- protocol.py             Handshake message formats, transcript hash
|   |-- session.py              SessionInitiator, SessionResponder, SecureSession
|   `-- server.py               Blind WebSocket relay (zero crypto)
|-- frontend/                   React/Vite app (Steps 5-8, in progress)
|   `-- src/crypto/             JS reimplementation of the same protocol
|-- tests/
|   |-- roundtrip_demo.py       Proof script, prints every intermediate value
|   |-- test_crypto.py          25 unit tests for the Python crypto layer
|   |-- test_session.py         33 integration tests for the handshake
|   `-- test_server.py          15 integration tests for the relay
|-- Dockerfile                  Simple relay image (no liboqs, ~24s build)
|-- Dockerfile.dev              Dev image with liboqs for running Python tests
|-- render.yaml                 Render deployment config
`-- requirements-server.txt     Server-only deps (no liboqs)
```

---

## Running locally

### Option 1: relay only (simple, no crypto deps)

```bash
docker build -t pqctunnel-relay .
docker run --rm -p 8000:8000 pqctunnel-relay
curl http://localhost:8000/health
# {"status": "ok"}
```

### Option 2: Python crypto tests (needs the liboqs dev image)

```bash
docker build -f Dockerfile.dev -t pqctunnel-test .
docker run --rm -e PYTHONPATH=/app -v "$(pwd):/app" pqctunnel-test \
  sh -c "pip install -q pytest pytest-asyncio && python -m pytest tests/test_crypto.py tests/test_session.py -v"
```

The dev image takes about 5-6 minutes to build the first time because liboqs compiles from source. Subsequent builds are cached.

### Option 3: proof script (shows real intermediate crypto values)

```bash
docker run --rm -e PYTHONPATH=/app -v "$(pwd):/app" pqctunnel-test \
  python tests/roundtrip_demo.py
```

This prints every public key, shared secret, KEM ciphertext, GCM nonce, ciphertext, and decrypted plaintext as hex, then deliberately corrupts a ciphertext byte and a signature byte to show the real thrown exceptions.

---

## Deploying to Render

1. Fork or push this repo to GitHub
2. Go to [render.com](https://render.com), create a new Web Service
3. Connect your GitHub repo, select "Existing" when it asks about configuration (it will find `render.yaml`)
4. Deploy. The Docker build takes about a minute since there is no liboqs compile step.
5. Once live, verify with:

```bash
curl https://your-service.onrender.com/health
# {"status": "ok"}
```

Note that the free tier puts services to sleep after 15 minutes of no traffic. The first request after idle takes 30-60 seconds. This is expected behavior.

---

## Deploying the frontend to Vercel

Coming in Step 5. The frontend goes in `frontend/` and gets deployed as a separate Vercel project.

---

## Rejection vocabulary

These are the exact strings that appear in Eve's console for each blocked attack. They come from client-side JS, not from the relay.

| Attack | Rejection |
|---|---|
| Replay | `"sequence number N already used"` |
| Tamper | `"GCM auth tag mismatch"` |
| Downgrade | `"malformed ClientHello: PQC fields missing"` |
| Key substitution (pre-check) | `"public key does not match session identity"` |
| Key substitution (crypto backstop) | `"ML-DSA signature verification failed: transcript hash mismatch"` |

---

## Test results

All tests run inside Docker against real cryptographic operations. No mocks, no stubs, no hardcoded success paths.

```
tests/test_crypto.py    25 passed
tests/test_session.py   33 passed
tests/test_server.py    15 passed
--------------------------------
Total                   73 passed
```

---

## What is still being built

- [ ] Step 4: Render deployment verified
- [ ] Step 5: Frontend (React, @noble/post-quantum, real client-side handshake)
- [ ] Step 6: Eve's attack buttons wired to real injections
- [ ] Step 7: Scoreboard, timing panel, exportable attack log
- [ ] Step 8: End-to-end test across 3 physical machines

---

## License

MIT
