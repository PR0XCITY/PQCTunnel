# PQCTunnel

A Post-Quantum Secure Messenger that runs entirely in your browser.

This project is a hybrid post-quantum secure tunnel. It uses ML-KEM-768 for key encapsulation and X25519 for elliptic curve Diffie-Hellman, combining them to establish a secure channel. Once the keys are exchanged, messages are authenticated and encrypted using AES-256-GCM. 

The most important part: **All cryptography runs client-side.** The relay server is completely blind. It just routes WebSockets and has no idea what you are saying or what your keys are.

## What it does

We built three distinct roles:
1. **Alice (Initiator)**: Starts the secure session.
2. **Bob (Responder)**: Receives the session request and completes the handshake.
3. **Eve (Adversary)**: A Red-Team intercept console. Eve can view the raw encrypted traffic bouncing through the blind relay and attempt to launch attacks like Replay, Tampering, Downgrade, or Man-in-the-Middle.

## Tech Stack

* **Frontend**: React and Vite.
* **Cryptography**: `@noble/post-quantum`, `@noble/curves`, and standard Web Crypto APIs for AES-GCM and HKDF. 
* **Backend**: A simple Python WebSocket relay server using `websockets` and `asyncio`.
* **Styling**: Tailwind CSS with custom CSS variables for a dual-theme setup (Quantum Console for Alice/Bob, Red-Team Console for Eve).

## Project Structure

* `network/`: Contains the Python backend relay.
* `frontend/`: Contains the React application.
  * `frontend/src/crypto/`: The core JavaScript cryptography implementation.
  * `frontend/src/attacks/`: Modules for Eve to simulate attacks on the protocol.
  * `frontend/src/views/`: The UI components for Alice/Bob and Eve.

## How to run locally

1. **Start the Relay Server**:
   Make sure you have Python installed.
   ```bash
   pip install websockets
   python -m network.server
   ```
   The relay will start on `ws://localhost:8765`.

2. **Start the Frontend**:
   In a new terminal, navigate to the `frontend` directory.
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open the local URL provided by Vite in multiple browser windows to act as Alice, Bob, and Eve.

## Security Note

This is an educational project and a proof of concept for post-quantum cryptography in the browser. Do not use this for securing highly sensitive communications in production without a thorough security audit.

Enjoy exploring post-quantum secure channels!
