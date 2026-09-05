/**
 * session.js
 * Full hybrid handshake and post-handshake secure session.
 *
 * Direct JavaScript port of network/session.py.
 * Same handshake flow, same HKDF_INFO, same transcript, same rejection strings.
 *
 * SessionInitiator  (Alice) — builds ClientHello, processes KemResponse
 * SessionResponder  (Bob)   — validates ClientHello, builds KemResponse
 * SecureSession             — post-handshake AES-GCM with replay protection
 *
 * Replay detection order for SecureSession.decrypt():
 *   GCM verification runs FIRST, replay check SECOND.
 *   Rationale: tamper attacks use a fresh seq so GCM fails before replay check;
 *   replay attacks reuse the original ciphertext so GCM passes but replay fires.
 *   This gives each attack its correct distinct rejection string.
 *   (Differs from Python reference which checks replay first — intentional for demo.)
 */

import { generateX25519Keypair, x25519Exchange, hkdfDerive } from './classical.js';
import {
  kemGenerateKeypair, kemEncapsulate, kemDecapsulate,
  signGenerateKeypair, signMessage, verifySignature,
  SignatureVerificationError,
} from './pqc.js';
import { encrypt, decrypt, DecryptionError } from './symmetric.js';
import {
  HKDF_INFO,
  computeTranscript,
  validateClientHello,
  buildClientHello,
  buildKemResponse,
  buildDataMessage,
  parseDataMessage,
  seqAad,
  bytesToB64,
  b64ToBytes,
  ProtocolError,
  ReplayError,
} from './protocol.js';

// ── Timing record ──────────────────────────────────────────────────────────

export class HandshakeTiming {
  constructor() {
    this.keygenMs  = 0;
    this.x25519Ms  = 0;
    this.kemMs     = 0;
    this.hkdfMs    = 0;
    this.signMs    = 0;
    this.verifyMs  = 0;
    this.totalMs   = 0;
  }
  toDict() {
    return {
      keygen_ms:  +this.keygenMs.toFixed(3),
      x25519_ms:  +this.x25519Ms.toFixed(3),
      kem_ms:     +this.kemMs.toFixed(3),
      hkdf_ms:    +this.hkdfMs.toFixed(3),
      sign_ms:    +this.signMs.toFixed(3),
      verify_ms:  +this.verifyMs.toFixed(3),
      total_ms:   +this.totalMs.toFixed(3),
    };
  }
}

// ── SessionInitiator (Alice) ───────────────────────────────────────────────

export class SessionInitiator {
  /**
   * Constructs Alice's session state and generates all keypairs.
   * Call await init() after construction.
   */
  constructor() {
    this.timing   = new HandshakeTiming();
    this._session = null;
    // Will be set by init()
    this._xPriv   = null;
    this.xPub     = null;
    this.kemPk    = null;
    this._kemSk   = null;
    this.sigPk    = null;
    this._sigSk   = null;
  }

  /** Async initializer — must be awaited before using other methods. */
  async init() {
    const t0 = performance.now();
    const { privateKey: xPriv, publicKey: xPub } = await generateX25519Keypair();
    const { publicKey: kemPk, secretKey: kemSk }  = kemGenerateKeypair();
    const { publicKey: sigPk, secretKey: sigSk }  = signGenerateKeypair();
    this.timing.keygenMs = performance.now() - t0;

    this._xPriv = xPriv;
    this.xPub   = xPub;
    this.kemPk  = kemPk;
    this._kemSk = kemSk;
    this.sigPk  = sigPk;
    this._sigSk = sigSk;
    return this;
  }

  /** Build the ClientHello payload to send to the relay. */
  buildClientHello() {
    return buildClientHello('alice', this.xPub, this.kemPk, this.sigPk);
  }

  /**
   * Process Bob's KemResponse. Derives session key and verifies his signature.
   * @param {object} responsePayload  KemResponse payload dict from relay
   * @returns {SecureSession}
   * @throws {SignatureVerificationError} if Bob's transcript signature is invalid
   */
  async processKemResponse(responsePayload) {
    const t0 = performance.now();

    const peerXPub = b64ToBytes(responsePayload.x25519_pk);
    const kemCt    = b64ToBytes(responsePayload.kem_ct);
    const peerSigPk = b64ToBytes(responsePayload.sig_pk);
    const signature = b64ToBytes(responsePayload.signature);

    // X25519 exchange
    const tx = performance.now();
    const xSs = await x25519Exchange(this._xPriv, peerXPub);
    this.timing.x25519Ms = performance.now() - tx;

    // ML-KEM decapsulate
    const tk = performance.now();
    const kemSs = kemDecapsulate(this._kemSk, kemCt);
    this.timing.kemMs = performance.now() - tk;

    // HKDF hybrid derivation
    const th = performance.now();
    const sessionKey = await hkdfDerive(xSs, kemSs, HKDF_INFO);
    this.timing.hkdfMs = performance.now() - th;

    // Compute transcript (using keys WE sent and keys Bob sent)
    const transcript = await computeTranscript(
      this.xPub, this.kemPk, this.sigPk,
      peerXPub, peerSigPk,
      kemCt,
    );

    // Verify Bob's ML-DSA-65 signature over the transcript
    const tv = performance.now();
    verifySignature(peerSigPk, transcript, signature);  // throws on failure
    this.timing.verifyMs = performance.now() - tv;

    this.timing.totalMs = performance.now() - t0;
    this._session = new SecureSession(sessionKey, 'alice');
    return this._session;
  }

  get session() {
    if (!this._session) throw new Error('Handshake not yet complete');
    return this._session;
  }
}

// ── SessionResponder (Bob) ─────────────────────────────────────────────────

export class SessionResponder {
  constructor() {
    this.timing   = new HandshakeTiming();
    this._session = null;
    this._xPriv   = null;
    this.xPub     = null;
    this.sigPk    = null;
    this._sigSk   = null;
  }

  /** Async initializer — must be awaited. */
  async init() {
    const t0 = performance.now();
    const { privateKey: xPriv, publicKey: xPub } = await generateX25519Keypair();
    const { publicKey: sigPk, secretKey: sigSk }  = signGenerateKeypair();
    this.timing.keygenMs = performance.now() - t0;

    this._xPriv = xPriv;
    this.xPub   = xPub;
    this.sigPk  = sigPk;
    this._sigSk = sigSk;
    return this;
  }

  /**
   * Process Alice's ClientHello. Encapsulates, derives session key, signs transcript.
   * @param {object} helloPayload       ClientHello payload dict
   * @param {object|null} originalHello Original ClientHello for MITM pre-check
   * @returns {object} KemResponse payload dict to send back
   * @throws {ProtocolError} on downgrade or key substitution
   */
  async processClientHello(helloPayload, originalHello = null) {
    const t0 = performance.now();

    // Pre-crypto validation (catches downgrade and MITM)
    validateClientHello(helloPayload, originalHello);

    const peerXPub = b64ToBytes(helloPayload.x25519_pk);
    const kemPk    = b64ToBytes(helloPayload.kem_pk);
    const peerSigPk = b64ToBytes(helloPayload.sig_pk);

    // X25519 exchange
    const tx = performance.now();
    const xSs = await x25519Exchange(this._xPriv, peerXPub);
    this.timing.x25519Ms = performance.now() - tx;

    // ML-KEM encapsulate to Alice's public key
    const tk = performance.now();
    const { cipherText: kemCt, sharedSecret: kemSs } = kemEncapsulate(kemPk);
    this.timing.kemMs = performance.now() - tk;

    // HKDF hybrid derivation
    const th = performance.now();
    const sessionKey = await hkdfDerive(xSs, kemSs, HKDF_INFO);
    this.timing.hkdfMs = performance.now() - th;

    // Compute transcript
    const transcript = await computeTranscript(
      peerXPub, kemPk, peerSigPk,
      this.xPub, this.sigPk,
      kemCt,
    );

    // Sign transcript with our ML-DSA-65 key
    const ts = performance.now();
    const signature = signMessage(this._sigSk, transcript);
    this.timing.signMs = performance.now() - ts;

    this.timing.totalMs = performance.now() - t0;
    this._session = new SecureSession(sessionKey, 'bob');

    return buildKemResponse(kemCt, this.xPub, this.sigPk, signature);
  }

  get session() {
    if (!this._session) throw new Error('Handshake not yet complete');
    return this._session;
  }
}

// ── SecureSession ──────────────────────────────────────────────────────────

export class SecureSession {
  /**
   * @param {Uint8Array} sessionKey  32-byte session key
   * @param {string}     role        'alice' or 'bob'
   */
  constructor(sessionKey, role) {
    if (sessionKey.length !== 32) throw new Error('Session key must be 32 bytes');
    this._key      = sessionKey;
    this._role     = role;
    this._sendSeq  = 0;
    this._recvSeen = new Set();
  }

  /**
   * Encrypt a plaintext message and return a DataMessage payload.
   * @param {Uint8Array|string} plaintext
   * @returns {Promise<object>} DataMessage payload ready to send
   */
  async encryptMessage(plaintext) {
    const pt  = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    const seq = this._sendSeq++;
    const aad = seqAad(seq);
    const { nonce, ciphertext, tag } = await encrypt(this._key, pt, aad);
    return buildDataMessage(seq, nonce, ciphertext, tag);
  }

  /**
   * Decrypt a DataMessage payload.
   *
   * Ordering: GCM verification runs BEFORE replay check.
   * This ensures:
   *   - Tamper attack (corrupted ciphertext, fresh seq) → DecryptionError "GCM auth tag mismatch"
   *   - Replay attack (original frame, same seq)        → ReplayError "sequence number N already used"
   *
   * @param {object} payload  DataMessage payload from relay
   * @returns {Promise<Uint8Array>} Decrypted plaintext bytes
   * @throws {DecryptionError} "GCM auth tag mismatch"
   * @throws {ReplayError}     "sequence number N already used"
   */
  async decryptMessage(payload) {
    const { seq, nonce, ciphertext, tag } = parseDataMessage(payload);
    const aad = seqAad(seq);

    // GCM first — tamper attacks are caught here even if seq was unseen
    const plaintext = await decrypt(this._key, nonce, ciphertext, tag, aad);

    // Replay check after successful decryption
    if (this._recvSeen.has(seq)) {
      throw new ReplayError(`sequence number ${seq} already used`);
    }
    this._recvSeen.add(seq);

    return plaintext;
  }

  get nextSendSeq() { return this._sendSeq; }
  get seenSeqs()    { return new Set(this._recvSeen); }
}
