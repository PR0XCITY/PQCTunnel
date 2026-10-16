/**
 * session.js
 * Hybrid post-quantum handshake (protocol v2) and post-handshake secure session.
 *
 * SessionInitiator  (Alice) — builds ClientHello, processes KemResponse, sends ClientFinished
 * SessionResponder  (Bob)   — validates ClientHello, builds KemResponse, verifies ClientFinished
 * SecureSession             — AES-256-GCM with directional keys and replay protection
 *
 * Every handshake step and every encrypt/decrypt is recorded as a trace of
 * { label, detail, value?, secret?, ok, ms } entries so the UI can show the
 * real bytes at each stage. Traces are display-only; nothing reads them back.
 *
 * Decrypt order: seq validation → GCM verification → replay check.
 *   Tamper (fresh seq, corrupted ct)  → DecryptionError "GCM auth tag mismatch"
 *   Replay (original frame)           → ReplayError "sequence number N already used"
 *   Reflection (own frame sent back)  → DecryptionError (wrong directional key)
 */

import { generateX25519Keypair, x25519Exchange, hkdfDerive } from './classical.js';
import {
  kemGenerateKeypair, kemEncapsulate, kemDecapsulate,
  signGenerateKeypair, signMessage, verifySignature,
} from './pqc.js';
import { encrypt, decrypt } from './symmetric.js';
import {
  HKDF_INFO,
  SIG_LABEL_INITIATOR,
  SIG_LABEL_RESPONDER,
  computeTranscript,
  deriveSafetyCode,
  signedPayload,
  validateClientHello,
  validateKemResponse,
  validateClientFinished,
  buildClientHello,
  buildKemResponse,
  buildClientFinished,
  buildDataMessage,
  parseDataMessage,
  seqAad,
  b64ToBytes,
  toHex,
  ProtocolError,
  ReplayError,
} from './protocol.js';

const now = () => performance.now();

// ── Timing + trace record ──────────────────────────────────────────────────

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

/** Runs one handshake step, timing it and appending a trace entry. */
class StepLog {
  constructor(timing) { this.timing = timing; this.steps = []; }

  async run(label, timingField, fn, describe = () => ({})) {
    const t = now();
    try {
      const result = await fn();
      const ms = now() - t;
      if (timingField) this.timing[timingField] += ms;
      this.steps.push({ label, ms, ok: true, ...describe(result) });
      return result;
    } catch (e) {
      this.steps.push({ label, ms: now() - t, ok: false, detail: e.message });
      throw e;
    }
  }
}

async function deriveDirectionalKeys(xSs, kemSs, transcript) {
  const okm = await hkdfDerive(xSs, kemSs, HKDF_INFO, 64, transcript);
  return { aliceToBob: okm.slice(0, 32), bobToAlice: okm.slice(32, 64) };
}

const short = (bytes, n = 24) => {
  const h = toHex(bytes);
  return h.length > n * 2 ? `${h.slice(0, n * 2)}…` : h;
};

// ── SessionInitiator (Alice) ───────────────────────────────────────────────

export class SessionInitiator {
  constructor() {
    this.timing   = new HandshakeTiming();
    this.log      = new StepLog(this.timing);
    this._session = null;
    this.safetyCode = null;
  }

  /** Generate all keypairs. Must be awaited before using other methods. */
  async init() {
    const t0 = now();
    const x = await this.log.run('Generate X25519 keypair', 'keygenMs',
      () => generateX25519Keypair(),
      r => ({ detail: 'Classical ECDH key (32 B public)', value: toHex(r.publicKey) }));
    const kem = await this.log.run('Generate ML-KEM-768 keypair', 'keygenMs',
      () => kemGenerateKeypair(),
      r => ({ detail: `FIPS 203 KEM — pk ${r.publicKey.length} B, sk ${r.secretKey.length} B`, value: short(r.publicKey) }));
    const sig = await this.log.run('Generate ML-DSA-65 keypair', 'keygenMs',
      () => signGenerateKeypair(),
      r => ({ detail: `FIPS 204 signature key — pk ${r.publicKey.length} B`, value: short(r.publicKey) }));
    this._initMs = now() - t0;

    this._xPriv = x.privateKey;
    this.xPub   = x.publicKey;
    this.kemPk  = kem.publicKey;
    this._kemSk = kem.secretKey;
    this.sigPk  = sig.publicKey;
    this._sigSk = sig.secretKey;
    return this;
  }

  /** Build the ClientHello payload to send to the relay. */
  buildClientHello() {
    this.log.steps.push({ label: 'Send ClientHello →', ok: true, ms: 0, wire: true,
      detail: 'x25519_pk + kem_pk + sig_pk (public keys only)' });
    return buildClientHello('alice', this.xPub, this.kemPk, this.sigPk);
  }

  /**
   * Process Bob's KemResponse: verify his signature, derive keys, sign the
   * transcript ourselves.
   * @returns {Promise<object>} ClientFinished payload to send to Bob
   * @throws {ProtocolError|SignatureVerificationError}
   */
  async processKemResponse(responsePayload) {
    const t0 = now();
    const L = this.log;
    L.steps.push({ label: '← Receive KemResponse', ok: true, ms: 0, wire: true,
      detail: 'kem_ct + x25519_pk + sig_pk + signature' });

    await L.run('Validate KemResponse fields', null,
      () => validateKemResponse(responsePayload),
      () => ({ detail: 'All field sizes correct (no downgrade)' }));

    const peerXPub  = b64ToBytes(responsePayload.x25519_pk);
    const kemCt     = b64ToBytes(responsePayload.kem_ct);
    const peerSigPk = b64ToBytes(responsePayload.sig_pk);
    const signature = b64ToBytes(responsePayload.signature);

    const xSs = await L.run('X25519 Diffie-Hellman', 'x25519Ms',
      () => x25519Exchange(this._xPriv, peerXPub),
      r => ({ detail: 'Classical shared secret (32 B)', value: toHex(r), secret: true }));

    const kemSs = await L.run('ML-KEM-768 decapsulate', 'kemMs',
      () => kemDecapsulate(this._kemSk, kemCt),
      r => ({ detail: `Recovered PQ shared secret from ${kemCt.length} B ciphertext`, value: toHex(r), secret: true }));

    const transcript = await L.run('Transcript hash (SHA-256)', null,
      () => computeTranscript(this.xPub, this.kemPk, this.sigPk, peerXPub, peerSigPk, kemCt),
      r => ({ detail: 'Hash of every public value exchanged', value: toHex(r) }));

    await L.run("Verify Bob's ML-DSA-65 signature", 'verifyMs',
      () => verifySignature(peerSigPk, signedPayload(SIG_LABEL_RESPONDER, transcript), signature),
      () => ({ detail: `${signature.length} B signature valid over transcript` }));

    const keys = await L.run('HKDF-SHA-256 → directional keys', 'hkdfMs',
      () => deriveDirectionalKeys(xSs, kemSs, transcript),
      r => ({ detail: 'IKM = x25519_ss ‖ kem_ss, salt = transcript', value: `A→B ${toHex(r.aliceToBob)}\nB→A ${toHex(r.bobToAlice)}`, secret: true }));

    const mySig = await L.run('Sign transcript (ML-DSA-65)', 'signMs',
      () => signMessage(this._sigSk, signedPayload(SIG_LABEL_INITIATOR, transcript)),
      r => ({ detail: `Proves Alice holds her advertised key (${r.length} B)` }));

    this.safetyCode = await L.run('Derive safety code', null,
      () => deriveSafetyCode(transcript),
      r => ({ detail: 'Compare with peer out-of-band to rule out MITM', value: `${r.emoji.join(' ')}  ${r.digits}` }));

    L.steps.push({ label: 'Send ClientFinished →', ok: true, ms: 0, wire: true,
      detail: "Alice's transcript signature" });

    this.transcript = transcript;
    this.timing.keygenMs = this._initMs;
    this.timing.totalMs = this._initMs + (now() - t0);
    this._session = new SecureSession(keys.aliceToBob, keys.bobToAlice, 'alice');
    return buildClientFinished(mySig);
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
    this.log      = new StepLog(this.timing);
    this._session = null;
    this._pending = null;
    this.safetyCode = null;
  }

  /** Generate keypairs. Must be awaited. */
  async init() {
    const t0 = now();
    const x = await this.log.run('Generate X25519 keypair', 'keygenMs',
      () => generateX25519Keypair(),
      r => ({ detail: 'Classical ECDH key (32 B public)', value: toHex(r.publicKey) }));
    const sig = await this.log.run('Generate ML-DSA-65 keypair', 'keygenMs',
      () => signGenerateKeypair(),
      r => ({ detail: `FIPS 204 signature key — pk ${r.publicKey.length} B`, value: short(r.publicKey) }));
    this._initMs = now() - t0;

    this._xPriv = x.privateKey;
    this.xPub   = x.publicKey;
    this.sigPk  = sig.publicKey;
    this._sigSk = sig.secretKey;
    return this;
  }

  /**
   * Process Alice's ClientHello: encapsulate, derive keys, sign the transcript.
   * The session is not usable until processClientFinished() succeeds.
   * @returns {Promise<object>} KemResponse payload to send back
   * @throws {ProtocolError} on downgrade / malformed hello
   */
  async processClientHello(helloPayload) {
    const t0 = now();
    const L = this.log;
    L.steps.push({ label: '← Receive ClientHello', ok: true, ms: 0, wire: true,
      detail: "Alice's x25519_pk + kem_pk + sig_pk" });

    await L.run('Validate ClientHello fields', null,
      () => validateClientHello(helloPayload),
      () => ({ detail: 'Version 2, PQC keys present and correctly sized' }));

    const peerXPub  = b64ToBytes(helloPayload.x25519_pk);
    const kemPk     = b64ToBytes(helloPayload.kem_pk);
    const peerSigPk = b64ToBytes(helloPayload.sig_pk);

    const xSs = await L.run('X25519 Diffie-Hellman', 'x25519Ms',
      () => x25519Exchange(this._xPriv, peerXPub),
      r => ({ detail: 'Classical shared secret (32 B)', value: toHex(r), secret: true }));

    const { cipherText: kemCt, sharedSecret: kemSs } = await L.run('ML-KEM-768 encapsulate', 'kemMs',
      () => kemEncapsulate(kemPk),
      r => ({ detail: `PQ shared secret + ${r.cipherText.length} B ciphertext for Alice`, value: toHex(r.sharedSecret), secret: true }));

    const transcript = await L.run('Transcript hash (SHA-256)', null,
      () => computeTranscript(peerXPub, kemPk, peerSigPk, this.xPub, this.sigPk, kemCt),
      r => ({ detail: 'Hash of every public value exchanged', value: toHex(r) }));

    const keys = await L.run('HKDF-SHA-256 → directional keys', 'hkdfMs',
      () => deriveDirectionalKeys(xSs, kemSs, transcript),
      r => ({ detail: 'IKM = x25519_ss ‖ kem_ss, salt = transcript', value: `A→B ${toHex(r.aliceToBob)}\nB→A ${toHex(r.bobToAlice)}`, secret: true }));

    const signature = await L.run('Sign transcript (ML-DSA-65)', 'signMs',
      () => signMessage(this._sigSk, signedPayload(SIG_LABEL_RESPONDER, transcript)),
      r => ({ detail: `Proves Bob holds his advertised key (${r.length} B)` }));

    this.safetyCode = await L.run('Derive safety code', null,
      () => deriveSafetyCode(transcript),
      r => ({ detail: 'Compare with peer out-of-band to rule out MITM', value: `${r.emoji.join(' ')}  ${r.digits}` }));

    L.steps.push({ label: 'Send KemResponse →', ok: true, ms: 0, wire: true,
      detail: 'kem_ct + x25519_pk + sig_pk + signature' });

    this.transcript = transcript;
    this._pending = { keys, peerSigPk, transcript };
    this._t = this._initMs + (now() - t0);
    return buildKemResponse(kemCt, this.xPub, this.sigPk, signature);
  }

  /**
   * Verify Alice's transcript signature and activate the session.
   * @throws {ProtocolError|SignatureVerificationError}
   */
  async processClientFinished(finishedPayload) {
    if (!this._pending) throw new ProtocolError('unexpected ClientFinished');
    const t0 = now();
    const L = this.log;
    L.steps.push({ label: '← Receive ClientFinished', ok: true, ms: 0, wire: true,
      detail: "Alice's transcript signature" });

    await L.run('Validate ClientFinished', null,
      () => validateClientFinished(finishedPayload));
    const signature = b64ToBytes(finishedPayload.signature);
    const { keys, peerSigPk, transcript } = this._pending;

    await L.run("Verify Alice's ML-DSA-65 signature", 'verifyMs',
      () => verifySignature(peerSigPk, signedPayload(SIG_LABEL_INITIATOR, transcript), signature),
      () => ({ detail: `${signature.length} B signature valid over transcript` }));

    this.timing.keygenMs = this._initMs;
    this.timing.totalMs = this._t + (now() - t0);
    this._pending = null;
    this._session = new SecureSession(keys.bobToAlice, keys.aliceToBob, 'bob');
    return this._session;
  }

  get session() {
    if (!this._session) throw new Error('Handshake not yet complete');
    return this._session;
  }
}

// ── SecureSession ──────────────────────────────────────────────────────────

export class SecureSession {
  /**
   * @param {Uint8Array} sendKey  32-byte key for messages we send
   * @param {Uint8Array} recvKey  32-byte key for messages we receive
   * @param {string}     role     'alice' or 'bob'
   */
  constructor(sendKey, recvKey, role) {
    if (sendKey.length !== 32 || recvKey.length !== 32) throw new Error('Session keys must be 32 bytes');
    this._sendKey  = sendKey;
    this._recvKey  = recvKey;
    this._role     = role;
    this._sendSeq  = 0;
    this._recvSeen = new Set();
  }

  /**
   * Encrypt and return the wire payload plus a step-by-step trace.
   * @param {Uint8Array|string} plaintext
   * @returns {Promise<{ payload: object, trace: object[] }>}
   */
  async seal(plaintext) {
    const trace = [];
    const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    trace.push({ label: 'Plaintext → UTF-8 bytes', ok: true, ms: 0,
      detail: `${pt.length} bytes`, value: toHex(pt) });

    const seq = this._sendSeq++;
    const aad = seqAad(seq);
    trace.push({ label: 'Sequence number → AAD', ok: true, ms: 0,
      detail: `seq ${seq} as 8-byte big-endian (authenticated, not encrypted)`, value: toHex(aad) });
    trace.push({ label: `Select ${this._role === 'alice' ? 'Alice→Bob' : 'Bob→Alice'} key`, ok: true, ms: 0,
      detail: 'AES-256 key from HKDF (direction-specific)', value: toHex(this._sendKey), secret: true });

    const t = now();
    const { nonce, ciphertext, tag } = await encrypt(this._sendKey, pt, aad);
    const ms = now() - t;
    trace.push({ label: 'Random 96-bit nonce', ok: true, ms: 0,
      detail: 'crypto.getRandomValues — never reused', value: toHex(nonce) });
    trace.push({ label: 'AES-256-GCM encrypt', ok: true, ms,
      detail: `${ciphertext.length} B ciphertext`, value: toHex(ciphertext) });
    trace.push({ label: 'GCM authentication tag', ok: true, ms: 0,
      detail: '128-bit tag over nonce + AAD + ciphertext', value: toHex(tag) });

    const payload = buildDataMessage(seq, nonce, ciphertext, tag);
    trace.push({ label: 'Base64 wire frame', ok: true, ms: 0,
      detail: 'What the relay (and Eve) actually see', value: JSON.stringify(payload, null, 1) });
    return { payload, trace };
  }

  /**
   * Validate, authenticate and decrypt a DataMessage, returning a trace.
   * Errors thrown carry `.trace` showing where processing stopped.
   * @returns {Promise<{ plaintext: Uint8Array, trace: object[] }>}
   */
  async open(payload) {
    const trace = [];
    const fail = (e) => {
      trace.push({ label: 'REJECTED', ok: false, ms: 0, detail: e.message });
      e.trace = trace;
      return e;
    };

    trace.push({ label: 'Receive wire frame', ok: true, ms: 0,
      detail: 'Base64 JSON from relay', value: JSON.stringify(payload, null, 1) });

    let parsed;
    try {
      parsed = parseDataMessage(payload);
    } catch (e) { throw fail(e); }
    const { seq, nonce, ciphertext, tag } = parsed;
    const aad = seqAad(seq);
    trace.push({ label: 'Validate frame + rebuild AAD', ok: true, ms: 0,
      detail: `seq ${seq} is a valid integer; nonce 12 B, tag 16 B`, value: toHex(aad) });
    trace.push({ label: `Select ${this._role === 'alice' ? 'Bob→Alice' : 'Alice→Bob'} key`, ok: true, ms: 0,
      detail: 'AES-256 key from HKDF (direction-specific)', value: toHex(this._recvKey), secret: true });

    const t = now();
    let plaintext;
    try {
      plaintext = await decrypt(this._recvKey, nonce, ciphertext, tag, aad);
    } catch (e) {
      trace.push({ label: 'AES-256-GCM verify tag', ok: false, ms: now() - t,
        detail: 'Tag does not match — frame was modified or encrypted under another key', value: toHex(tag) });
      throw fail(e);
    }
    trace.push({ label: 'AES-256-GCM verify tag', ok: true, ms: now() - t,
      detail: 'Tag valid — ciphertext, nonce and seq are authentic', value: toHex(tag) });

    if (this._recvSeen.has(seq)) {
      trace.push({ label: 'Replay check', ok: false, ms: 0, detail: `seq ${seq} was already accepted` });
      throw fail(new ReplayError(`sequence number ${seq} already used`));
    }
    this._recvSeen.add(seq);
    trace.push({ label: 'Replay check', ok: true, ms: 0, detail: `seq ${seq} is new` });
    trace.push({ label: 'Decrypted bytes → UTF-8', ok: true, ms: 0,
      detail: `${plaintext.length} bytes`, value: toHex(plaintext) });
    return { plaintext, trace };
  }

  /** Encrypt and return only the DataMessage payload. */
  async encryptMessage(plaintext) {
    return (await this.seal(plaintext)).payload;
  }

  /** Decrypt and return only the plaintext bytes. */
  async decryptMessage(payload) {
    return (await this.open(payload)).plaintext;
  }

  get sendKey()     { return this._sendKey; }
  get recvKey()     { return this._recvKey; }
  get nextSendSeq() { return this._sendSeq; }
  get seenSeqs()    { return new Set(this._recvSeen); }
}
