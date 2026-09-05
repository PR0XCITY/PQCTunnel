/**
 * protocol.js
 * Wire-format message definitions for the PQCTunnel handshake and data channel.
 *
 * Direct JavaScript port of network/protocol.py.
 * Same field names, same base64 encoding, same constants, same rejection vocabulary.
 *
 * Constants
 * ---------
 * PROTOCOL_VERSION       "1"
 * HKDF_INFO              "pqctunnel-session-v1"   (UTF-8 bytes when used in HKDF)
 * TRANSCRIPT_DOMAIN_SEP  "pqctunnel-handshake-v1\x00" (UTF-8 bytes)
 *
 * Field sizes (decoded bytes)
 * ---------------------------
 * X25519_PK_SIZE       32
 * ML_KEM_768_PK_SIZE   1184
 * ML_KEM_768_CT_SIZE   1088
 * ML_DSA_65_PK_SIZE    1952
 *
 * Exceptions
 * ----------
 * ProtocolError   — structural / pre-crypto validation failure
 * ReplayError     — duplicate sequence number
 */

// ── Constants ──────────────────────────────────────────────────────────────

export const PROTOCOL_VERSION      = '1';
export const HKDF_INFO             = 'pqctunnel-session-v1';
export const TRANSCRIPT_DOMAIN_SEP = 'pqctunnel-handshake-v1\x00';

export const X25519_PK_SIZE      = 32;
export const ML_KEM_768_PK_SIZE  = 1184;
export const ML_KEM_768_CT_SIZE  = 1088;
export const ML_DSA_65_PK_SIZE   = 1952;

export const VALID_ROLES = new Set(['alice', 'bob']);

export const MSG_CLIENT_HELLO = 'client_hello';
export const MSG_KEM_RESPONSE = 'kem_response';
export const MSG_DATA         = 'data';
export const MSG_REJECTION    = 'rejection';

// ── Custom exceptions ──────────────────────────────────────────────────────

export class ProtocolError extends Error {
  constructor(reason) { super(reason); this.name = 'ProtocolError'; }
}

export class ReplayError extends Error {
  constructor(reason) { super(reason); this.name = 'ReplayError'; }
}

// ── Base64 helpers ─────────────────────────────────────────────────────────

export function bytesToB64(bytes) {
  // Works in both Node.js and browser
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  return btoa(String.fromCharCode(...bytes));
}

export function b64ToBytes(b64) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  return new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
}

// ── Transcript hash ────────────────────────────────────────────────────────

/**
 * Compute the handshake transcript hash.
 * Exact port of protocol.py::compute_transcript().
 *
 * Both parties compute this independently and must arrive at identical bytes.
 * The ML-DSA-65 signature is over this 32-byte hash.
 *
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 of transcript material
 */
export async function computeTranscript(
  initiatorX25519Pk,
  initiatorKemPk,
  initiatorSigPk,
  responderX25519Pk,
  responderSigPk,
  kemCt
) {
  const enc = new TextEncoder();
  const domainSep = enc.encode(TRANSCRIPT_DOMAIN_SEP);

  // Concatenate all material in the same order as the Python reference
  const total = domainSep.length +
    initiatorX25519Pk.length + initiatorKemPk.length + initiatorSigPk.length +
    responderX25519Pk.length + responderSigPk.length +
    kemCt.length;

  const material = new Uint8Array(total);
  let offset = 0;
  for (const part of [domainSep, initiatorX25519Pk, initiatorKemPk, initiatorSigPk,
                       responderX25519Pk, responderSigPk, kemCt]) {
    material.set(part, offset);
    offset += part.length;
  }

  const hash = await globalThis.crypto.subtle.digest('SHA-256', material);
  return new Uint8Array(hash);
}

// ── validate_client_hello ──────────────────────────────────────────────────

/**
 * Structural and identity pre-checks on a received ClientHello payload dict.
 * Port of protocol.py::validate_client_hello().
 *
 * @param {object} hello           Parsed ClientHello payload
 * @param {object|null} [original] The original ClientHello payload for MITM check
 * @throws {ProtocolError} With specific rejection reason on failure
 */
export function validateClientHello(hello, original = null) {
  const x25519Pk = b64ToBytes(hello.x25519_pk || '');
  const kemPk    = b64ToBytes(hello.kem_pk    || '');
  const sigPk    = b64ToBytes(hello.sig_pk    || '');

  // Classical field check
  if (x25519Pk.length !== X25519_PK_SIZE) {
    throw new ProtocolError('malformed ClientHello: classical fields missing');
  }
  // PQC field checks (downgrade detection)
  if (kemPk.length !== ML_KEM_768_PK_SIZE) {
    throw new ProtocolError('malformed ClientHello: PQC fields missing');
  }
  if (sigPk.length !== ML_DSA_65_PK_SIZE) {
    throw new ProtocolError('malformed ClientHello: PQC fields missing');
  }
  // Version / role checks
  if (hello.version !== PROTOCOL_VERSION) {
    throw new ProtocolError(`unsupported protocol version: ${JSON.stringify(hello.version)}`);
  }
  if (!VALID_ROLES.has(hello.role)) {
    throw new ProtocolError(`invalid role: ${JSON.stringify(hello.role)}`);
  }

  // MITM key substitution check (only when original is provided)
  if (original !== null) {
    const keysMatch = (
      hello.x25519_pk === original.x25519_pk &&
      hello.kem_pk    === original.kem_pk    &&
      hello.sig_pk    === original.sig_pk
    );
    if (!keysMatch) {
      throw new ProtocolError('public key does not match session identity');
    }
  }
}

// ── Message builders ───────────────────────────────────────────────────────

/** Build a ClientHello payload from raw key bytes. */
export function buildClientHello(role, x25519Pk, kemPk, sigPk) {
  return {
    version:   PROTOCOL_VERSION,
    role,
    x25519_pk: bytesToB64(x25519Pk),
    kem_pk:    bytesToB64(kemPk),
    sig_pk:    bytesToB64(sigPk),
  };
}

/** Build a KemResponse payload. */
export function buildKemResponse(kemCt, x25519Pk, sigPk, signature) {
  return {
    kem_ct:    bytesToB64(kemCt),
    x25519_pk: bytesToB64(x25519Pk),
    sig_pk:    bytesToB64(sigPk),
    signature: bytesToB64(signature),
  };
}

/** Build a DataMessage payload, binding seq into AAD. */
export function buildDataMessage(seq, nonce, ciphertext, tag) {
  return {
    seq,
    nonce:      bytesToB64(nonce),
    ciphertext: bytesToB64(ciphertext),
    tag:        bytesToB64(tag),
  };
}

/** Parse a DataMessage payload back to typed fields. */
export function parseDataMessage(payload) {
  return {
    seq:        Number(payload.seq),
    nonce:      b64ToBytes(payload.nonce),
    ciphertext: b64ToBytes(payload.ciphertext),
    tag:        b64ToBytes(payload.tag),
  };
}

/** Encode sequence number as 8-byte big-endian AAD (matches Python). */
export function seqAad(seq) {
  const buf = new Uint8Array(8);
  // seq is a safe integer; write as big-endian 64-bit
  let n = seq;
  for (let i = 7; i >= 0; i--) {
    buf[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return buf;
}

/** Wrap a message object in the standard { type, payload } envelope. */
export function makeEnvelope(type, payload) {
  return { type, payload };
}

/** Parse an envelope; throw ProtocolError if malformed. */
export function parseEnvelope(envelope) {
  const validTypes = new Set([MSG_CLIENT_HELLO, MSG_KEM_RESPONSE, MSG_DATA, MSG_REJECTION]);
  if (!envelope || typeof envelope.type !== 'string') {
    throw new ProtocolError('malformed envelope: missing type');
  }
  if (!validTypes.has(envelope.type)) {
    throw new ProtocolError(`unknown message type: ${JSON.stringify(envelope.type)}`);
  }
  return { type: envelope.type, payload: envelope.payload };
}

/** Hex-encode a Uint8Array for display. */
export function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
