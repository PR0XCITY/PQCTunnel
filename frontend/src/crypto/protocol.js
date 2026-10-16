/**
 * protocol.js
 * Wire-format message definitions for the PQCTunnel handshake and data channel.
 *
 * Protocol v2 (browser). The Python package in network/ is the v1 reference.
 *
 * Handshake (3 messages)
 * ----------------------
 *   Alice → Bob   ClientHello     { version, role, x25519_pk, kem_pk, sig_pk }
 *   Bob   → Alice KemResponse     { kem_ct, x25519_pk, sig_pk, signature }
 *   Alice → Bob   ClientFinished  { signature }
 *
 *   transcript = SHA-256(domain || alice.x25519 || alice.kem_pk || alice.sig_pk
 *                                || bob.x25519 || bob.sig_pk || kem_ct)
 *   Bob signs   SIG_LABEL_RESPONDER || transcript
 *   Alice signs SIG_LABEL_INITIATOR || transcript
 *
 *   keys = HKDF-SHA-256(ikm = x25519_ss || kem_ss, salt = transcript, info = HKDF_INFO, 64)
 *   k_alice→bob = keys[0:32], k_bob→alice = keys[32:64]
 *
 *   safety code = SHA-256(SAS_LABEL || transcript), shown on both screens.
 *   Signatures prove each side holds the key it advertised; only comparing the
 *   safety code proves the advertised key belongs to the real peer (MITM check).
 *
 * Exceptions
 * ----------
 * ProtocolError   — structural / pre-crypto validation failure
 * ReplayError     — duplicate sequence number
 */

// ── Constants ──────────────────────────────────────────────────────────────

export const PROTOCOL_VERSION      = '2';
export const HKDF_INFO             = 'pqctunnel-v2 directional keys';
export const TRANSCRIPT_DOMAIN_SEP = 'pqctunnel-handshake-v2\x00';
export const SIG_LABEL_RESPONDER   = 'pqctunnel-v2 responder signature\x00';
export const SIG_LABEL_INITIATOR   = 'pqctunnel-v2 initiator signature\x00';
export const SAS_LABEL             = 'pqctunnel-v2 safety code\x00';

// Encrypted control message: Alice asks Bob to drop the session before a new
// handshake. It rides inside AES-GCM, so only the real peer can send it.
export const REKEY_SIGNAL          = '\u0000pqctunnel:rekey';

export const X25519_PK_SIZE      = 32;
export const ML_KEM_768_PK_SIZE  = 1184;
export const ML_KEM_768_CT_SIZE  = 1088;
export const ML_DSA_65_PK_SIZE   = 1952;
export const ML_DSA_65_SIG_SIZE  = 3309;
export const GCM_NONCE_SIZE      = 12;
export const GCM_TAG_SIZE        = 16;

export const VALID_ROLES = new Set(['alice', 'bob']);

export const MSG_CLIENT_HELLO    = 'client_hello';
export const MSG_KEM_RESPONSE    = 'kem_response';
export const MSG_CLIENT_FINISHED = 'client_finished';
export const MSG_DATA            = 'data';
export const MSG_ALERT           = 'alert';
export const MSG_REJECTION       = 'rejection';

// ── Custom exceptions ──────────────────────────────────────────────────────

export class ProtocolError extends Error {
  constructor(reason) { super(reason); this.name = 'ProtocolError'; }
}

export class ReplayError extends Error {
  constructor(reason) { super(reason); this.name = 'ReplayError'; }
}

// ── Byte helpers ───────────────────────────────────────────────────────────

export function bytesToB64(bytes) {
  // Works in both Node.js and browser
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  // Chunked: spreading a large array into fromCharCode overflows the call stack
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function b64ToBytes(b64) {
  if (typeof b64 !== 'string') return new Uint8Array(0);
  try {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

const utf8 = (s) => new TextEncoder().encode(s);

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

/** Hex-encode a Uint8Array for display. */
export function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Short display fingerprint of a key: first 8 bytes of its SHA-256. */
export async function fingerprint(bytes) {
  return toHex((await sha256(bytes)).slice(0, 8)).match(/.{4}/g).join(':');
}

// ── Transcript hash ────────────────────────────────────────────────────────

/**
 * Compute the handshake transcript hash. All fields are fixed-length (sizes are
 * validated before this is called), so plain concatenation is unambiguous.
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
  return sha256(concatBytes(
    utf8(TRANSCRIPT_DOMAIN_SEP),
    initiatorX25519Pk, initiatorKemPk, initiatorSigPk,
    responderX25519Pk, responderSigPk,
    kemCt,
  ));
}

/** Bytes that get signed: role label || transcript (stops cross-role reuse). */
export function signedPayload(label, transcript) {
  return concatBytes(utf8(label), transcript);
}

// ── Safety code (short authentication string) ──────────────────────────────

const SAS_EMOJI = [
  '🐶','🐱','🦁','🐴','🦄','🐷','🐘','🐰','🐼','🐓','🐧','🐢','🐟','🐙','🦋','🌷',
  '🌳','🌵','🍄','🌏','🌙','☁️','🔥','🍌','🍎','🍓','🌽','🍕','🎂','❤️','😀','🤖',
  '🎩','👓','🔧','🎅','👍','☂️','⌛','⏰','🎁','💡','📕','✏️','📎','✂️','🔒','🔑',
  '🔨','☎️','🏁','🚂','🚲','✈️','🚀','🏆','⚽','🎸','🎺','🔔','⚓','🎧','📁','📌',
];

/**
 * Derive the human-comparable safety code from the transcript.
 * If Alice and Bob see the same code, nobody substituted keys in between.
 * @returns {Promise<{ emoji: string[], digits: string, hex: string }>}
 */
export async function deriveSafetyCode(transcript) {
  const h = await sha256(concatBytes(utf8(SAS_LABEL), transcript));
  const emoji = Array.from(h.slice(0, 6), b => SAS_EMOJI[b & 63]);
  // 4 groups of 5 digits from bytes 6..21
  const groups = [];
  for (let g = 0; g < 4; g++) {
    const v = ((h[6 + g * 4] << 24) >>> 0) + (h[7 + g * 4] << 16) + (h[8 + g * 4] << 8) + h[9 + g * 4];
    groups.push(String(v % 100000).padStart(5, '0'));
  }
  return { emoji, digits: groups.join(' '), hex: toHex(h) };
}

// ── Validation ─────────────────────────────────────────────────────────────

/**
 * Structural pre-checks on a received ClientHello payload.
 * @throws {ProtocolError} With specific rejection reason on failure
 */
export function validateClientHello(hello) {
  if (!hello || typeof hello !== 'object') {
    throw new ProtocolError('malformed ClientHello: not an object');
  }
  if (b64ToBytes(hello.x25519_pk).length !== X25519_PK_SIZE) {
    throw new ProtocolError('malformed ClientHello: classical fields missing');
  }
  // PQC field checks (downgrade detection)
  if (b64ToBytes(hello.kem_pk).length !== ML_KEM_768_PK_SIZE ||
      b64ToBytes(hello.sig_pk).length !== ML_DSA_65_PK_SIZE) {
    throw new ProtocolError('malformed ClientHello: PQC fields missing');
  }
  if (hello.version !== PROTOCOL_VERSION) {
    throw new ProtocolError(`unsupported protocol version: ${JSON.stringify(hello.version)}`);
  }
  if (hello.role !== 'alice') {
    throw new ProtocolError(`invalid role: ${JSON.stringify(hello.role)}`);
  }
}

/** Structural pre-checks on a received KemResponse payload. */
export function validateKemResponse(resp) {
  if (!resp || typeof resp !== 'object') {
    throw new ProtocolError('malformed KemResponse: not an object');
  }
  if (b64ToBytes(resp.x25519_pk).length !== X25519_PK_SIZE) {
    throw new ProtocolError('malformed KemResponse: classical fields missing');
  }
  if (b64ToBytes(resp.kem_ct).length !== ML_KEM_768_CT_SIZE ||
      b64ToBytes(resp.sig_pk).length !== ML_DSA_65_PK_SIZE) {
    throw new ProtocolError('malformed KemResponse: PQC fields missing');
  }
  if (b64ToBytes(resp.signature).length !== ML_DSA_65_SIG_SIZE) {
    throw new ProtocolError('malformed KemResponse: signature missing');
  }
}

/** Structural pre-checks on a received ClientFinished payload. */
export function validateClientFinished(fin) {
  if (!fin || b64ToBytes(fin.signature).length !== ML_DSA_65_SIG_SIZE) {
    throw new ProtocolError('malformed ClientFinished: signature missing');
  }
}

/**
 * Sequence numbers must be JSON numbers that are non-negative safe integers.
 * Anything else ("x", 0.5, null) would otherwise alias seq 0 in the AAD
 * encoding and slip past the replay set.
 */
export function validateSeq(seq) {
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) {
    throw new ProtocolError(`invalid sequence number: ${JSON.stringify(seq)}`);
  }
  return seq;
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

/** Build a ClientFinished payload. */
export function buildClientFinished(signature) {
  return { signature: bytesToB64(signature) };
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

/**
 * Parse a DataMessage payload back to typed fields.
 * @throws {ProtocolError} on a bad seq, nonce or tag
 */
export function parseDataMessage(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new ProtocolError('malformed DataMessage: not an object');
  }
  const seq   = validateSeq(payload.seq);
  const nonce = b64ToBytes(payload.nonce);
  const tag   = b64ToBytes(payload.tag);
  if (nonce.length !== GCM_NONCE_SIZE) throw new ProtocolError('malformed DataMessage: bad nonce');
  if (tag.length !== GCM_TAG_SIZE)     throw new ProtocolError('malformed DataMessage: bad tag');
  return { seq, nonce, ciphertext: b64ToBytes(payload.ciphertext), tag };
}

/** Encode sequence number as 8-byte big-endian AAD. */
export function seqAad(seq) {
  validateSeq(seq);
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(seq));
  return buf;
}

/** Wrap a message object in the standard { type, payload } envelope. */
export function makeEnvelope(type, payload) {
  return { type, payload };
}
