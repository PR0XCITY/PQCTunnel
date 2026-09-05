/**
 * classical.js
 * X25519 key exchange and HKDF-SHA-256 key derivation.
 *
 * Uses the Web Crypto API (available natively in browsers and Node >= 18).
 * No external dependencies.
 *
 * Mirrors crypto/classical.py exactly:
 *   - Same IKM construction: x25519_ss || kem_ss
 *   - Same HKDF params: SHA-256, salt = 32 zero bytes (PyCA default for salt=None)
 *   - Same info string encoding: UTF-8 bytes
 */

const subtle = () => globalThis.crypto.subtle;

/** Generate an X25519 keypair. Returns { privateKey: CryptoKey, publicKey: Uint8Array (32 bytes) } */
export async function generateX25519Keypair() {
  const kp = await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const rawPub = await subtle().exportKey('raw', kp.publicKey);
  return {
    privateKey: kp.privateKey,      // opaque CryptoKey — never leave this machine
    publicKey:  new Uint8Array(rawPub),  // 32-byte raw public key for the wire
  };
}

/**
 * Perform X25519 Diffie-Hellman.
 * @param {CryptoKey}   privateKey  Our private key (from generateX25519Keypair)
 * @param {Uint8Array}  peerPubBytes  Peer's raw 32-byte public key
 * @returns {Promise<Uint8Array>} 32-byte shared secret
 */
export async function x25519Exchange(privateKey, peerPubBytes) {
  const peerKey = await subtle().importKey(
    'raw', peerPubBytes, { name: 'X25519' }, false, []
  );
  const bits = await subtle().deriveBits(
    { name: 'X25519', public: peerKey },
    privateKey,
    256
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-SHA-256 hybrid key derivation.
 *
 * IKM  = x25519SharedSecret || kemSharedSecret
 * Salt = 32 zero bytes (RFC 5869 default when salt is not provided; matches PyCA)
 * Info = UTF-8 encoded info string
 *
 * @param {Uint8Array} x25519Ss  32-byte X25519 shared secret
 * @param {Uint8Array} kemSs     32-byte ML-KEM shared secret
 * @param {Uint8Array|string} info  HKDF context string or bytes
 * @param {number} length  Output length in bytes (default 32)
 * @returns {Promise<Uint8Array>} Derived key bytes
 */
export async function hkdfDerive(x25519Ss, kemSs, info, length = 32) {
  // Concatenate IKM exactly as Python does: x25519_ss + kem_ss
  const ikm = new Uint8Array(x25519Ss.length + kemSs.length);
  ikm.set(x25519Ss, 0);
  ikm.set(kemSs, x25519Ss.length);

  const infoBytes = typeof info === 'string'
    ? new TextEncoder().encode(info)
    : info;

  // PyCA uses 32 zero-bytes as salt when salt=None (SHA-256 digest size = 32)
  const salt = new Uint8Array(32);

  const ikmKey = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const derived = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: infoBytes },
    ikmKey,
    length * 8
  );
  return new Uint8Array(derived);
}
