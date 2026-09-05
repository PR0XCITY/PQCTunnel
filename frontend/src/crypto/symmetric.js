/**
 * symmetric.js
 * AES-256-GCM encryption/decryption via the Web Crypto API.
 *
 * Mirrors crypto/symmetric.py exactly:
 *   - 12-byte random nonce (IV) per message
 *   - 16-byte (128-bit) authentication tag
 *   - Optional AAD (additional authenticated data, bound but not encrypted)
 *   - DecryptionError thrown on tag mismatch (exact string: "GCM auth tag mismatch")
 *
 * Web Crypto AES-GCM note:
 *   encrypt() returns (ciphertext || tag) concatenated. We split the tag off
 *   the end so the DataMessage wire format matches the Python reference exactly:
 *   { nonce, ciphertext, tag } as three separate fields.
 */

const subtle = () => globalThis.crypto.subtle;

// ── Custom exception ───────────────────────────────────────────────────────

export class DecryptionError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'DecryptionError';
  }
}

// ── Encrypt ────────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * @param {Uint8Array} keyBytes    32-byte session key
 * @param {Uint8Array} plaintext   Bytes to encrypt
 * @param {Uint8Array} [aad]       Additional authenticated data (default: empty)
 * @returns {Promise<{ nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array }>}
 *          nonce = 12 bytes, tag = 16 bytes, ciphertext = same length as plaintext
 */
export async function encrypt(keyBytes, plaintext, aad = new Uint8Array(0)) {
  const key = await subtle().importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);

  const nonce = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nonce);

  const result = await subtle().encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    plaintext
  );

  // Web Crypto appends the 16-byte tag at the end of the output
  const buf = new Uint8Array(result);
  const ciphertext = buf.slice(0, buf.length - 16);
  const tag        = buf.slice(buf.length - 16);

  return { nonce, ciphertext, tag };
}

// ── Decrypt ────────────────────────────────────────────────────────────────

/**
 * Decrypt and authenticate with AES-256-GCM.
 *
 * @param {Uint8Array} keyBytes    32-byte session key
 * @param {Uint8Array} nonce       12-byte nonce from the DataMessage
 * @param {Uint8Array} ciphertext  Encrypted payload
 * @param {Uint8Array} tag         16-byte authentication tag
 * @param {Uint8Array} [aad]       Additional authenticated data (must match encrypt)
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 * @throws {DecryptionError} "GCM auth tag mismatch" if verification fails
 */
export async function decrypt(keyBytes, nonce, ciphertext, tag, aad = new Uint8Array(0)) {
  const key = await subtle().importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);

  // Web Crypto expects (ciphertext || tag) concatenated
  const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
  ctWithTag.set(ciphertext, 0);
  ctWithTag.set(tag, ciphertext.length);

  try {
    const result = await subtle().decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      ctWithTag
    );
    return new Uint8Array(result);
  } catch {
    // Web Crypto throws a generic DOMException on tag mismatch;
    // we re-throw with the exact vocabulary from the Python reference
    throw new DecryptionError('GCM auth tag mismatch');
  }
}
