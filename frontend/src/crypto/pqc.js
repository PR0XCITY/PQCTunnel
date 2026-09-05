/**
 * pqc.js
 * ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) via @noble/post-quantum 0.7.x.
 *
 * Mirrors crypto/pqc.py exactly in terms of what each function returns and throws.
 * Same exception vocabulary:
 *   SignatureVerificationError: "ML-DSA signature verification failed: transcript hash mismatch"
 *   verifySignature() throws on failure, returns undefined on success.
 *
 * @noble/post-quantum 0.7.x API (differs from naive expectations — read carefully):
 *   keygen()             not  generateKeyPair()
 *   result.secretKey     not  result.privateKey
 *   encapsulate()        returns { cipherText, sharedSecret }  (capital T in cipherText)
 *   decapsulate(ct, sk)  cipherText first, secretKey second
 *   sign(msg, sk)        message is FIRST argument, secretKey is SECOND
 *   verify(sig, msg, pk) signature is FIRST, message SECOND, publicKey THIRD
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65  } from '@noble/post-quantum/ml-dsa.js';

// ── Custom exception (exact string used throughout the project) ────────────

export class SignatureVerificationError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SignatureVerificationError';
  }
}

// ── ML-KEM-768 ─────────────────────────────────────────────────────────────

/**
 * Generate an ML-KEM-768 keypair.
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 *   publicKey = 1184 bytes, secretKey = 2400 bytes
 */
export function kemGenerateKeypair() {
  return ml_kem768.keygen();
  // Returns { publicKey, secretKey }
}

/**
 * Encapsulate to a public key (Bob encapsulates to Alice's kemPk).
 * @param {Uint8Array} publicKey  1184-byte ML-KEM-768 public key
 * @returns {{ cipherText: Uint8Array, sharedSecret: Uint8Array }}
 *   cipherText = 1088 bytes, sharedSecret = 32 bytes
 */
export function kemEncapsulate(publicKey) {
  return ml_kem768.encapsulate(publicKey);
  // Returns { cipherText, sharedSecret }
}

/**
 * Decapsulate to recover the shared secret (Alice decapsulates with her secretKey).
 * Note: decapsulate NEVER throws — ML-KEM returns a random value on wrong key.
 * Wrong session key will be caught later by GCM authentication failure.
 *
 * @param {Uint8Array} secretKey  2400-byte ML-KEM-768 secret key
 * @param {Uint8Array} cipherText 1088-byte ciphertext from encapsulate()
 * @returns {Uint8Array} 32-byte shared secret
 */
export function kemDecapsulate(secretKey, cipherText) {
  return ml_kem768.decapsulate(cipherText, secretKey);
  // Note argument order: (cipherText, secretKey) in noble API
}

// ── ML-DSA-65 ──────────────────────────────────────────────────────────────

/**
 * Generate an ML-DSA-65 keypair.
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 *   publicKey = 1952 bytes, secretKey = 4032 bytes
 */
export function signGenerateKeypair() {
  return ml_dsa65.keygen();
  // Returns { publicKey, secretKey }
}

/**
 * Sign a message with ML-DSA-65.
 * @param {Uint8Array} secretKey  4032-byte ML-DSA-65 secret key
 * @param {Uint8Array} message    Bytes to sign (the 32-byte transcript hash)
 * @returns {Uint8Array} Signature (up to 3309 bytes)
 */
export function signMessage(secretKey, message) {
  // noble API: sign(message, secretKey) — message is FIRST
  return ml_dsa65.sign(message, secretKey);
}

/**
 * Verify a ML-DSA-65 signature over a message.
 * Throws on failure. Returns undefined on success (matching Python contract).
 *
 * @param {Uint8Array} publicKey  1952-byte ML-DSA-65 public key
 * @param {Uint8Array} message    The signed bytes (transcript hash)
 * @param {Uint8Array} signature  The signature to verify
 * @throws {SignatureVerificationError}
 *   "ML-DSA signature verification failed: transcript hash mismatch"
 */
export function verifySignature(publicKey, message, signature) {
  // noble API: verify(signature, message, publicKey) — sig is FIRST
  const valid = ml_dsa65.verify(signature, message, publicKey);
  if (!valid) {
    throw new SignatureVerificationError(
      'ML-DSA signature verification failed: transcript hash mismatch'
    );
  }
  // Returns undefined on success — same contract as Python reference
}
