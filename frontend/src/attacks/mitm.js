/**
 * mitm.js — Key substitution (MITM) attack frame builder.
 *
 * Replaces the initiator's x25519_pk and kem_pk with Eve's own keys while
 * keeping the original sig_pk (a common MITM pattern — the attacker keeps
 * the victim's identity key to avoid the transcript signature check).
 *
 * Two possible rejection paths depending on relay state:
 *   - If relay has the original ClientHello stored:
 *       "public key does not match session identity"  (relay pre-check)
 *   - If not (relay bypassed or first hello):
 *       "ML-DSA signature verification failed: transcript hash mismatch"  (client JS)
 */

import { bytesToB64 } from '../crypto/protocol.js';
import { generateX25519Keypair } from '../crypto/classical.js';
import { kemGenerateKeypair } from '../crypto/pqc.js';

/**
 * Build a MITM ClientHello substituting Eve's own X25519 and KEM public keys.
 *
 * @param {object}     capturedHelloPayload  Payload from a mirrored ClientHello
 * @param {Uint8Array} eveX25519Pk           Eve's 32-byte X25519 public key
 * @param {Uint8Array} eveKemPk              Eve's 1184-byte ML-KEM-768 public key
 * @returns {object}                          MITM ClientHello envelope
 */
export function buildMitmFrame(capturedHelloPayload, eveX25519Pk, eveKemPk) {
  return {
    type: 'client_hello',
    payload: {
      ...capturedHelloPayload,
      x25519_pk: bytesToB64(eveX25519Pk),   // Eve's X25519 key
      kem_pk:    bytesToB64(eveKemPk),       // Eve's KEM key
      // sig_pk left as-is — Eve keeps the victim's identity key
    },
  };
}

/**
 * Convenience: generate fresh Eve keypairs and build the MITM frame.
 * @param {object} capturedHelloPayload
 * @returns {Promise<{ frame: object, eveX: object, eveKem: object }>}
 */
export async function buildMitmFrameFresh(capturedHelloPayload) {
  const eveX   = await generateX25519Keypair();
  const eveKem = kemGenerateKeypair();
  const frame  = buildMitmFrame(
    capturedHelloPayload, eveX.publicKey, eveKem.publicKey
  );
  return { frame, eveX, eveKem };
}
