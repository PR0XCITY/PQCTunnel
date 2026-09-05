/**
 * tamper.js — Tamper attack frame builder.
 *
 * Flips byte[0] of the ciphertext field and uses a fresh sequence number
 * so the relay's replay pre-check does not intercept it.
 *
 * The receiving peer runs AES-256-GCM decryption first (before the replay check)
 * and throws: "GCM auth tag mismatch"
 */

import { b64ToBytes, bytesToB64 } from '../crypto/protocol.js';

/**
 * @param {object} capturedDataPayload  Payload from a mirrored DataMessage
 * @param {number} freshSeq             A seq number the peer has NOT yet seen
 * @returns {object}                    Tampered DataMessage envelope
 */
export function buildTamperFrame(capturedDataPayload, freshSeq) {
  // Decode, flip byte[0], re-encode
  const ct = b64ToBytes(capturedDataPayload.ciphertext);
  const tampered = new Uint8Array(ct);
  tampered[0] ^= 0xFF;

  return {
    type: 'data',
    payload: {
      seq:        freshSeq,                           // fresh seq bypasses relay replay check
      nonce:      capturedDataPayload.nonce,          // same nonce
      ciphertext: bytesToB64(tampered),               // corrupted
      tag:        capturedDataPayload.tag,            // same tag (won't match tampered ct)
    },
  };
}
