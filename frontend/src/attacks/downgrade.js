/**
 * downgrade.js — Downgrade attack frame builder.
 *
 * Strips kem_pk and sig_pk from a captured ClientHello, leaving them empty.
 * The relay detects this via size check and rejects with:
 * "malformed ClientHello: PQC fields missing"
 */

import { bytesToB64 } from '../crypto/protocol.js';

/**
 * @param {object} capturedHelloPayload  Payload from a mirrored ClientHello
 * @returns {object}                     Downgraded ClientHello envelope
 */
export function buildDowngradeFrame(capturedHelloPayload) {
  return {
    type: 'client_hello',
    payload: {
      ...capturedHelloPayload,
      kem_pk: bytesToB64(new Uint8Array(0)),   // stripped
      sig_pk: bytesToB64(new Uint8Array(0)),   // stripped
    },
  };
}
