/**
 * replay.js — Replay attack frame builder.
 * Resends a captured DataMessage frame unchanged.
 * The receiving peer rejects with: "sequence number N already used"
 */

/**
 * @param {object} capturedEnvelope  The exact mirrored envelope from the relay
 * @returns {object}                 The same envelope for injection
 */
export function buildReplayFrame(capturedEnvelope) {
  // Literally the same bytes — no modification needed
  return capturedEnvelope;
}
