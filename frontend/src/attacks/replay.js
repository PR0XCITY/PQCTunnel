/**
 * replay.js — Replay attack frame builders.
 *
 * buildReplayFrame:          resends a captured DataMessage unchanged.
 *   → "sequence number N already used"
 * buildSeqConfusionFrame:    resends it with seq replaced by a non-integer
 *   ("0" as a string). v1 encoded this to the same AAD as seq 0 and the replay
 *   set missed it. → "invalid sequence number: \"0\""
 * buildReflectionFrame:      sends a frame back to the peer that wrote it.
 *   With one shared key this decrypted fine; with directional keys it fails.
 *   → "GCM auth tag mismatch"
 */

/**
 * @param {object} capturedEnvelope  The exact mirrored envelope from the relay
 * @returns {object}                 The same envelope for injection
 */
export function buildReplayFrame(capturedEnvelope) {
  // Literally the same bytes — no modification needed
  return capturedEnvelope;
}

/** Replay with a type-confused seq that aliases the original AAD in v1. */
export function buildSeqConfusionFrame(capturedEnvelope) {
  return {
    type: 'data',
    payload: { ...capturedEnvelope.payload, seq: String(capturedEnvelope.payload.seq) },
  };
}

/** Reflection: the frame is unchanged; only the injection target differs. */
export function buildReflectionFrame(capturedEnvelope) {
  return capturedEnvelope;
}
