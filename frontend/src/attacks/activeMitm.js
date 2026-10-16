/**
 * activeMitm.js — Full man-in-the-middle via a compromised relay.
 *
 * When the relay hands Eve every frame instead of forwarding it (MITM mode),
 * Eve can run one real handshake with Alice (posing as Bob) and another with
 * Bob (posing as Alice), then decrypt and re-encrypt every message.
 *
 * Signatures do not stop this: Eve signs with her own ML-DSA keys and neither
 * side knows the other's real key in advance. What exposes her is the safety
 * code — Alice's is derived from the Alice↔Eve transcript, Bob's from the
 * Eve↔Bob transcript, so they differ.
 *
 * onFrame(from, frame) returns the frames Eve should inject next:
 *   [{ target, frame, note, plaintext? }]
 */

import { SessionInitiator, SessionResponder } from '../crypto/session.js';
import { makeEnvelope, REKEY_SIGNAL } from '../crypto/protocol.js';

const other = (r) => (r === 'alice' ? 'bob' : 'alice');

export class ActiveMitm {
  constructor() { this.reset(); }

  reset() {
    this.toAlice = null;   // SessionResponder — Eve pretending to be Bob
    this.toBob   = null;   // SessionInitiator — Eve pretending to be Alice
    this.aliceReady = false;
    this.bobReady   = false;
  }

  /** Safety codes each victim will see. */
  get codes() {
    return {
      alice: this.toAlice?.safetyCode ?? null,
      bob:   this.toBob?.safetyCode ?? null,
    };
  }

  get established() { return this.aliceReady && this.bobReady; }

  async onFrame(from, frame) {
    const type = frame?.type;
    const payload = frame?.payload;
    const pass = (note = 'forwarded unchanged') => [{ target: other(from), frame, note }];

    try {
      if (type === 'client_hello' && from === 'alice') {
        this.reset();
        this.toAlice = await new SessionResponder().init();
        const resp = await this.toAlice.processClientHello(payload);
        this.toBob = await new SessionInitiator().init();
        return [
          { target: 'alice', frame: makeEnvelope('kem_response', resp), note: 'Eve, posing as Bob, answers Alice with her own keys' },
          { target: 'bob', frame: makeEnvelope('client_hello', this.toBob.buildClientHello()), note: 'Eve, posing as Alice, sends Bob her own ClientHello' },
        ];
      }

      if (type === 'kem_response' && from === 'bob' && this.toBob && !this.bobReady) {
        const fin = await this.toBob.processKemResponse(payload);
        this.bobReady = true;
        return [{ target: 'bob', frame: makeEnvelope('client_finished', fin), note: 'Eve completes her handshake with Bob' }];
      }

      if (type === 'client_finished' && from === 'alice' && this.toAlice && !this.aliceReady) {
        await this.toAlice.processClientFinished(payload);
        this.aliceReady = true;
        return [];
      }

      if (type === 'data' && this.established) {
        const [inbound, outbound] = from === 'alice'
          ? [this.toAlice.session, this.toBob.session]
          : [this.toBob.session, this.toAlice.session];
        const pt = await inbound.decryptMessage(payload);
        const text = new TextDecoder().decode(pt);
        const re = await outbound.encryptMessage(pt);
        return [{
          target: other(from),
          frame: makeEnvelope('data', re),
          note: 'decrypted, read, re-encrypted under the other key',
          plaintext: text === REKEY_SIGNAL ? '[re-key control message]' : text,
        }];
      }
    } catch (e) {
      return pass(`could not process (${e.message}) — forwarded unchanged`);
    }

    return pass();
  }
}
