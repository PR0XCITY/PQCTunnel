/**
 * Protocol v2 tests for the browser crypto. Run: npm test (node --test).
 * Every call hits the real libraries — no mocks.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SessionInitiator, SessionResponder, SecureSession } from '../src/crypto/session.js';
import {
  buildClientHello, b64ToBytes, bytesToB64, toHex, seqAad,
  ProtocolError, ReplayError,
} from '../src/crypto/protocol.js';
import { SignatureVerificationError } from '../src/crypto/pqc.js';
import { DecryptionError } from '../src/crypto/symmetric.js';
import { buildMitmFrameFresh } from '../src/attacks/mitm.js';
import { buildDowngradeFrame } from '../src/attacks/downgrade.js';
import { buildTamperFrame } from '../src/attacks/tamper.js';
import { ActiveMitm } from '../src/attacks/activeMitm.js';

async function handshake() {
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const resp = await bob.processClientHello(alice.buildClientHello());
  const fin = await alice.processKemResponse(resp);
  await bob.processClientFinished(fin);
  return { alice, bob, a: alice.session, b: bob.session };
}

const text = (bytes) => new TextDecoder().decode(bytes);

test('honest handshake: matching directional keys and safety codes', async () => {
  const { alice, bob, a, b } = await handshake();
  assert.equal(toHex(a.sendKey), toHex(b.recvKey));
  assert.equal(toHex(a.recvKey), toHex(b.sendKey));
  assert.notEqual(toHex(a.sendKey), toHex(a.recvKey));
  assert.equal(alice.safetyCode.digits, bob.safetyCode.digits);
  assert.deepEqual(alice.safetyCode.emoji, bob.safetyCode.emoji);
});

test('messages round-trip both ways with traces', async () => {
  const { a, b } = await handshake();
  const { payload, trace } = await a.seal('hello bob');
  assert.ok(trace.length >= 5);
  const opened = await b.open(payload);
  assert.equal(text(opened.plaintext), 'hello bob');
  assert.equal(text(await a.decryptMessage(await b.encryptMessage('hi alice'))), 'hi alice');
});

test('replay of the same frame is rejected', async () => {
  const { a, b } = await handshake();
  const m = await a.encryptMessage('once');
  await b.decryptMessage(m);
  await assert.rejects(b.decryptMessage(m), ReplayError);
});

test('replay with non-integer seq is rejected before decryption', async () => {
  const { a, b } = await handshake();
  const m = await a.encryptMessage('once');
  await b.decryptMessage(m);
  for (const seq of ['x', 0.5, null, -1, '0', 2 ** 53, undefined]) {
    await assert.rejects(b.decryptMessage({ ...m, seq }), ProtocolError, `seq=${String(seq)}`);
  }
});

test('reflection: own frame sent back fails authentication', async () => {
  const { a } = await handshake();
  const m = await a.encryptMessage('reflect me');
  await assert.rejects(a.decryptMessage(m), DecryptionError);
});

test('tamper: flipped ciphertext byte fails GCM and records the failing step', async () => {
  const { a, b } = await handshake();
  const m = await a.encryptMessage('do not touch');
  const err = await b.decryptMessage(buildTamperFrame(m, 99).payload).catch(e => e);
  assert.ok(err instanceof DecryptionError);
  assert.ok(err.trace.some(s => s.label.includes('GCM') && s.ok === false));
});

test('downgrade: stripped PQC fields are rejected', async () => {
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const frame = buildDowngradeFrame(alice.buildClientHello());
  await assert.rejects(bob.processClientHello(frame.payload), /PQC fields missing/);
});

test('forged responder signature is rejected by Alice', async () => {
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const resp = await bob.processClientHello(alice.buildClientHello());
  const sig = b64ToBytes(resp.signature);
  sig[10] ^= 1;
  await assert.rejects(alice.processKemResponse({ ...resp, signature: bytesToB64(sig) }), SignatureVerificationError);
});

test('forged initiator signature is rejected by Bob', async () => {
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const fin = await alice.processKemResponse(await bob.processClientHello(alice.buildClientHello()));
  const sig = b64ToBytes(fin.signature);
  sig[10] ^= 1;
  await assert.rejects(bob.processClientFinished({ signature: bytesToB64(sig) }), SignatureVerificationError);
});

test("key substitution keeping victim's sig_pk fails Alice's signature check", async () => {
  // Eve swaps Alice's X25519/KEM keys but cannot sign as Alice.
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const { frame } = await buildMitmFrameFresh(alice.buildClientHello());
  const resp = await bob.processClientHello(frame.payload);
  // Alice's view of the transcript differs, so Bob's signature fails for her
  await assert.rejects(alice.processKemResponse(resp), SignatureVerificationError);
});

test('full MITM is detectable: safety codes differ', async () => {
  // Eve runs one handshake with Alice (as Bob) and one with Bob (as Alice)
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const eveAsBob = await new SessionResponder().init();
  const eveAsAlice = await new SessionInitiator().init();

  const finA = await alice.processKemResponse(await eveAsBob.processClientHello(alice.buildClientHello()));
  await eveAsBob.processClientFinished(finA);
  const finE = await eveAsAlice.processKemResponse(await bob.processClientHello(eveAsAlice.buildClientHello()));
  await bob.processClientFinished(finE);

  // Both handshakes "succeed" — signatures can't detect an unknown peer...
  const m = await alice.session.encryptMessage('secret');
  assert.equal(text(await eveAsBob.session.decryptMessage(m)), 'secret');
  // ...but the safety codes on Alice's and Bob's screens do not match.
  assert.notEqual(alice.safetyCode.digits, bob.safetyCode.digits);
});

test('ActiveMitm relays a full session, reads plaintext, and safety codes differ', async () => {
  const alice = await new SessionInitiator().init();
  const bob = await new SessionResponder().init();
  const eve = new ActiveMitm();

  // Drive the frames exactly as the compromised relay would hand them to Eve
  const toAB = {};
  const deliver = async (actions) => {
    for (const a of actions) {
      if (a.target === 'bob' && a.frame.type === 'client_hello') {
        toAB.bobResp = await bob.processClientHello(a.frame.payload);
      } else if (a.target === 'alice' && a.frame.type === 'kem_response') {
        toAB.aliceFin = await alice.processKemResponse(a.frame.payload);
      } else if (a.target === 'bob' && a.frame.type === 'client_finished') {
        await bob.processClientFinished(a.frame.payload);
      } else if (a.target === 'bob' && a.frame.type === 'data') {
        toAB.bobGot = text(await bob.session.decryptMessage(a.frame.payload));
        toAB.evePlain = a.plaintext;
      }
    }
  };
  await deliver(await eve.onFrame('alice', { type: 'client_hello', payload: alice.buildClientHello() }));
  await deliver(await eve.onFrame('bob', { type: 'kem_response', payload: toAB.bobResp }));
  await deliver(await eve.onFrame('alice', { type: 'client_finished', payload: toAB.aliceFin }));
  assert.ok(eve.established);

  await deliver(await eve.onFrame('alice', { type: 'data', payload: await alice.session.encryptMessage('meet at 9') }));
  assert.equal(toAB.bobGot, 'meet at 9');
  assert.equal(toAB.evePlain, 'meet at 9');
  assert.equal(eve.codes.alice.digits, alice.safetyCode.digits);
  assert.equal(eve.codes.bob.digits, bob.safetyCode.digits);
  assert.notEqual(alice.safetyCode.digits, bob.safetyCode.digits);
});

test('ClientFinished before ClientHello is rejected', async () => {
  const bob = await new SessionResponder().init();
  await assert.rejects(bob.processClientFinished({ signature: '' }), ProtocolError);
});

test('seqAad refuses invalid seq and encodes big-endian', () => {
  assert.equal(toHex(seqAad(258)), '0000000000000102');
  assert.throws(() => seqAad(NaN), ProtocolError);
});

test('SecureSession requires 32-byte keys', () => {
  assert.throws(() => new SecureSession(new Uint8Array(16), new Uint8Array(32), 'alice'));
});
