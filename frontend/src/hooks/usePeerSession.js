/**
 * usePeerSession.js
 * Alice/Bob protocol state machine on top of useWebSocket.
 *
 * Protocol state lives in refs (not React state) so async handlers never see a
 * stale phase, and incoming frames are processed strictly one at a time.
 * React state mirrors it purely for rendering.
 *
 * Phases: waiting → handshaking → secure | error | aborted
 *
 * Every frame the client refuses is reported back over the relay as an
 * { type: "alert" } frame, so the sender (and Eve's console) can see why.
 */

import { useState, useRef, useCallback, useEffect } from 'react';
import { useWebSocket } from './useWebSocket.js';
import { SessionInitiator, SessionResponder } from '../crypto/session.js';
import { makeEnvelope, toHex, b64ToBytes, fingerprint, validateClientHello, REKEY_SIGNAL } from '../crypto/protocol.js';

const clock = () => {
  const d = new Date();
  return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
};
let nextId = 1;
const uid = () => nextId++;

const frameBytes = (obj) => new TextEncoder().encode(JSON.stringify(obj)).length;
const b64Short = (b64, n = 16) => {
  const hex = toHex(b64ToBytes(b64));
  return hex.length > n * 2 ? `${hex.slice(0, n * 2)}…` : hex;
};

export function usePeerSession(roomCode, role) {
  const peer = role === 'alice' ? 'bob' : 'alice';
  const isInitiator = role === 'alice';

  const [phase, setPhaseState]     = useState('waiting');
  const [statusMsg, setStatusMsg]  = useState('Connecting to relay...');
  const [peerOnline, setPeerOnline] = useState(false);
  const [eveOnline, setEveOnline]  = useState(false);
  const [messages, setMessages]    = useState([]);
  const [wireLog, setWireLog]      = useState([]);
  const [handshake, setHandshake]  = useState(null); // { steps, timing, safetyCode, keys }
  const [verification, setVerification] = useState('unverified'); // unverified | match | mismatch

  const phaseRef   = useRef('waiting');
  const engineRef  = useRef(null);   // SessionInitiator | SessionResponder
  const sessionRef = useRef(null);   // SecureSession
  const queueRef   = useRef(Promise.resolve());
  const sendRef    = useRef(() => {});

  const setPhase = (p) => { phaseRef.current = p; setPhaseState(p); };

  const wire = useCallback((dir, type, fields = {}, extra = {}) => {
    setWireLog(prev => [...prev.slice(-299), { id: uid(), ts: clock(), dir, type, fields, ...extra }]);
  }, []);

  const transmit = useCallback((type, payload, fields) => {
    const env = makeEnvelope(type, payload);
    sendRef.current(env);
    wire('out', type, fields, { bytes: frameBytes(env), frame: env });
  }, [wire]);

  /** Refuse a frame: log it, show it, and tell the peer + observers why. */
  const reject = useCallback((frameType, err, payload, trace) => {
    const reason = err.message || String(err);
    wire('err', frameType, { REASON: reason }, { frame: payload && makeEnvelope(frameType, payload) });
    if (frameType === 'data') {
      setMessages(prev => [...prev, {
        id: uid(), from: peer, blocked: true, reason, ts: clock(), trace: trace ?? err.trace ?? [],
      }]);
    }
    sendRef.current(makeEnvelope('alert', {
      reason, frame_type: frameType, seq: payload?.seq ?? null, from: role,
    }));
  }, [peer, role, wire]);

  const resetSession = useCallback((msg) => {
    engineRef.current = null;
    sessionRef.current = null;
    setPhase('waiting');
    setHandshake(null);
    setVerification('unverified');
    setStatusMsg(msg);
  }, []);

  const publishHandshake = useCallback(async (engine) => {
    const s = sessionRef.current;
    setHandshake({
      steps: [...engine.log.steps],
      timing: engine.timing.toDict(),
      safetyCode: engine.safetyCode,
      keys: s ? {
        send: toHex(s.sendKey), recv: toHex(s.recvKey),
        sendFp: await fingerprint(s.sendKey), recvFp: await fingerprint(s.recvKey),
      } : null,
    });
  }, []);

  // ── Handshake (Alice) ────────────────────────────────────────────────────
  const startHandshake = useCallback(async () => {
    if (phaseRef.current === 'handshaking' || phaseRef.current === 'secure') return;
    setPhase('handshaking');
    setStatusMsg('Generating X25519, ML-KEM-768 and ML-DSA-65 keypairs...');
    try {
      const engine = await new SessionInitiator().init();
      engineRef.current = engine;
      const hello = engine.buildClientHello();
      transmit('client_hello', hello, {
        X25519_PK: b64Short(hello.x25519_pk, 32),
        KEM_PK: b64Short(hello.kem_pk),
        SIG_PK: b64Short(hello.sig_pk),
        VERSION: hello.version,
      });
      await publishHandshake(engine);
      setStatusMsg('ClientHello sent — waiting for Bob\'s KemResponse...');
    } catch (e) {
      setPhase('error');
      setStatusMsg(`Key generation failed: ${e.message}`);
    }
  }, [transmit, publishHandshake]);

  // ── Frame handlers ───────────────────────────────────────────────────────
  const onClientHello = async (payload) => {
    if (isInitiator) return reject('client_hello', new Error('unexpected ClientHello: Alice is the initiator'), payload);
    // Structural checks first, so a downgrade is reported as a downgrade
    try { validateClientHello(payload); } catch (e) { return reject('client_hello', e, payload); }
    if (phaseRef.current === 'handshaking' || phaseRef.current === 'secure') {
      return reject('client_hello', new Error('unexpected ClientHello: session already established'), payload);
    }
    wire('in', 'client_hello', {
      X25519_PK: b64Short(payload?.x25519_pk, 32),
      KEM_PK: b64Short(payload?.kem_pk),
      SIG_PK: b64Short(payload?.sig_pk),
    }, { bytes: frameBytes(payload ?? {}) });
    setPhase('handshaking');
    setStatusMsg('ClientHello received — encapsulating with ML-KEM-768...');
    const engine = await new SessionResponder().init();
    engineRef.current = engine;
    try {
      const resp = await engine.processClientHello(payload);
      transmit('kem_response', resp, {
        KEM_CT: b64Short(resp.kem_ct),
        X25519_PK: b64Short(resp.x25519_pk, 32),
        SIGNATURE: b64Short(resp.signature),
      });
      await publishHandshake(engine);
      setStatusMsg('KemResponse sent — waiting for Alice\'s signature...');
    } catch (e) {
      await publishHandshake(engine);
      setPhase('error');
      setStatusMsg(`Handshake rejected: ${e.message}`);
      reject('client_hello', e, payload);
    }
  };

  const onKemResponse = async (payload) => {
    const engine = engineRef.current;
    if (!isInitiator || phaseRef.current !== 'handshaking' || !(engine instanceof SessionInitiator)) {
      return reject('kem_response', new Error('unexpected KemResponse: no handshake in progress'), payload);
    }
    wire('in', 'kem_response', {
      KEM_CT: b64Short(payload?.kem_ct),
      X25519_PK: b64Short(payload?.x25519_pk, 32),
      SIGNATURE: b64Short(payload?.signature),
    }, { bytes: frameBytes(payload ?? {}) });
    setStatusMsg('Verifying Bob\'s ML-DSA-65 signature...');
    try {
      const fin = await engine.processKemResponse(payload);
      sessionRef.current = engine.session;
      transmit('client_finished', fin, { SIGNATURE: b64Short(fin.signature) });
      await publishHandshake(engine);
      setPhase('secure');
      setStatusMsg('Hybrid post-quantum channel established — compare safety codes with Bob');
    } catch (e) {
      await publishHandshake(engine);
      setPhase('error');
      setStatusMsg(`Handshake rejected: ${e.message}`);
      reject('kem_response', e, payload);
    }
  };

  const onClientFinished = async (payload) => {
    const engine = engineRef.current;
    if (isInitiator || phaseRef.current !== 'handshaking' || !(engine instanceof SessionResponder)) {
      return reject('client_finished', new Error('unexpected ClientFinished: no handshake in progress'), payload);
    }
    wire('in', 'client_finished', { SIGNATURE: b64Short(payload?.signature) }, { bytes: frameBytes(payload ?? {}) });
    try {
      sessionRef.current = await engine.processClientFinished(payload);
      await publishHandshake(engine);
      setPhase('secure');
      setStatusMsg('Hybrid post-quantum channel established — compare safety codes with Alice');
    } catch (e) {
      await publishHandshake(engine);
      setPhase('error');
      setStatusMsg(`Handshake rejected: ${e.message}`);
      reject('client_finished', e, payload);
    }
  };

  const onData = async (payload) => {
    const session = sessionRef.current;
    if (!session || phaseRef.current !== 'secure') {
      return reject('data', new Error('no established session'), payload, []);
    }
    try {
      const { plaintext, trace } = await session.open(payload);
      const text = new TextDecoder().decode(plaintext);
      if (text === REKEY_SIGNAL) {
        wire('in', 'data', { SEQ: String(payload.seq), CONTROL: 'authenticated re-key request' });
        resetSession(`${peer.toUpperCase()} requested a new handshake (authenticated) — waiting for ClientHello...`);
        return;
      }
      trace.push({ label: 'Plaintext', ok: true, ms: 0, detail: 'Shown in chat', value: text, plain: true });
      wire('in', 'data', { SEQ: String(payload.seq), CT: b64Short(payload.ciphertext), TAG: b64Short(payload.tag), DECRYPTED: text },
        { bytes: frameBytes(payload), frame: makeEnvelope('data', payload) });
      setMessages(prev => [...prev, { id: uid(), from: peer, text, ts: clock(), trace, seq: payload.seq, payload }]);
    } catch (e) {
      reject('data', e, payload);
    }
  };

  const handle = async (msg) => {
    const { type, payload } = msg ?? {};
    switch (type) {
      case 'joined':
        setStatusMsg(`Joined room ${payload.room} as ${role.toUpperCase()}`);
        setEveOnline(payload.peers?.includes('eve') ?? false);
        if (payload.peers?.includes(peer)) {
          setPeerOnline(true);
          if (isInitiator) await startHandshake();
        } else {
          setStatusMsg(`Joined room ${payload.room} — waiting for ${peer.toUpperCase()}...`);
        }
        return;
      case 'peer_joined':
        if (payload.role === 'eve') { setEveOnline(true); return; }
        if (payload.role !== peer) return;
        setPeerOnline(true);
        resetSession(`${peer.toUpperCase()} connected — starting handshake...`);
        if (isInitiator) await startHandshake();
        return;
      case 'peer_left':
        if (payload.role === 'eve') { setEveOnline(false); return; }
        if (payload.role !== peer) return;
        setPeerOnline(false);
        resetSession(`${peer.toUpperCase()} disconnected — session keys destroyed. Waiting for reconnect...`);
        return;
      case 'client_hello':    return onClientHello(payload);
      case 'kem_response':    return onKemResponse(payload);
      case 'client_finished': return onClientFinished(payload);
      case 'data':            return onData(payload);
      case 'alert':
        wire('alert', 'alert', { REASON: payload?.reason ?? '?', FRAME: payload?.frame_type ?? '?' });
        return;
      case 'rejection':
      case 'error':
        wire('relay', type, { REASON: payload?.reason ?? '?' });
        return;
      default:
        wire('relay', String(type), {});
    }
  };

  const handleRef = useRef(handle);
  handleRef.current = handle;

  const onMessage = useCallback((msg) => {
    // Serialize: each frame is fully processed before the next one starts
    queueRef.current = queueRef.current
      .then(() => handleRef.current(msg))
      .catch(e => console.error('[session] handler error', e));
  }, []);

  const { status: wsStatus, send } = useWebSocket(roomCode, role, { onMessage });
  useEffect(() => { sendRef.current = send; }, [send]);

  // ── Sending ──────────────────────────────────────────────────────────────
  const sendMessage = useCallback(async (text) => {
    const session = sessionRef.current;
    if (!session || phaseRef.current !== 'secure' || !text) return;
    const { payload, trace } = await session.seal(text);
    trace.unshift({ label: 'Plaintext', ok: true, ms: 0, detail: 'Typed by you', value: text, plain: true });
    transmit('data', payload, { SEQ: String(payload.seq), CT: b64Short(payload.ciphertext), TAG: b64Short(payload.tag), PLAINTEXT: text });
    setMessages(prev => [...prev, { id: uid(), from: role, text, ts: clock(), trace, seq: payload.seq, payload }]);
  }, [role, transmit]);

  /** User compared safety codes. A mismatch tears the session down. */
  const confirmSafetyCode = useCallback((matches) => {
    setVerification(matches ? 'match' : 'mismatch');
    if (!matches) {
      sessionRef.current = null;
      engineRef.current = null;
      setPhase('aborted');
      setStatusMsg('Safety codes did not match — possible man-in-the-middle. Session keys destroyed.');
      sendRef.current(makeEnvelope('alert', { reason: 'safety code mismatch — session aborted', frame_type: 'handshake', from: role }));
    }
  }, [role]);

  /** Alice can re-run the handshake after an error or abort. */
  const restartHandshake = useCallback(() => {
    if (!isInitiator) return;
    queueRef.current = queueRef.current.then(async () => {
      const session = sessionRef.current;
      if (session && phaseRef.current === 'secure') {
        const { payload } = await session.seal(REKEY_SIGNAL);
        transmit('data', payload, { SEQ: String(payload.seq), CONTROL: 're-key request (encrypted)' });
      }
      resetSession('Starting a new handshake...');
      await startHandshake();
    }).catch(e => console.error('[session] restart error', e));
  }, [isInitiator, resetSession, startHandshake, transmit]);

  return {
    peer, isInitiator, wsStatus,
    phase, statusMsg, peerOnline, eveOnline,
    messages, wireLog, handshake, verification,
    sendMessage, confirmSafetyCode, restartHandshake,
  };
}
