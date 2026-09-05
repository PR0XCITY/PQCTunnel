/**
 * AliceBobView.jsx — "Quantum Console Interface"
 *
 * Performs the full hybrid handshake client-side.
 * All keypairs generated locally. Relay is blind.
 * Displays real ciphertext hex and real decrypted plaintext.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { SessionInitiator, SessionResponder } from '../crypto/session.js';
import { makeEnvelope, toHex, b64ToBytes } from '../crypto/protocol.js';
import { useWebSocket } from '../hooks/useWebSocket.js';
import WireView from '../components/WireView.jsx';
import ChatPanel from '../components/ChatPanel.jsx';
import HandshakeTiming from '../components/HandshakeTiming.jsx';

export default function AliceBobView({ roomCode, role }) {
  const [handshakeStatus, setHandshakeStatus] = useState('waiting'); // waiting|handshaking|secure|error
  const [wireLog,   setWireLog]   = useState([]);
  const [messages,  setMessages]  = useState([]);
  const [timing,    setTiming]    = useState(null);
  const [peerOnline, setPeerOnline] = useState(false);
  const [statusMsg, setStatusMsg] = useState('Waiting for peer...');

  const sessionRef   = useRef(null);   // SecureSession
  const initiatorRef = useRef(null);   // SessionInitiator (alice only)
  const responderRef = useRef(null);   // SessionResponder (bob only)

  const peer = role === 'alice' ? 'bob' : 'alice';

  const addWire = useCallback((direction, type, payload, extra = {}) => {
    setWireLog(prev => [...prev, {
      id:        Date.now() + Math.random(),
      ts:        new Date().toISOString(),
      direction,
      type,
      payload,
      ...extra,
    }]);
  }, []);

  // ── Message handler ──────────────────────────────────────────────────────
  const handleMessage = useCallback(async (msg) => {
    const { type, payload } = msg;

    if (type === 'joined') {
      setStatusMsg(`Joined room ${payload.room} as ${payload.role.toUpperCase()}`);
      if (payload.peers?.includes(peer)) {
        setPeerOnline(true);
        if (role === 'alice') startHandshake();
      }
      return;
    }

    if (type === 'peer_joined') {
      setPeerOnline(true);
      setStatusMsg(`${payload.role.toUpperCase()} connected — starting handshake...`);
      if (role === 'alice') startHandshake();
      return;
    }

    if (type === 'peer_left') {
      setPeerOnline(false);
      sessionRef.current = null;
      setHandshakeStatus('waiting');
      setStatusMsg('Peer disconnected. Waiting...');
      return;
    }

    if (type === 'client_hello' && role === 'bob') {
      await handleClientHello(payload);
      return;
    }

    if (type === 'kem_response' && role === 'alice') {
      await handleKemResponse(payload);
      return;
    }

    if (type === 'data' && sessionRef.current) {
      await handleDataMessage(payload);
      return;
    }

    if (type === 'rejection') {
      addWire('in', 'rejection', payload, { isRejection: true });
      return;
    }
  }, [role, peer]);

  const { status: wsStatus, send } = useWebSocket(roomCode, role, {
    onMessage: handleMessage,
  });

  // ── Alice: initiate handshake ────────────────────────────────────────────
  const startHandshake = useCallback(async () => {
    if (handshakeStatus !== 'waiting' && handshakeStatus !== 'error') return;
    setHandshakeStatus('handshaking');
    setStatusMsg('Generating keypairs...');

    try {
      const t0 = performance.now();
      const initiator = await new SessionInitiator().init();
      initiatorRef.current = initiator;

      const helloPayload = initiator.buildClientHello();
      const envelope = makeEnvelope('client_hello', helloPayload);

      addWire('out', 'client_hello', helloPayload, {
        label: 'Alice → Bob (ClientHello)',
        fields: {
          version:   helloPayload.version,
          x25519_pk: toHex(b64ToBytes(helloPayload.x25519_pk)),
          kem_pk:    toHex(b64ToBytes(helloPayload.kem_pk)).slice(0, 32) + '...',
          sig_pk:    toHex(b64ToBytes(helloPayload.sig_pk)).slice(0, 32) + '...',
        },
      });

      send(envelope);
      setStatusMsg('Sent ClientHello — waiting for KemResponse...');
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Handshake error: ${e.message}`);
    }
  }, [handshakeStatus, send, addWire]);

  // ── Bob: process ClientHello, send KemResponse ───────────────────────────
  const handleClientHello = useCallback(async (helloPayload) => {
    setHandshakeStatus('handshaking');
    setStatusMsg('Received ClientHello — encapsulating...');

    addWire('in', 'client_hello', helloPayload, {
      label: 'Alice → Bob (ClientHello)',
      fields: {
        x25519_pk: toHex(b64ToBytes(helloPayload.x25519_pk)),
        kem_pk:    toHex(b64ToBytes(helloPayload.kem_pk)).slice(0, 32) + '...',
        sig_pk:    toHex(b64ToBytes(helloPayload.sig_pk)).slice(0, 32) + '...',
      },
    });

    try {
      const responder = await new SessionResponder().init();
      responderRef.current = responder;

      const kemResponsePayload = await responder.processClientHello(helloPayload);
      sessionRef.current = responder.session;

      const t = responder.timing;
      setTiming(t.toDict());
      setHandshakeStatus('secure');
      setStatusMsg('Handshake complete. Channel is secure.');

      addWire('out', 'kem_response', kemResponsePayload, {
        label: 'Bob → Alice (KemResponse)',
        fields: {
          kem_ct:    toHex(b64ToBytes(kemResponsePayload.kem_ct)).slice(0, 32) + '...',
          x25519_pk: toHex(b64ToBytes(kemResponsePayload.x25519_pk)),
          sig_pk:    toHex(b64ToBytes(kemResponsePayload.sig_pk)).slice(0, 32) + '...',
          signature: toHex(b64ToBytes(kemResponsePayload.signature)).slice(0, 32) + '...',
        },
      });

      send(makeEnvelope('kem_response', kemResponsePayload));
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Handshake failed: ${e.message}`);
      addWire('in', 'error', { reason: e.message }, { isRejection: true });
    }
  }, [send, addWire]);

  // ── Alice: process KemResponse, derive session key ───────────────────────
  const handleKemResponse = useCallback(async (responsePayload) => {
    setStatusMsg('Received KemResponse — verifying signature...');

    addWire('in', 'kem_response', responsePayload, {
      label: 'Bob → Alice (KemResponse)',
      fields: {
        kem_ct:    toHex(b64ToBytes(responsePayload.kem_ct)).slice(0, 32) + '...',
        x25519_pk: toHex(b64ToBytes(responsePayload.x25519_pk)),
        signature: toHex(b64ToBytes(responsePayload.signature)).slice(0, 32) + '...',
      },
    });

    try {
      const initiator = initiatorRef.current;
      await initiator.processKemResponse(responsePayload);
      sessionRef.current = initiator.session;

      const t = initiator.timing;
      setTiming(t.toDict());
      setHandshakeStatus('secure');
      setStatusMsg('Handshake complete. Channel is secure.');
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Verification failed: ${e.message}`);
      addWire('in', 'error', { reason: e.message }, { isRejection: true });
    }
  }, [addWire]);

  // ── Data message ─────────────────────────────────────────────────────────
  const handleDataMessage = useCallback(async (payload) => {
    try {
      const plainBytes = await sessionRef.current.decryptMessage(payload);
      const plaintext  = new TextDecoder().decode(plainBytes);

      addWire('in', 'data', payload, {
        label:     `${peer.toUpperCase()} → ${role.toUpperCase()} (encrypted)`,
        plaintext,
        fields: {
          seq:        payload.seq,
          nonce:      payload.nonce,
          ciphertext: payload.ciphertext.slice(0, 32) + '...',
          tag:        payload.tag,
          decrypted:  plaintext,
        },
      });

      setMessages(prev => [...prev, { id: Date.now(), from: peer, text: plaintext }]);
    } catch (e) {
      addWire('in', 'rejection', { reason: e.message }, { isRejection: true });
    }
  }, [peer, role, addWire]);

  // ── Send a chat message ───────────────────────────────────────────────────
  const sendMessage = useCallback(async (text) => {
    if (!sessionRef.current || !text.trim()) return;
    const plainBytes = new TextEncoder().encode(text);
    const payload    = await sessionRef.current.encryptMessage(plainBytes);
    const envelope   = makeEnvelope('data', payload);

    addWire('out', 'data', payload, {
      label:    `${role.toUpperCase()} → ${peer.toUpperCase()} (encrypted)`,
      plaintext: text,
      fields: {
        seq:        payload.seq,
        nonce:      payload.nonce,
        ciphertext: payload.ciphertext.slice(0, 32) + '...',
        tag:        payload.tag,
        plaintext:  text,
      },
    });

    send(envelope);
    setMessages(prev => [...prev, { id: Date.now(), from: role, text }]);
  }, [role, peer, send, addWire]);

  // ── Status indicator ──────────────────────────────────────────────────────
  const statusColors = {
    waiting:     '#64748b',
    handshaking: '#f59e0b',
    secure:      '#10b981',
    error:       '#ef4444',
  };

  return (
    <div className="ab-layout">
      {/* Header */}
      <header className="ab-header">
        <div className="ab-header-left">
          <span className={`role-badge role-${role}`}>
            {role === 'alice' ? '🔵' : '🟢'} {role.toUpperCase()}
          </span>
          <span className="room-code">Room: {roomCode}</span>
        </div>
        <div className="ab-header-center">
          <div
            className="status-dot"
            style={{ background: statusColors[handshakeStatus] }}
          />
          <span className="status-text">{statusMsg}</span>
        </div>
        <div className="ab-header-right">
          <div className={`peer-pill ${peerOnline ? 'online' : 'offline'}`}>
            {peer.toUpperCase()} {peerOnline ? '● online' : '○ offline'}
          </div>
          <div className={`ws-pill ${wsStatus}`}>{wsStatus}</div>
        </div>
      </header>

      {/* Main panels */}
      <div className="ab-body">
        {/* Left: Wire View */}
        <div className="ab-panel ab-wire">
          <div className="panel-header">
            <span className="panel-icon">⚡</span>
            <span>Wire Traffic</span>
            <span className="panel-badge">{wireLog.length}</span>
          </div>
          <WireView entries={wireLog} />
        </div>

        {/* Center: Chat */}
        <div className="ab-panel ab-chat">
          <div className="panel-header">
            <span className="panel-icon">💬</span>
            <span>Secure Chat</span>
            {handshakeStatus === 'secure' && (
              <span className="secure-badge">🔒 AES-256-GCM</span>
            )}
          </div>
          <ChatPanel
            messages={messages}
            role={role}
            peer={peer}
            isSecure={handshakeStatus === 'secure'}
            onSend={sendMessage}
          />
        </div>

        {/* Right: Timing */}
        <div className="ab-panel ab-timing">
          <div className="panel-header">
            <span className="panel-icon">⏱</span>
            <span>Handshake Timing</span>
          </div>
          <HandshakeTiming timing={timing} role={role} />
        </div>
      </div>
    </div>
  );
}
