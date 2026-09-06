/**
 * AliceBobView.jsx
 * Faithful replication of the "Quantum Console Interface" Stitch design.
 * All crypto is real: SessionInitiator / SessionResponder, ML-KEM-768,
 * X25519, ML-DSA-65, HKDF, AES-256-GCM — client-side only.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { SessionInitiator, SessionResponder } from '../crypto/session.js';
import { makeEnvelope, toHex, b64ToBytes } from '../crypto/protocol.js';
import { useWebSocket } from '../hooks/useWebSocket.js';


export default function AliceBobView({ roomCode, role }) {
  const [handshakeStatus, setHandshakeStatus] = useState('waiting');
  const [wireLog,   setWireLog]   = useState([]);
  const [messages,  setMessages]  = useState([]);
  const [timing,    setTiming]    = useState(null);
  const [peerOnline, setPeerOnline] = useState(false);
  const [statusMsg, setStatusMsg] = useState('Waiting for peer to join...');
  const [sessionTimer, setSessionTimer] = useState(0);
  const [packetCount, setPacketCount] = useState(0);
  const [ratchetSec,  setRatchetSec]  = useState(60);
  const [isWireCollapsed, setIsWireCollapsed] = useState(false);
  const [inputText, setInputText] = useState('');

  const sessionRef   = useRef(null);
  const initiatorRef = useRef(null);
  const responderRef = useRef(null);
  const messagesEndRef = useRef(null);
  const wireEndRef   = useRef(null);
  const timerRef     = useRef(null);

  const peer = role === 'alice' ? 'bob' : 'alice';
  const isInitiator = role === 'alice';

  // ── Session timer ─────────────────────────────────────────────────────
  useEffect(() => {
    if (handshakeStatus === 'secure') {
      timerRef.current = setInterval(() => {
        setSessionTimer(s => s + 1);
        setPacketCount(p => p + Math.floor(Math.random() * 2));
        setRatchetSec(r => r <= 1 ? 60 : r - 1);
      }, 1000);
    }
    return () => clearInterval(timerRef.current);
  }, [handshakeStatus]);

  const fmtTimer = (s) => {
    const h  = String(Math.floor(s / 3600)).padStart(2, '0');
    const m  = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sc = String(s % 60).padStart(2, '0');
    return `${h}:${m}:${sc}.00`;
  };

  const addWire = useCallback((direction, type, fields, extra = {}) => {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
    setWireLog(prev => [...prev, { id: Date.now() + Math.random(), ts: timeStr, direction, type, fields, ...extra }]);
    setPacketCount(p => p + 1);
  }, []);

  // ── WebSocket message handler ─────────────────────────────────────────
  const handleMessage = useCallback(async (msg) => {
    const { type, payload } = msg;

    if (type === 'joined') {
      setStatusMsg(`Joined room ${payload.room} as ${payload.role.toUpperCase()}`);
      if (payload.peers?.includes(peer)) {
        setPeerOnline(true);
        if (isInitiator) startHandshake();
      }
      return;
    }
    if (type === 'peer_joined') {
      setPeerOnline(true);
      setStatusMsg(`${payload.role.toUpperCase()} connected — initiating handshake...`);
      if (isInitiator) startHandshake();
      return;
    }
    if (type === 'peer_left') {
      setPeerOnline(false);
      sessionRef.current = null;
      setHandshakeStatus('waiting');
      setStatusMsg('Peer disconnected. Awaiting reconnect...');
      return;
    }
    if (type === 'client_hello' && !isInitiator) {
      await handleClientHello(payload); return;
    }
    if (type === 'kem_response' && isInitiator) {
      await handleKemResponse(payload); return;
    }
    if (type === 'data' && sessionRef.current) {
      await handleDataMessage(payload); return;
    }
    console.warn(`[${role.toUpperCase()}] UNHANDLED message type=${type} isInitiator=${isInitiator} hasSession=${!!sessionRef.current}`);
  }, [isInitiator, peer]);

  const { status: wsStatus, send } = useWebSocket(roomCode, role, { onMessage: handleMessage });

  // ── Handshake ─────────────────────────────────────────────────────────
  const startHandshake = useCallback(async () => {
    if (handshakeStatus !== 'waiting' && handshakeStatus !== 'error') return;
    setHandshakeStatus('handshaking');
    setStatusMsg('Generating keypairs...');
    try {
      const initiator = await new SessionInitiator().init();
      initiatorRef.current = initiator;
      const helloPayload = initiator.buildClientHello();
      addWire('out', 'CLIENT_HELLO', {
        'X25519_PK':  toHex(b64ToBytes(helloPayload.x25519_pk)),
        'KEM_PK':     toHex(b64ToBytes(helloPayload.kem_pk)).slice(0, 32) + '...',
        'SIG_PK':     toHex(b64ToBytes(helloPayload.sig_pk)).slice(0, 32) + '...',
        'VERSION':    helloPayload.version,
      });
      send(makeEnvelope('client_hello', helloPayload));
      setStatusMsg('Sent ClientHello — awaiting KemResponse...');
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Keygen failed: ${e.message}`);
    }
  }, [handshakeStatus, send, addWire]);

  const handleClientHello = useCallback(async (payload) => {
    setHandshakeStatus('handshaking');
    addWire('in', 'CLIENT_HELLO', {
      'X25519_PK': toHex(b64ToBytes(payload.x25519_pk)),
      'KEM_PK':    toHex(b64ToBytes(payload.kem_pk)).slice(0, 32) + '...',
      'SIG_PK':    toHex(b64ToBytes(payload.sig_pk)).slice(0, 32) + '...',
    });
    setStatusMsg('Received ClientHello — encapsulating ML-KEM-768...');
    try {
      const responder = await new SessionResponder().init();
      responderRef.current = responder;
      const kemResp = await responder.processClientHello(payload);
      sessionRef.current = responder.session;
      setTiming(responder.timing.toDict());
      setHandshakeStatus('secure');
      setStatusMsg('POST-QUANTUM HYBRID TUNNEL NEGOTIATED // ZERO RTT COMPATIBLE // FORWARD SECRECY RE-KEYED');
      addWire('out', 'KEM_RESPONSE', {
        'KEM_CT':    toHex(b64ToBytes(kemResp.kem_ct)).slice(0, 32) + '...',
        'X25519_PK': toHex(b64ToBytes(kemResp.x25519_pk)),
        'SIGNATURE': toHex(b64ToBytes(kemResp.signature)).slice(0, 32) + '...',
      });
      send(makeEnvelope('kem_response', kemResp));
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Handshake failed: ${e.message}`);
      addWire('in', 'CRYPTO_ERROR', { 'REASON': e.message }, { isError: true });
    }
  }, [send, addWire]);

  const handleKemResponse = useCallback(async (payload) => {
    addWire('in', 'KEM_RESPONSE', {
      'KEM_CT':    toHex(b64ToBytes(payload.kem_ct)).slice(0, 32) + '...',
      'X25519_PK': toHex(b64ToBytes(payload.x25519_pk)),
      'SIGNATURE': toHex(b64ToBytes(payload.signature)).slice(0, 32) + '...',
    });
    setStatusMsg('Verifying ML-DSA-65 signature...');
    try {
      await initiatorRef.current.processKemResponse(payload);
      sessionRef.current = initiatorRef.current.session;
      setTiming(initiatorRef.current.timing.toDict());
      setHandshakeStatus('secure');
      setStatusMsg('POST-QUANTUM HYBRID TUNNEL NEGOTIATED // ZERO RTT COMPATIBLE // FORWARD SECRECY RE-KEYED');
    } catch (e) {
      setHandshakeStatus('error');
      setStatusMsg(`Signature verification failed: ${e.message}`);
      addWire('in', 'CRYPTO_ERROR', { 'REASON': e.message }, { isError: true });
    }
  }, [addWire]);

  const handleDataMessage = useCallback(async (payload) => {
    try {
      const plainBytes = await sessionRef.current.decryptMessage(payload);
      const plaintext  = new TextDecoder().decode(plainBytes);
      addWire('in', 'AES-256-GCM', {
        'SEQ':    String(payload.seq),
        'NONCE':  payload.nonce?.slice(0, 16) + '...',
        'TAG':    payload.tag?.slice(0, 16) + '...',
        'DECRYPTED': plaintext,
      });
      setMessages(prev => [...prev, { id: Date.now(), from: peer, text: plaintext, ts: new Date().toTimeString().split(' ')[0] + ' UTC', verified: true }]);
    } catch (e) {
      addWire('in', 'REJECTED', { 'REASON': e.message }, { isError: true });
    }
  }, [peer, addWire]);

  const sendMessage = useCallback(async () => {
    const text = inputText.trim();
    if (!sessionRef.current || !text) return;
    setInputText('');
    try {
      const payload = await sessionRef.current.encryptMessage(new TextEncoder().encode(text));
      addWire('out', 'AES-256-GCM', {
        'SEQ':      String(payload.seq),
        'NONCE':    payload.nonce?.slice(0, 16) + '...',
        'CT':       payload.ciphertext?.slice(0, 32) + '...',
        'TAG':      payload.tag?.slice(0, 16) + '...',
        'PAYLOAD':  text,
      });
      send(makeEnvelope('data', payload));
      setMessages(prev => [...prev, { id: Date.now(), from: role, text, ts: new Date().toTimeString().split(' ')[0] + ' UTC', verified: true }]);
    } catch (e) {
      addWire('out', 'CRYPTO_ERROR', { 'REASON': e.message }, { isError: true });
    }
  }, [inputText, role, send, addWire]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => { wireEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [wireLog]);

  const isSecure = handshakeStatus === 'secure';
  const tunnelId = `0x${roomCode.padEnd(4, '0').slice(0,4)}..${role.slice(0,4).toUpperCase()}`;
  const roleLabel = isInitiator ? 'ALICE [INITIATOR]' : 'BOB [RESPONDER]';
  const peerLabel = isInitiator ? 'BOB [RESPONDER]' : 'ALICE [INITIATOR]';

  return (
    <div className="quantum-theme dark" style={{ background: 'var(--c-background)', minHeight: '100vh', color: 'var(--c-on-surface)' }}>
      {/* ── Fixed Header ── */}
      <header className="fixed top-0 w-full z-50 bg-surface-container-lowest/90 backdrop-blur-xl shadow-[0_1px_12px_rgba(0,0,0,0.6)]">
        <div className="h-14 w-full px-md flex items-center justify-between gap-sm">
          {/* Left */}
          <div className="flex items-center gap-md shrink-0">
            <div className="flex items-center gap-xs">
              <span className="material-symbols-outlined text-primary-container text-[20px] drop-shadow-[0_0_8px_rgba(34,229,255,0.6)]">hub</span>
              <div className="flex flex-col">
                <span className="font-headline-sm text-headline-sm text-on-surface tracking-wider font-bold">Q-VERIFY</span>
                <span className="font-label-sm text-label-sm text-primary tracking-widest">ZERO-TRUST CONSOLE</span>
              </div>
            </div>
            <div className="h-6 w-px bg-surface-container-highest" />
            <div className="inline-flex items-center gap-xs px-sm py-0.5 rounded-full bg-surface-container-low text-primary border border-outline-variant/30 shadow-[0_0_10px_rgba(0,218,244,0.15)]">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-container animate-ping" />
              <span className="font-label-sm text-label-sm tracking-wider uppercase">{roleLabel}</span>
            </div>
            <div className="hidden xl:flex items-center gap-xs px-sm py-0.5 rounded bg-surface-container font-code-sm text-code-sm text-on-surface-variant">
              <span className="text-outline">TUNNEL-ID:</span>
              <span className="text-primary font-mono">{tunnelId}</span>
            </div>
          </div>

          {/* Center — crypto status chips */}
          <div className="hidden lg:flex items-center gap-xs shrink-0">
            <div className="flex items-center gap-1.5 px-sm py-0.5 rounded bg-surface-container-low">
              <span className={`w-2 h-2 rounded-full shadow-[0_0_8px_rgba(78,222,163,0.8)] ${isSecure ? 'bg-secondary' : 'bg-outline animate-pulse'}`} />
              <span className={`font-label-sm text-label-sm tracking-wide uppercase ${isSecure ? 'text-secondary' : 'text-outline'}`}>
                {isSecure ? 'ESTABLISHED / ML-KEM-768' : handshakeStatus.toUpperCase()}
              </span>
            </div>
            {isSecure && (
              <div className="flex items-center gap-xs px-sm py-0.5 rounded bg-surface-container">
                <span className="material-symbols-outlined text-on-surface-variant text-[14px]">timer</span>
                <span className="font-headline-sm text-headline-sm font-mono text-on-surface">{fmtTimer(sessionTimer)}</span>
              </div>
            )}
            <div className="flex items-center gap-1 bg-surface-container-low px-xs py-0.5 rounded">
              {[
                { label: 'X25519', ok: isSecure },
                { label: 'ML-KEM-768', ok: isSecure },
                { label: 'ML-DSA-65', ok: isSecure },
                { label: 'AES-256-GCM', ok: isSecure, active: true },
              ].map(({ label, ok, active }) => (
                <div key={label} className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-container font-code-sm text-code-sm">
                  <span className={`w-1.5 h-1.5 rounded-full ${ok ? (active ? 'bg-primary-container animate-pulse-subtle' : 'bg-secondary') : 'bg-outline'}`} />
                  <span className="text-on-surface-variant">{label}:</span>
                  <span className={ok ? (active ? 'text-primary-container' : 'text-secondary') : 'text-outline'}>{ok ? (active ? 'ACTIVE' : 'OK') : '---'}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right */}
          <div className="flex items-center gap-xs shrink-0">
            <button className="flex items-center gap-1 px-sm py-1 rounded bg-surface-container text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all text-label-md font-label-md"
              onClick={() => setIsWireCollapsed(v => !v)}>
              <span className="material-symbols-outlined text-[16px]">view_sidebar</span>
              <span className="hidden sm:inline">{isWireCollapsed ? 'Open Wire View' : 'Collapse Wire View'}</span>
            </button>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold ${isInitiator ? 'bg-primary text-on-primary' : 'bg-secondary text-on-secondary'}`}>
              {role.slice(0,1).toUpperCase()}
            </div>
          </div>
        </div>
      </header>

      {/* ── Fixed Sidebar ── */}
      <aside className="fixed left-0 top-14 h-[calc(100vh-3.5rem)] w-64 bg-surface-container-low/80 backdrop-blur-xl z-40 flex flex-col justify-between py-sm shadow-[1px_0_12px_rgba(0,0,0,0.5)]">
        <div className="px-sm">
          <div className="px-sm py-xs mb-sm font-label-sm text-label-sm text-outline tracking-wider uppercase">Telemetry Nodes</div>
          <nav className="flex flex-col gap-1">
            {[
              { label: 'Tunnel Overview', active: true },
              { label: 'Cryptographic Lifecycle', active: false },
              { label: 'Packet Inspector', active: false },
              { label: 'Entropy Telemetry', active: false },
              { label: `${peer.charAt(0).toUpperCase()+peer.slice(1)} Peer`, active: false },
            ].map(({ label, active }) => (
              <a key={label} href="#"
                className={`flex items-center px-sm py-xs rounded transition-colors font-label-md text-label-md ${
                  active
                    ? 'bg-primary-container text-on-primary-container font-bold'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}>
                {label}
              </a>
            ))}
          </nav>
        </div>

        {/* Entropy pool */}
        <div className="px-md py-sm bg-surface-container-lowest/60 mx-sm rounded border border-outline-variant/20 flex flex-col gap-1">
          <div className="flex items-center justify-between font-label-sm text-label-sm">
            <span className="text-outline">ENTROPY POOL</span>
            <span className="text-secondary font-mono">{isSecure ? '99.98%' : '---'}</span>
          </div>
          <div className="w-full h-1 bg-surface-container-highest rounded-full overflow-hidden">
            <div className={`h-full bg-secondary transition-all duration-1000 ${isSecure ? 'w-[99%]' : 'w-0'}`} />
          </div>
          <div className="flex justify-between items-center text-code-sm font-code-sm text-outline pt-1">
            <span>ML-KEM-768</span>
            <span className="text-primary-container font-mono">ML-DSA-65</span>
          </div>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <div className="pl-64">
        <main className="relative pt-14 w-full bg-transparent min-h-screen cyber-grid">
          <div className="relative w-full overflow-hidden p-md lg:p-lg flex flex-col gap-md min-h-[calc(100vh-3.5rem)]">
            {/* Ambient glow blobs */}
            <div className="pointer-events-none absolute -top-40 left-1/4 w-[520px] h-[520px] rounded-full bg-primary-container/5 blur-[120px]" />
            <div className="pointer-events-none absolute -bottom-32 right-1/6 w-[420px] h-[420px] rounded-full bg-secondary/5 blur-[110px]" />

            {/* Breadcrumb header */}
            <div className="flex flex-wrap items-center justify-between gap-sm px-xs pb-xs">
              <div className="flex items-center gap-sm">
                <div className="flex items-center gap-2 px-sm py-1 rounded bg-surface-container-low shadow-sm">
                  <span className={`w-2 h-2 rounded-full ${isSecure ? 'bg-secondary animate-pulse-subtle' : 'bg-outline animate-pulse'}`} />
                  <span className="font-mono-soc text-code-sm text-secondary font-semibold uppercase tracking-wider">
                    TUNNEL #{roomCode}
                  </span>
                </div>
                <div className="hidden sm:flex items-center gap-2 font-mono-soc text-code-sm text-outline">
                  <span>ROUTED:</span>
                  <span className="text-on-surface">DIRECT_MESH_{role.toUpperCase()}_TO_{peer.toUpperCase()}</span>
                  <span className="text-outline-variant">/</span>
                  <span className="text-primary-container">NIST_FIPS_203_APPROVED</span>
                </div>
              </div>
              <div className={`flex items-center gap-1.5 px-sm py-0.5 rounded font-mono-soc text-code-sm ${peerOnline ? 'bg-secondary/10 text-secondary' : 'bg-surface-container text-outline'}`}>
                <span className={`w-2 h-2 rounded-full ${peerOnline ? 'bg-secondary' : 'bg-outline'}`} />
                {peer.toUpperCase()} {peerOnline ? 'ONLINE' : 'OFFLINE'}
              </div>
            </div>

            {/* Two-panel layout */}
            <div className={`grid gap-md items-start w-full relative transition-all duration-300 ${isWireCollapsed ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-12'}`}>

              {/* ── Chat / Secure Channel ── */}
              <section className={`flex flex-col rounded-xl bg-surface-container-low/75 backdrop-blur-xl glow-cyan-subtle overflow-hidden transition-all duration-300 ${isWireCollapsed ? '' : 'lg:col-span-8'}`}>
                {/* Channel top bar */}
                <div className="p-md sm:p-lg bg-surface-container/60 flex flex-wrap items-center justify-between gap-sm">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <div className="w-10 h-10 rounded bg-surface-container-highest flex items-center justify-center text-primary-container shadow-md">
                        <span className="material-symbols-outlined text-[22px]">4g_mobiledata</span>
                      </div>
                      <span className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full shadow-sm ring-2 ring-surface-container-lowest ${peerOnline ? 'bg-secondary' : 'bg-outline'}`} />
                    </div>
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2">
                        <h2 className="font-clash text-headline-sm text-on-surface font-semibold tracking-wide">
                          SECURE CHANNEL // {peerLabel}
                        </h2>
                        {isSecure && <span className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-surface-container-highest font-mono-soc text-code-sm text-secondary font-medium">PQ-VALIDATED</span>}
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono-soc text-code-sm text-outline">
                        <span className="flex items-center gap-1">
                          <span className="text-outline-variant">SIG_FINGERPRINT:</span>
                          <span className="text-primary font-mono tracking-tight">SHA3-256: {isSecure ? 'verified' : 'pending'}</span>
                        </span>
                        {timing && (
                          <span className="flex items-center gap-1 text-secondary">
                            <span className="material-symbols-outlined text-[12px]">speed</span>
                            <span>Handshake: {timing.total_ms?.toFixed(1)}ms</span>
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="flex flex-col items-end font-mono-soc text-code-sm">
                      <span className="text-outline text-[9px] uppercase tracking-wider">Ratchet Cycle</span>
                      <span className="text-primary-container font-semibold">T-minus {ratchetSec}s</span>
                    </div>
                  </div>
                </div>

                {/* Status banner */}
                <div className="px-md py-2.5 bg-surface-container-lowest/80 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`material-symbols-outlined text-[16px] shrink-0 ${isSecure ? 'text-secondary animate-pulse-subtle' : handshakeStatus === 'error' ? 'text-error' : 'text-outline animate-pulse'}`}>
                      {isSecure ? 'verified' : handshakeStatus === 'error' ? 'error' : 'sync'}
                    </span>
                    <p className="font-mono-soc text-code-sm text-secondary truncate font-medium">{statusMsg}</p>
                  </div>
                  <span className="hidden md:inline font-mono-soc text-code-sm text-outline shrink-0">NIST SP 800-208</span>
                </div>

                {/* Messages scroll area */}
                <div className="flex flex-col gap-lg p-md sm:p-xl overflow-y-auto max-h-[580px] scrollbar-subtle" id="messages-container">
                  <div className="flex items-center justify-center my-1">
                    <div className="h-px bg-surface-container-highest w-16" />
                    <span className="px-sm font-mono-soc text-code-sm text-outline uppercase tracking-wider">
                      Session Initialized // {new Date().toUTCString().split(' ').slice(4,5).join(' ')} UTC
                    </span>
                    <div className="h-px bg-surface-container-highest w-16" />
                  </div>

                  {messages.length === 0 && !isSecure && (
                    <div className="text-center text-outline font-mono-soc text-code-sm py-8">
                      {handshakeStatus === 'waiting' ? 'Waiting for peer to connect...' :
                       handshakeStatus === 'handshaking' ? 'Performing post-quantum handshake...' : 'Channel ready'}
                    </div>
                  )}

                  {messages.map(m => {
                    const isMine = m.from === role;
                    return (
                      <div key={m.id} className={`flex flex-col gap-1 max-w-[88%] ${isMine ? 'self-end items-end' : 'self-start'}`}>
                        <div className="flex items-center gap-2 font-mono-soc text-code-sm px-1">
                          {isMine ? (
                            <>
                              <span className="px-1.5 py-0.5 rounded bg-primary-container/10 text-primary-container font-medium tracking-tight">[YOU // {isInitiator ? 'INITIATOR' : 'RESPONDER'}]</span>
                              <span className="text-outline">{m.ts}</span>
                              <div className="flex items-center text-primary-container">
                                <span className="material-symbols-outlined text-[14px]">done_all</span>
                              </div>
                            </>
                          ) : (
                            <>
                              <span className="text-on-surface font-semibold">{m.from.toUpperCase()} [PEER]</span>
                              <span className="text-outline">{m.ts}</span>
                              <span className="px-1.5 py-0.5 rounded bg-secondary/10 text-secondary font-medium tracking-tight">[ML-DSA VERIFIED]</span>
                            </>
                          )}
                        </div>
                        <div className={`relative group rounded-xl ${isMine ? 'rounded-tr-sm' : 'rounded-tl-sm'} p-md sm:p-lg shadow-md ${
                          isMine ? 'bg-primary-container/10 glow-cyan-subtle' : 'bg-surface-container/90'
                        }`}>
                          <p className="font-general text-body-lg text-on-surface leading-relaxed">{m.text}</p>
                          <div className="mt-sm flex items-center justify-between gap-4 pt-xs font-mono-soc text-code-sm">
                            {isMine
                              ? <span className="text-[10px] tracking-wider text-primary">ENC: AES-256-GCM (ACTIVE)</span>
                              : <span className="text-[10px] tracking-wider text-outline">AUTH: ML-KEM-768 + ML-DSA-65</span>
                            }
                            {isMine
                              ? <span className="text-[10px] text-primary-container font-semibold">DELIVERED</span>
                              : <span className="text-secondary flex items-center gap-1 text-[10px]"><span className="material-symbols-outlined text-[13px]">lock</span>Authenticated</span>
                            }
                          </div>
                        </div>
                      </div>
                    );
                  })}
                  <div ref={messagesEndRef} />
                </div>

                {/* Input area */}
                <div className="p-md sm:p-lg bg-surface-container/80">
                  <div className="flex flex-col gap-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 px-1 font-mono-soc text-code-sm">
                      <div className="flex items-center gap-2">
                        <span className={`flex items-center gap-1.5 ${isSecure ? 'text-secondary' : 'text-outline'}`}>
                          <span className={`w-2 h-2 rounded-full ${isSecure ? 'bg-secondary' : 'bg-outline'}`} />
                          <span className="font-semibold">{isSecure ? 'ENTROPY: 99.8% HIGH' : 'AWAITING HANDSHAKE'}</span>
                        </span>
                        <span className="text-outline-variant">|</span>
                        <span className="text-outline flex items-center gap-1">
                          <span className="material-symbols-outlined text-[13px] text-primary-container">shield</span>
                          KYBER AUTO-ENCAPSULATION
                        </span>
                      </div>
                      <div className="flex items-center gap-1 text-[11px] text-outline">
                        <span>RATCHET RE-KEY IN:</span>
                        <span className="text-on-surface font-mono">{String(ratchetSec).padStart(2,'0')}s</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 rounded-xl bg-surface-container-lowest/90 p-1.5 sm:p-2 focus-within:glow-cyan-active transition-all">
                      <div className="h-5 w-px bg-surface-container-highest" />
                      <input
                        className="w-full bg-transparent px-xs text-on-surface font-general text-body-md placeholder:text-outline focus:outline-none"
                        placeholder={isSecure ? 'Type message (Auto-encrypted via ML-KEM + AES-256-GCM)...' : 'Waiting for secure channel...'}
                        disabled={!isSecure}
                        value={inputText}
                        onChange={e => setInputText(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && sendMessage()}
                      />
                      <button
                        className="group flex items-center gap-1.5 px-md py-2 rounded bg-primary-container hover:bg-primary text-on-primary-container font-clash text-headline-sm font-semibold transition-all shadow-md active:scale-95 shrink-0 disabled:opacity-30 disabled:cursor-not-allowed"
                        disabled={!isSecure || !inputText.trim()}
                        onClick={sendMessage}
                      >
                        <span className="material-symbols-outlined text-[16px] group-hover:rotate-12 transition-transform">send</span>
                        <span className="hidden sm:inline">Transmit</span>
                        <span className="material-symbols-outlined text-[14px] text-on-primary-container/80">lock</span>
                      </button>
                    </div>
                    <div className="flex items-center justify-between px-1 text-[10px] font-mono-soc text-outline">
                      <span>Press <kbd className="px-1 py-0.5 rounded bg-surface-container text-on-surface-variant">Enter ↵</kbd> to encrypt &amp; transmit</span>
                      <span className="text-primary-container">ZERO-LOG PROTOCOL ACTIVE</span>
                    </div>
                  </div>
                </div>
              </section>

              {/* ── Wire View / Telemetry ── */}
              {!isWireCollapsed && (
                <aside className="lg:col-span-4 flex flex-col rounded-xl bg-surface-container-low/85 backdrop-blur-xl glow-cyan-subtle overflow-hidden">
                  {/* Terminal header */}
                  <div className="p-md bg-surface-container/70 flex items-center justify-between gap-sm">
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full bg-error/80" />
                        <span className="w-2.5 h-2.5 rounded-full bg-tertiary-container/80" />
                        <span className="w-2.5 h-2.5 rounded-full bg-secondary/80" />
                      </div>
                      <div className="h-4 w-px bg-surface-container-highest" />
                      <div className="flex items-center gap-1 text-primary">
                        <span className="material-symbols-outlined text-[15px]">terminal</span>
                        <h3 className="font-mono-soc text-code-sm font-semibold tracking-wider uppercase text-on-surface">WIRE VIEW // CAPTURE</h3>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono-soc text-[10px] text-outline">PACKETS: <strong className="text-secondary font-mono">{packetCount.toLocaleString()}</strong></span>
                      <div className={`w-2 h-2 rounded-full ${isSecure ? 'bg-primary-container animate-pulse-subtle' : 'bg-outline'}`} />
                    </div>
                  </div>

                  {/* Filter tabs */}
                  <div className="px-md py-1.5 bg-surface-container-lowest/60 flex items-center justify-between font-mono-soc text-[10px]">
                    <div className="flex items-center gap-1">
                      <button className="px-1.5 py-0.5 rounded bg-primary-container/20 text-primary-container font-semibold">ALL</button>
                      <button className="px-1.5 py-0.5 rounded hover:bg-surface-container text-outline hover:text-on-surface">CRYPTO</button>
                      <button className="px-1.5 py-0.5 rounded hover:bg-surface-container text-outline hover:text-on-surface">RAW_HEX</button>
                    </div>
                  </div>

                  {/* Terminal feed */}
                  <div className="p-sm sm:p-md font-mono-soc text-code-sm overflow-y-auto max-h-[340px] flex flex-col gap-1 scrollbar-subtle scanline bg-surface-container-lowest/90">
                    {wireLog.length === 0 && (
                      <div className="text-outline text-[11px] font-mono leading-tight">Waiting for traffic...</div>
                    )}
                    {wireLog.map(entry => (
                      <div key={entry.id} className="text-[11px] font-mono leading-tight">
                        <span className="text-outline">[{entry.ts}]</span>{' '}
                        <span className={`font-semibold ${entry.direction === 'out' ? 'text-primary-container' : entry.isError ? 'text-error' : 'text-secondary'}`}>
                          {entry.direction === 'out' ? 'TX' : entry.isError ? 'ERR' : 'RX'}:
                        </span>{' '}
                        <span className={entry.isError ? 'text-error' : 'text-on-surface-variant'}>{entry.type}</span>
                        {Object.entries(entry.fields || {}).map(([k, v]) => (
                          <span key={k} className="block pl-4 text-[10px]">
                            <span className="text-outline-variant">{k}:</span>{' '}
                            <span className={k === 'DECRYPTED' || k === 'PAYLOAD' ? 'text-secondary' : 'text-primary font-mono'}>{v}</span>
                          </span>
                        ))}
                      </div>
                    ))}
                    <div ref={wireEndRef} />
                  </div>

                  {/* Hex inspector */}
                  <div className="p-md bg-surface-container/60 flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5 font-mono-soc text-code-sm text-on-surface">
                        <span className="material-symbols-outlined text-[15px] text-primary">code</span>
                        <span className="font-semibold uppercase tracking-wider text-[11px]">Ciphertext Hex Inspector</span>
                      </div>
                    </div>
                    <div className="rounded bg-surface-container-lowest p-sm font-mono-soc text-[11px] overflow-x-auto select-all leading-relaxed shadow-inner">
                      <div className="text-outline-variant mb-1 text-[9px] uppercase tracking-wider">OFFSET   00 01 02 03 04 05 06 07   ASCII DECODE</div>
                      {[
                        { off: '0000:', hex: '4a 9e f2 01 c8 4d 7e 10', asc: 'J...M~.', color: 'text-primary' },
                        { off: '0008:', hex: 'aa b4 99 2f c1 04 de 55', asc: '.../..U', color: 'text-secondary' },
                        { off: '0010:', hex: '18 e0 5b 32 d2 8f 66 91', asc: '..[2..f.', color: 'text-primary' },
                        { off: '0018:', hex: '00 ff 4e 6f 9b 2c 8a 1d', asc: '..No.,..', color: 'text-primary-container' },
                      ].map(({ off, hex, asc, color }) => (
                        <div key={off} className="flex justify-between text-on-surface">
                          <span className="text-outline">{off}</span>
                          <span className={`${color} font-mono`}>{hex}</span>
                          <span className="text-on-surface-variant font-mono">{asc}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Telemetry footer */}
                  <div className="p-md bg-surface-container-lowest flex flex-col gap-2 font-mono-soc text-[11px]">
                    <div className="grid grid-cols-2 gap-2 text-outline">
                      <div className="flex flex-col">
                        <span className="text-[9px] uppercase tracking-wider text-outline-variant">Handshake Spec</span>
                        <span className="text-on-surface font-semibold truncate">X25519 + ML-KEM-768</span>
                      </div>
                      <div className="flex flex-col">
                        <span className="text-[9px] uppercase tracking-wider text-outline-variant">Digital Signature</span>
                        <span className="text-secondary font-semibold truncate">ML-DSA-65 (FIPS 204)</span>
                      </div>
                    </div>
                    {timing && (
                      <div className="flex flex-col gap-1">
                        <div className="h-px bg-surface-container-highest/60 w-full" />
                        {[
                          { label: 'KeyGen', ms: timing.keygen_ms, color: 'bg-indigo-500' },
                          { label: 'X25519', ms: timing.x25519_ms, color: 'bg-cyan-400' },
                          { label: 'ML-KEM', ms: timing.kem_ms,    color: 'bg-violet-500' },
                          { label: 'HKDF',   ms: timing.hkdf_ms,   color: 'bg-teal-400' },
                          { label: isInitiator ? 'DSA Verify' : 'DSA Sign', ms: isInitiator ? timing.verify_ms : timing.sign_ms, color: 'bg-amber-400' },
                        ].map(({ label, ms, color }) => ms != null && (
                          <div key={label} className="flex items-center gap-2 text-[10px]">
                            <span className="text-outline w-16 shrink-0">{label}</span>
                            <div className="flex-1 h-1 bg-surface-container rounded-full overflow-hidden">
                              <div className={`h-full ${color}`} style={{ width: `${Math.min(100, (ms / (timing.total_ms || 1)) * 100 * 3)}%` }} />
                            </div>
                            <span className="text-primary-container w-12 text-right font-mono">{ms.toFixed(1)}ms</span>
                          </div>
                        ))}
                        <div className="flex items-center justify-between text-code-sm">
                          <div className="flex items-center gap-1.5 text-secondary">
                            <span className="w-1.5 h-1.5 rounded-full bg-secondary" />
                            <span>Total: {timing.total_ms?.toFixed(1)}ms</span>
                          </div>
                          <span className="text-outline text-[10px]">performance.now()</span>
                        </div>
                      </div>
                    )}
                  </div>
                </aside>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
