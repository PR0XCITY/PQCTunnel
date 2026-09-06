/**
 * EveView.jsx
 * Faithful replication of the "Adversary Red-Team Intercept Console" Stitch design.
 * Connects to the blind WebSocket relay to intercept traffic.
 * Wires up actual attack modules: Replay, Tamper, Downgrade, MITM.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useWebSocket } from '../hooks/useWebSocket.js';

// Attack helpers
import { buildReplayFrame } from '../attacks/replay.js';
import { buildTamperFrame } from '../attacks/tamper.js';
import { buildDowngradeFrame } from '../attacks/downgrade.js';
import { buildMitmFrameFresh } from '../attacks/mitm.js';


export default function EveView({ roomCode, role }) {
  const [intercepts, setIntercepts] = useState([]);
  const [selectedIntercept, setSelectedIntercept] = useState(null);
  
  // Real-time metrics
  const [capturedCount, setCapturedCount] = useState(0);
  const [attackCount, setAttackCount] = useState(0);
  const [successCount, setSuccessCount] = useState(0);

  const endRef = useRef(null);

  // Status mapping
  const statusColor = (type) => {
    if (type === 'ALERT' || type === 'ERROR') return 'text-primary'; // eve primary = red
    if (type === 'SUCCESS') return 'text-secondary'; // eve secondary = cyan
    if (type === 'INJECTED' || type === 'MODIFIED') return 'text-tertiary-container';
    return 'text-outline';
  };

  const handleMessage = useCallback((msg) => {
    const now = new Date();
    const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    // Eve only ever receives mirror frames for Alice↔Bob traffic.
    // Relay format: { type: "mirror", payload: { from, frame, ts } }
    if (msg.type === 'mirror') {
      const innerFrame = msg.payload?.frame ?? {};
      const from       = msg.payload?.from ?? '?';
      const frameType  = innerFrame.type ?? 'unknown';
      const isData     = frameType === 'data';

      setIntercepts(prev => [...prev, {
        id: Date.now() + Math.random(),
        ts,
        type:       isData ? 'INTERCEPT' : 'CONTROL',
        proto:      isData ? 'AES-256-GCM' : frameType.toUpperCase(),
        from,
        raw:        JSON.stringify(msg, null, 2),
        parsed:     msg.payload,   // { from, frame, ts }
        innerFrame,                // the actual frame to re-inject
      }]);
      if (isData) setCapturedCount(c => c + 1);
    } else {
      // joined / inject_ok / rejection / error
      setIntercepts(prev => [...prev, {
        id: Date.now() + Math.random(),
        ts,
        type:   'CONTROL',
        proto:  msg.type.toUpperCase(),
        raw:    JSON.stringify(msg, null, 2),
        parsed: msg,
      }]);
    }
  }, []);

  const { status, send } = useWebSocket(roomCode, role, { onMessage: handleMessage });

  // Eve MUST send { type: 'inject', payload: { target, frame } }.
  // Server _handle_eve() rejects anything else with "Eve may only send 'inject' messages".
  const injectTo = useCallback((target, frame) => {
    send({ type: 'inject', payload: { target, frame } });
  }, [send]);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [intercepts]);

  // ── Attack Handlers ───────────────────────────────────────────────────

  const logAttackResult = (attackName, result, error = null) => {
    const now = new Date();
    const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
    setAttackCount(c => c + 1);
    if (!error) setSuccessCount(c => c + 1);
    
    setIntercepts(prev => [...prev, {
      id: Date.now() + Math.random(),
      ts,
      type: error ? 'ERROR' : 'INJECTED',
      proto: attackName,
      raw: error ? error.message : result,
      isAttackLog: true
    }]);
  };

  // ── Replay: resend exact same frame to opposite peer ─────────────────
  const handleReplay = async () => {
    if (!selectedIntercept) return alert('Select an intercepted AES-256-GCM packet to replay.');
    if (selectedIntercept.proto !== 'AES-256-GCM') return alert('Replay attack requires an AES-256-GCM data packet.');
    try {
      const { innerFrame, from } = selectedIntercept;
      const target = from === 'alice' ? 'bob' : 'alice';
      logAttackResult('REPLAY_ATTACK', `Injecting replay seq=${innerFrame.payload?.seq} → ${target}...`);
      injectTo(target, buildReplayFrame(innerFrame));
      logAttackResult('REPLAY_ATTACK', `Done. Expect: "sequence number N already used".`);
    } catch (e) { logAttackResult('REPLAY_ATTACK', null, e); }
  };

  // ── Tamper: flip byte[0] of ciphertext, fresh seq ─────────────────────
  const handleTamper = async () => {
    if (!selectedIntercept) return alert('Select an intercepted AES-256-GCM packet to tamper.');
    if (selectedIntercept.proto !== 'AES-256-GCM') return alert('Tamper attack requires an AES-256-GCM data packet.');
    try {
      const { innerFrame, from } = selectedIntercept;
      const target = from === 'alice' ? 'bob' : 'alice';
      const freshSeq = Math.floor(Math.random() * 1000000) + 50000;
      logAttackResult('TAMPER_ATTACK', `Flipping ciphertext byte, seq=${freshSeq} → ${target}...`);
      injectTo(target, buildTamperFrame(innerFrame.payload, freshSeq));
      logAttackResult('TAMPER_ATTACK', `Done. Expect: "GCM auth tag mismatch".`);
    } catch (e) { logAttackResult('TAMPER_ATTACK', null, e); }
  };

  // ── Downgrade: strip PQC fields from ClientHello ──────────────────────
  const handleDowngrade = async () => {
    if (!selectedIntercept || selectedIntercept.innerFrame?.type !== 'client_hello') {
      return alert('Select an intercepted CLIENT_HELLO packet to attempt downgrade.');
    }
    try {
      const { innerFrame, from } = selectedIntercept;
      const target = from === 'alice' ? 'bob' : 'alice';
      logAttackResult('DOWNGRADE_ATTACK', `Stripping PQC fields → ${target}...`);
      injectTo(target, buildDowngradeFrame(innerFrame.payload));
      logAttackResult('DOWNGRADE_ATTACK', `Done. Expect: "malformed ClientHello: PQC fields missing".`);
    } catch (e) { logAttackResult('DOWNGRADE_ATTACK', null, e); }
  };

  // ── MITM: replace X25519 + KEM keys with Eve’s own ───────────────────
  const handleMitm = async () => {
    if (!selectedIntercept || selectedIntercept.innerFrame?.type !== 'client_hello') {
      return alert('Select an intercepted CLIENT_HELLO packet to attempt MITM key substitution.');
    }
    try {
      const { innerFrame, from } = selectedIntercept;
      const target = from === 'alice' ? 'bob' : 'alice';
      logAttackResult('MITM_ATTACK', `Generating Eve keypairs and substituting keys → ${target}...`);
      const { frame } = await buildMitmFrameFresh(innerFrame.payload);
      injectTo(target, frame);
      logAttackResult('MITM_ATTACK', `Done. Expect: "public key does not match session identity".`);
    } catch (e) { logAttackResult('MITM_ATTACK', null, e); }
  };


  return (
    <div className="eve-theme dark" style={{ background: 'var(--c-background)', minHeight: '100vh', color: 'var(--c-on-surface)' }}>
      {/* Background grit */}
      <div className="fixed inset-0 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(255,83,88,0.03) 0%, transparent 100%)' }} />
      <div className="fixed inset-0 pointer-events-none cyber-grid opacity-50" />
      
      {/* ── Fixed Header ── */}
      <header className="fixed top-0 w-full z-50 bg-surface-container-lowest/90 backdrop-blur-xl border-b border-error/20">
        <div className="h-14 w-full px-md flex items-center justify-between">
          {/* Left */}
          <div className="flex items-center gap-md">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[24px] drop-shadow-[0_0_12px_rgba(255,83,88,0.8)]">bug_report</span>
              <div className="flex flex-col">
                <span className="font-headline-xl-mobile text-on-surface tracking-tighter leading-none">RED-TEAM</span>
                <span className="font-label-caps text-primary tracking-widest mt-1">INTERCEPT CONSOLE</span>
              </div>
            </div>
            <div className="h-6 w-px bg-surface-container-highest ml-2" />
            <div className="flex items-center gap-xs px-sm py-1 rounded bg-error/10 border border-error/30">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />
              <span className="font-label-caps text-primary tracking-widest">ACTIVE INTERCEPT</span>
            </div>
          </div>
          
          {/* Right */}
          <div className="flex items-center gap-lg">
            <div className="flex items-center gap-4 font-mono text-[11px]">
              <div className="flex flex-col items-end">
                <span className="text-outline uppercase tracking-wider text-[9px]">Captured</span>
                <span className="text-secondary font-bold text-[13px]">{capturedCount.toString().padStart(4, '0')}</span>
              </div>
              <div className="flex flex-col items-end">
                <span className="text-outline uppercase tracking-wider text-[9px]">Attacks Executed</span>
                <span className="text-tertiary-container font-bold text-[13px]">{attackCount.toString().padStart(3, '0')}</span>
              </div>
              <div className="flex flex-col items-end">
                <span className="text-outline uppercase tracking-wider text-[9px]">Injections</span>
                <span className="text-primary font-bold text-[13px]">{successCount.toString().padStart(3, '0')}</span>
              </div>
            </div>
            <div className="w-8 h-8 rounded bg-primary text-on-primary flex items-center justify-center font-bold font-mono">
              EVE
            </div>
          </div>
        </div>
      </header>

      {/* ── Main Content ── */}
      <main className="relative pt-16 px-md pb-md h-screen flex flex-col gap-md">
        
        {/* Global connection status bar */}
        <div className="w-full rounded bg-surface-container/80 border border-outline-variant/30 px-sm py-1.5 flex justify-between items-center text-[10px] font-mono">
          <div className="flex items-center gap-3">
            <span className={`flex items-center gap-1.5 ${status === 'connected' ? 'text-secondary' : 'text-primary'}`}>
              <span className="material-symbols-outlined text-[14px]">wifi_tethering</span>
              <span>RELAY: {status.toUpperCase()}</span>
            </span>
            <span className="text-outline-variant">|</span>
            <span className="text-on-surface-variant flex items-center gap-1">
              TARGET ROOM: <strong className="text-primary tracking-wider">{roomCode}</strong>
            </span>
          </div>
          <span className="text-outline flex items-center gap-1">
            <span className="material-symbols-outlined text-[13px] text-tertiary-container">visibility</span>
            STEALTH MODE: ENGAGED
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-md flex-1 min-h-0">
          
          {/* ── Packet Sniffer Feed (Left) ── */}
          <section className="lg:col-span-7 flex flex-col rounded bg-surface-container-low/90 border border-outline-variant/20 overflow-hidden shadow-2xl">
            <div className="px-sm py-xs bg-surface-container border-b border-outline-variant/20 flex items-center justify-between">
              <h3 className="font-label-caps text-on-surface flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[14px] text-primary">radar</span>
                RAW TRAFFIC INTERCEPT
              </h3>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[9px] text-outline">AUTO-SCROLL</span>
                <div className="w-6 h-3 rounded-full bg-secondary/20 flex items-center p-0.5"><div className="w-2 h-2 rounded-full bg-secondary ml-auto" /></div>
              </div>
            </div>
            
            <div className="flex-1 overflow-y-auto p-2 font-mono text-[11px] leading-relaxed scrollbar-subtle scanline bg-surface-container-lowest/80 relative">
              {intercepts.length === 0 ? (
                <div className="absolute inset-0 flex items-center justify-center text-outline/50 flex-col gap-2">
                  <span className="material-symbols-outlined text-[32px] animate-pulse">leak_add</span>
                  <p>AWAITING PACKETS...</p>
                </div>
              ) : (
                <div className="flex flex-col gap-1">
                  {intercepts.map(pkt => {
                    const isSelected = selectedIntercept?.id === pkt.id;
                    return (
                      <div 
                        key={pkt.id}
                        onClick={() => setSelectedIntercept(pkt)}
                        className={`p-1.5 border-l-2 cursor-pointer transition-colors ${
                          isSelected ? 'border-primary bg-primary/10' : 
                          pkt.isAttackLog ? 'border-tertiary-container bg-tertiary-container/5' :
                          'border-outline-variant/30 hover:bg-surface-container/50'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-outline text-[10px] w-20">{pkt.ts}</span>
                          <span className={`font-bold ${statusColor(pkt.type)} w-20`}>{pkt.type}</span>
                          <span className={`${pkt.isAttackLog ? 'text-on-surface' : 'text-secondary'} truncate`}>{pkt.proto}</span>
                        </div>
                        {isSelected && (
                          <div className="mt-1 pl-2 border-l border-outline-variant/30">
                             <pre className="text-on-surface-variant text-[10px] overflow-x-auto p-2 bg-surface-container-lowest rounded shadow-inner whitespace-pre-wrap word-break">
                              {pkt.raw}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })}
                  <div ref={endRef} />
                </div>
              )}
            </div>
          </section>

          {/* ── Attack Arsenal (Right) ── */}
          <section className="lg:col-span-5 flex flex-col gap-md min-h-0">
            
            {/* Selected Packet Inspector */}
            <div className="flex-1 flex flex-col rounded bg-surface-container-low/90 border border-outline-variant/20 overflow-hidden shadow-2xl">
              <div className="px-sm py-xs bg-surface-container border-b border-outline-variant/20 flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[14px] text-tertiary-container">troubleshoot</span>
                <h3 className="font-label-caps text-on-surface">PAYLOAD INSPECTOR</h3>
              </div>
              <div className="p-sm flex-1 overflow-y-auto scrollbar-subtle font-mono text-[11px] bg-surface-container-lowest/50">
                {selectedIntercept && !selectedIntercept.isAttackLog ? (
                  <div className="flex flex-col gap-3">
                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                      <div className="bg-surface-container/50 p-1.5 rounded border border-outline-variant/10">
                        <span className="text-outline block mb-0.5">Protocol</span>
                        <span className="text-secondary font-bold">{selectedIntercept.proto}</span>
                      </div>
                      <div className="bg-surface-container/50 p-1.5 rounded border border-outline-variant/10">
                        <span className="text-outline block mb-0.5">Size</span>
                        <span className="text-on-surface font-bold">{selectedIntercept.raw.length} bytes</span>
                      </div>
                    </div>
                    
                    <div className="flex flex-col gap-1">
                      <span className="text-outline text-[10px] uppercase">Hex Dump (Excerpt)</span>
                      <div className="rounded bg-surface-container-lowest p-2 font-mono text-[10px] leading-loose shadow-inner border border-outline-variant/20 text-on-surface-variant select-all">
                        {/* Fake hex dump for visual effect based on raw data */}
                        0000  <span className="text-primary">{toHexAsciiFast(selectedIntercept.raw.slice(0, 8))}</span>  {toAsciiFast(selectedIntercept.raw.slice(0, 8))}<br/>
                        0008  <span className="text-primary-container">{toHexAsciiFast(selectedIntercept.raw.slice(8, 16))}</span>  {toAsciiFast(selectedIntercept.raw.slice(8, 16))}<br/>
                        0010  <span className="text-outline-variant">{toHexAsciiFast(selectedIntercept.raw.slice(16, 24))}</span>  {toAsciiFast(selectedIntercept.raw.slice(16, 24))}
                      </div>
                    </div>
                    
                    {selectedIntercept.proto === 'AES-256-GCM' && (
                      <div className="flex items-center gap-2 p-2 bg-error/10 border border-error/20 rounded text-error">
                         <span className="material-symbols-outlined text-[16px]">lock</span>
                         <span>Encrypted payload. Content opaque. TAG verification required by receiver.</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="h-full flex items-center justify-center text-outline/50">
                     Select a packet to inspect...
                  </div>
                )}
              </div>
            </div>

            {/* Attack Vectors */}
            <div className="flex-shrink-0 flex flex-col rounded bg-surface-container-low/90 border border-error/30 overflow-hidden shadow-[0_0_15px_rgba(255,83,88,0.1)]">
              <div className="px-sm py-xs bg-error/10 border-b border-error/20 flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[14px] text-primary">warning</span>
                <h3 className="font-label-caps text-primary">ATTACK VECTORS</h3>
              </div>
              <div className="p-sm grid grid-cols-2 gap-2">
                
                <button 
                  onClick={handleReplay}
                  className="flex flex-col items-start p-2 rounded bg-surface-container border border-outline-variant/30 hover:border-primary/50 hover:bg-surface-container-high transition-all group relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 p-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="material-symbols-outlined text-[12px] text-primary">play_arrow</span>
                  </div>
                  <span className="font-label-caps text-on-surface mb-1 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-sm bg-primary/80"></span>
                    Replay Attack
                  </span>
                  <span className="font-mono text-[9px] text-outline-variant text-left leading-tight">
                    Duplicate and re-inject AES payload to bypass state.
                  </span>
                </button>

                <button 
                  onClick={handleTamper}
                  className="flex flex-col items-start p-2 rounded bg-surface-container border border-outline-variant/30 hover:border-primary/50 hover:bg-surface-container-high transition-all group relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 p-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="material-symbols-outlined text-[12px] text-primary">play_arrow</span>
                  </div>
                  <span className="font-label-caps text-on-surface mb-1 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-sm bg-tertiary-container/80"></span>
                    Bit Tampering
                  </span>
                  <span className="font-mono text-[9px] text-outline-variant text-left leading-tight">
                    Flip bits in ciphertext to trigger GCM auth failures.
                  </span>
                </button>

                <button 
                  onClick={handleDowngrade}
                  className="flex flex-col items-start p-2 rounded bg-surface-container border border-outline-variant/30 hover:border-primary/50 hover:bg-surface-container-high transition-all group relative overflow-hidden"
                >
                   <div className="absolute top-0 right-0 p-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="material-symbols-outlined text-[12px] text-primary">play_arrow</span>
                  </div>
                  <span className="font-label-caps text-on-surface mb-1 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-sm bg-secondary/80"></span>
                    PQC Downgrade
                  </span>
                  <span className="font-mono text-[9px] text-outline-variant text-left leading-tight">
                    Strip ML-KEM from ClientHello to force classic X25519.
                  </span>
                </button>

                <button 
                  onClick={handleMitm}
                  className="flex flex-col items-start p-2 rounded bg-surface-container border border-outline-variant/30 hover:border-primary/50 hover:bg-surface-container-high transition-all group relative overflow-hidden"
                >
                   <div className="absolute top-0 right-0 p-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="material-symbols-outlined text-[12px] text-primary">play_arrow</span>
                  </div>
                  <span className="font-label-caps text-on-surface mb-1 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-sm bg-error/80"></span>
                    MITM / Strip Sig
                  </span>
                  <span className="font-mono text-[9px] text-outline-variant text-left leading-tight">
                    Intercept KemResponse, strip ML-DSA signature, re-inject.
                  </span>
                </button>

              </div>
            </div>

          </section>
        </div>
      </main>
    </div>
  );
}

// Helpers for fake hex dump rendering
function toHexAsciiFast(str) {
  if (!str) return '';
  let res = '';
  for(let i=0; i<Math.min(str.length, 8); i++) {
    res += str.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
  }
  return res.padEnd(24, ' ');
}
function toAsciiFast(str) {
  if (!str) return '';
  let res = '';
  for(let i=0; i<Math.min(str.length, 8); i++) {
    const code = str.charCodeAt(i);
    res += (code >= 32 && code <= 126) ? str.charAt(i) : '.';
  }
  return res;
}
