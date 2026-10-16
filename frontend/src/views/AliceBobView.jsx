/**
 * AliceBobView.jsx
 * "Quantum Console" for Alice (initiator) and Bob (responder).
 *
 * Everything shown is real: the handshake steps, timings, keys, safety code,
 * and the byte-level encrypt/decrypt trace of every message all come from the
 * client-side crypto in src/crypto/. Protocol logic lives in usePeerSession.
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import { usePeerSession } from '../hooks/usePeerSession.js';
import { b64ToBytes } from '../crypto/protocol.js';
import TracePanel from '../components/TracePanel.jsx';
import HexDump from '../components/HexDump.jsx';
import SafetyCodeCard from '../components/SafetyCodeCard.jsx';

const WIRE_FILTERS = {
  all:       () => true,
  handshake: e => ['client_hello', 'kem_response', 'client_finished'].includes(e.type),
  data:      e => e.type === 'data',
  errors:    e => e.dir === 'err' || e.dir === 'relay' || e.dir === 'alert',
};

const PHASE_LABEL = {
  waiting: 'WAITING', handshaking: 'HANDSHAKING', secure: 'ESTABLISHED',
  error: 'HANDSHAKE FAILED', aborted: 'ABORTED',
};

export default function AliceBobView({ roomCode, role }) {
  const s = usePeerSession(roomCode, role);
  const { peer, isInitiator, phase, messages, wireLog, handshake } = s;

  const [inputText, setInputText]     = useState('');
  const [revealSecrets, setReveal]    = useState(false);
  const [tab, setTab]                 = useState('handshake');
  const [selectedMsgId, setSelected]  = useState(null);
  const [autoInspect, setAutoInspect] = useState(true);
  const [wireFilter, setWireFilter]   = useState('all');
  const [selectedWire, setSelectedWire] = useState(null);
  const [sessionSecs, setSessionSecs] = useState(0);

  const messagesEndRef = useRef(null);
  const wireEndRef     = useRef(null);
  const isSecure = phase === 'secure';

  // Session timer — real seconds since the channel was established
  useEffect(() => {
    if (!isSecure) { setSessionSecs(0); return; }
    const t = setInterval(() => setSessionSecs(x => x + 1), 1000);
    return () => clearInterval(t);
  }, [isSecure]);

  // Auto-inspect the newest message so every send/receive shows its pipeline
  const lastMsg = messages[messages.length - 1];
  useEffect(() => {
    if (lastMsg && autoInspect) { setSelected(lastMsg.id); setTab('message'); }
  }, [lastMsg?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (phase === 'handshaking' || phase === 'error') setTab('handshake');
  }, [phase]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [messages.length]);
  useEffect(() => { wireEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [wireLog.length, tab]);

  const selectedMsg = messages.find(m => m.id === selectedMsgId) ?? null;
  const filteredWire = useMemo(() => wireLog.filter(WIRE_FILTERS[wireFilter]), [wireLog, wireFilter]);
  const lastPacket = wireLog[wireLog.length - 1];

  const send = async () => {
    const text = inputText.trim();
    if (!text || !isSecure) return;
    setInputText('');
    await s.sendMessage(text);
  };

  const fmtTimer = (x) => [Math.floor(x / 3600), Math.floor((x % 3600) / 60), x % 60]
    .map(n => String(n).padStart(2, '0')).join(':');

  const roleLabel = isInitiator ? 'ALICE [INITIATOR]' : 'BOB [RESPONDER]';
  const peerLabel = isInitiator ? 'BOB [RESPONDER]' : 'ALICE [INITIATOR]';
  const t = handshake?.timing;

  return (
    <div className="quantum-theme dark" style={{ background: 'var(--c-background)', minHeight: '100vh', color: 'var(--c-on-surface)' }}>
      {/* ── Header ── */}
      <header className="fixed top-0 w-full z-50 bg-surface-container-lowest/90 backdrop-blur-xl shadow-[0_1px_12px_rgba(0,0,0,0.6)]">
        <div className="h-14 w-full px-md flex items-center justify-between gap-sm">
          <div className="flex items-center gap-md shrink-0">
            <div className="flex items-center gap-xs">
              <span className="material-symbols-outlined text-primary-container text-[20px] drop-shadow-[0_0_8px_rgba(34,229,255,0.6)]">hub</span>
              <div className="flex flex-col">
                <span className="font-headline-sm text-headline-sm text-on-surface tracking-wider font-bold">PQCTUNNEL</span>
                <span className="font-label-sm text-label-sm text-primary tracking-widest">QUANTUM CONSOLE</span>
              </div>
            </div>
            <div className="h-6 w-px bg-surface-container-highest" />
            <div className="inline-flex items-center gap-xs px-sm py-0.5 rounded-full bg-surface-container-low text-primary border border-outline-variant/30">
              <span className={`w-1.5 h-1.5 rounded-full ${isInitiator ? 'bg-primary-container' : 'bg-secondary'}`} />
              <span className="font-label-sm text-label-sm tracking-wider uppercase">{roleLabel}</span>
            </div>
            <span className="hidden xl:inline font-mono-soc text-code-sm text-outline">ROOM <span className="text-primary">{roomCode}</span></span>
          </div>

          <div className="hidden lg:flex items-center gap-xs">
            <div className="flex items-center gap-1.5 px-sm py-0.5 rounded bg-surface-container-low">
              <span className={`w-2 h-2 rounded-full ${isSecure ? 'bg-secondary' : phase === 'error' || phase === 'aborted' ? 'bg-error' : 'bg-outline animate-pulse'}`} />
              <span className={`font-label-sm text-label-sm tracking-wide ${isSecure ? 'text-secondary' : phase === 'error' || phase === 'aborted' ? 'text-error' : 'text-outline'}`}>
                {PHASE_LABEL[phase]}
              </span>
            </div>
            {isSecure && (
              <div className="flex items-center gap-xs px-sm py-0.5 rounded bg-surface-container font-mono text-[12px]">
                <span className="material-symbols-outlined text-on-surface-variant text-[14px]">timer</span>
                {fmtTimer(sessionSecs)}
              </div>
            )}
            <div className="flex items-center gap-1 bg-surface-container-low px-xs py-0.5 rounded">
              {['X25519', 'ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM'].map(label => (
                <div key={label} className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-container font-code-sm text-code-sm">
                  <span className={`w-1.5 h-1.5 rounded-full ${isSecure ? 'bg-secondary' : 'bg-outline'}`} />
                  <span className={isSecure ? 'text-on-surface-variant' : 'text-outline'}>{label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-xs shrink-0">
            {s.eveOnline && (
              <span className="hidden md:inline-flex items-center gap-1 px-sm py-0.5 rounded bg-error/15 text-error font-label-sm text-label-sm" title="Eve is connected to the relay and can see every frame (but not the plaintext)">
                <span className="material-symbols-outlined text-[14px]">visibility</span>EVE ON RELAY
              </span>
            )}
            <button
              onClick={() => setReveal(v => !v)}
              className={`flex items-center gap-1 px-sm py-1 rounded font-label-md text-label-md transition-colors ${revealSecrets ? 'bg-tertiary-container/20 text-tertiary-container' : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'}`}
              title="Show shared secrets and session keys (demo only)"
            >
              <span className="material-symbols-outlined text-[16px]">{revealSecrets ? 'visibility' : 'visibility_off'}</span>
              <span className="hidden sm:inline">{revealSecrets ? 'Hide secrets' : 'Reveal secrets'}</span>
            </button>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold ${isInitiator ? 'bg-primary text-on-primary' : 'bg-secondary text-on-secondary'}`}>
              {role[0].toUpperCase()}
            </div>
          </div>
        </div>
      </header>

      {/* ── Sidebar: safety code, keys, timings ── */}
      <aside className="hidden lg:flex fixed left-0 top-14 h-[calc(100vh-3.5rem)] w-72 bg-surface-container-low/80 backdrop-blur-xl z-40 flex-col gap-md p-md overflow-y-auto scrollbar-subtle shadow-[1px_0_12px_rgba(0,0,0,0.5)]">
        <SafetyCodeCard safetyCode={handshake?.safetyCode} verification={s.verification}
          onConfirm={s.confirmSafetyCode} phase={phase} peer={peer} />
        <KeysCard keys={handshake?.keys} reveal={revealSecrets} role={role} peer={peer} />
        {t && <TimingCard t={t} isInitiator={isInitiator} />}
        {isInitiator && (phase === 'secure' || phase === 'error' || phase === 'aborted') && s.peerOnline && (
          <button onClick={s.restartHandshake}
            className="rounded-lg bg-primary-container/15 px-sm py-2 font-label-md text-label-md text-primary-container hover:bg-primary-container/25 flex items-center justify-center gap-1">
            <span className="material-symbols-outlined text-[16px]">autorenew</span>
            New handshake (fresh keys)
          </button>
        )}
      </aside>

      {/* ── Main ── */}
      <div className="lg:pl-72">
        <main className="relative pt-14 w-full min-h-screen cyber-grid">
          <div className="relative w-full p-md lg:p-lg flex flex-col gap-md">

            {/* Tunnel strip: you ⇄ blind relay ⇄ peer, with a packet per frame */}
            <TunnelStrip role={role} peer={peer} peerOnline={s.peerOnline} eveOnline={s.eveOnline}
              phase={phase} lastPacket={lastPacket} />

            {/* Status banner */}
            <div className={`rounded-xl px-md py-2 flex items-center gap-2 font-mono-soc text-code-md ${
              isSecure ? 'bg-secondary/10 text-secondary' : phase === 'error' || phase === 'aborted' ? 'bg-error/10 text-error' : 'bg-surface-container-low text-on-surface-variant'
            }`}>
              <span className={`material-symbols-outlined text-[18px] ${phase === 'handshaking' ? 'animate-spin' : ''}`}>
                {isSecure ? 'verified_user' : phase === 'error' || phase === 'aborted' ? 'gpp_bad' : phase === 'handshaking' ? 'progress_activity' : 'hourglass_empty'}
              </span>
              <span className="truncate">{s.statusMsg}</span>
            </div>

            {/* Mobile: safety code above chat */}
            <div className="lg:hidden">
              <SafetyCodeCard safetyCode={handshake?.safetyCode} verification={s.verification}
                onConfirm={s.confirmSafetyCode} phase={phase} peer={peer} />
            </div>

            <div className="grid gap-md items-start grid-cols-1 xl:grid-cols-12">
              {/* ── Chat ── */}
              <section className="xl:col-span-7 flex flex-col rounded-xl bg-surface-container-low/75 backdrop-blur-xl glow-cyan-subtle overflow-hidden">
                <div className="px-md py-sm bg-surface-container/60 flex items-center justify-between gap-sm">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${s.peerOnline ? 'bg-secondary' : 'bg-outline'}`} />
                    <h2 className="font-clash text-headline-sm text-on-surface">SECURE CHANNEL // {peerLabel}</h2>
                  </div>
                  <label className="flex items-center gap-1.5 font-mono-soc text-code-sm text-outline cursor-pointer select-none">
                    <input type="checkbox" checked={autoInspect} onChange={e => setAutoInspect(e.target.checked)} className="accent-[var(--c-primary-container)]" />
                    Auto-inspect
                  </label>
                </div>

                <div className="flex flex-col gap-md p-md sm:p-lg overflow-y-auto h-[52vh] min-h-[320px] scrollbar-subtle">
                  {messages.length === 0 && (
                    <div className="m-auto text-center text-outline font-mono-soc text-code-md max-w-xs">
                      {isSecure
                        ? 'Channel is ready. Every message is encrypted here before it leaves this browser — click any message to see how.'
                        : phase === 'handshaking' ? 'Performing hybrid post-quantum handshake...'
                        : `Waiting for ${peer.toUpperCase()}...`}
                    </div>
                  )}
                  {messages.map(m => (
                    <ChatBubble key={m.id} m={m} mine={m.from === role} selected={m.id === selectedMsgId}
                      onClick={() => { setSelected(m.id); setTab('message'); }} />
                  ))}
                  <div ref={messagesEndRef} />
                </div>

                <div className="p-md bg-surface-container/80 flex flex-col gap-1.5">
                  <div className="flex items-center gap-2 rounded-xl bg-surface-container-lowest/90 p-1.5 focus-within:glow-cyan-active transition-all">
                    <input
                      className="w-full bg-transparent px-sm text-on-surface font-general text-body-lg placeholder:text-outline focus:outline-none"
                      placeholder={isSecure ? 'Type a message — it is encrypted with AES-256-GCM before sending' : 'Waiting for secure channel...'}
                      disabled={!isSecure}
                      value={inputText}
                      onChange={e => setInputText(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && send()}
                    />
                    <button
                      className="flex items-center gap-1.5 px-md py-2 rounded bg-primary-container hover:bg-primary text-on-primary-container font-clash text-headline-sm transition-all active:scale-95 shrink-0 disabled:opacity-30 disabled:cursor-not-allowed"
                      disabled={!isSecure || !inputText.trim()}
                      onClick={send}
                    >
                      <span className="material-symbols-outlined text-[16px]">lock</span>
                      <span className="hidden sm:inline">Encrypt &amp; send</span>
                    </button>
                  </div>
                  <div className="px-1 text-[10px] font-mono-soc text-outline">
                    The relay only ever sees base64 ciphertext. Open Eve's console in another window to watch it.
                  </div>
                </div>
              </section>

              {/* ── Inspector ── */}
              <aside className="xl:col-span-5 flex flex-col rounded-xl bg-surface-container-low/85 backdrop-blur-xl glow-cyan-subtle overflow-hidden">
                <div className="flex items-center gap-1 p-1.5 bg-surface-container/70">
                  {[
                    ['handshake', 'key', 'Handshake'],
                    ['message', 'lock_open', 'Message'],
                    ['wire', 'terminal', `Wire (${wireLog.length})`],
                  ].map(([id, icon, label]) => (
                    <button key={id} onClick={() => setTab(id)}
                      className={`flex-1 flex items-center justify-center gap-1 px-sm py-1.5 rounded-lg font-label-md text-label-md transition-colors ${
                        tab === id ? 'bg-primary-container/20 text-primary-container' : 'text-outline hover:bg-surface-container-high hover:text-on-surface'
                      }`}>
                      <span className="material-symbols-outlined text-[16px]">{icon}</span>{label}
                    </button>
                  ))}
                </div>

                <div className="p-md h-[calc(52vh+92px)] min-h-[412px] overflow-y-auto scrollbar-subtle">
                  {tab === 'handshake' && (
                    <HandshakeTab handshake={handshake} reveal={revealSecrets} isInitiator={isInitiator} phase={phase} />
                  )}
                  {tab === 'message' && (
                    <MessageTab m={selectedMsg} mine={selectedMsg?.from === role} reveal={revealSecrets} />
                  )}
                  {tab === 'wire' && (
                    <WireTab entries={filteredWire} filter={wireFilter} setFilter={setWireFilter}
                      selected={selectedWire} setSelected={setSelectedWire} endRef={wireEndRef} />
                  )}
                </div>
              </aside>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

// ── Pieces ─────────────────────────────────────────────────────────────────

function TunnelStrip({ role, peer, peerOnline, eveOnline, phase, lastPacket }) {
  const out = lastPacket?.dir === 'out';
  const bad = lastPacket?.dir === 'err';
  const showPacket = lastPacket && ['out', 'in', 'err'].includes(lastPacket.dir);
  const Node = ({ name, on, me }) => (
    <div className="flex flex-col items-center gap-1 w-16 shrink-0">
      <div className={`w-9 h-9 rounded-full flex items-center justify-center font-bold text-[13px] ${
        on ? (name === 'alice' ? 'bg-primary text-on-primary' : 'bg-secondary text-on-secondary') : 'bg-surface-container-highest text-outline'
      }`}>{name[0].toUpperCase()}</div>
      <span className="font-mono-soc text-[10px] text-outline">{me ? 'YOU' : name.toUpperCase()}</span>
    </div>
  );
  return (
    <div className="rounded-xl bg-surface-container-low/70 px-md py-sm flex items-center gap-sm">
      <Node name={role} on me />
      <div className="relative flex-1 h-8 flex items-center">
        <div className={`absolute inset-x-0 top-1/2 h-0.5 -translate-y-1/2 ${phase === 'secure' ? 'bg-secondary/50' : 'bg-outline-variant'}`} />
        <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 px-sm py-0.5 rounded bg-surface-container-highest font-mono-soc text-[10px] text-on-surface-variant flex items-center gap-1 z-10">
          <span className="material-symbols-outlined text-[13px]">router</span>
          BLIND RELAY
          {eveOnline && <span className="text-error flex items-center gap-0.5"><span className="material-symbols-outlined text-[13px]">visibility</span>EVE</span>}
        </div>
        {showPacket && (
          <span key={lastPacket.id}
            className={`absolute top-1/2 -translate-y-1/2 h-2.5 w-2.5 rounded-full ${out ? 'packet-fly' : 'packet-fly-rev'} ${
              bad ? 'bg-error shadow-[0_0_10px_rgba(255,180,171,0.9)]' : 'bg-primary-container shadow-[0_0_10px_rgba(34,229,255,0.9)]'
            }`} />
        )}
      </div>
      <Node name={peer} on={peerOnline} />
    </div>
  );
}

function ChatBubble({ m, mine, selected, onClick }) {
  if (m.blocked) {
    return (
      <button onClick={onClick} className={`self-start max-w-[88%] text-left rounded-xl p-md bg-error/10 ring-1 ${selected ? 'ring-error' : 'ring-error/30'} hover:bg-error/15`}>
        <div className="flex items-center gap-1.5 font-mono-soc text-code-sm text-error font-semibold">
          <span className="material-symbols-outlined text-[16px]">block</span>
          BLOCKED INCOMING FRAME · {m.ts}
        </div>
        <div className="mt-1 font-mono text-[12px] text-on-surface">{m.reason}</div>
        <div className="mt-1 font-mono-soc text-[10px] text-outline">Click to see where verification failed</div>
      </button>
    );
  }
  return (
    <button onClick={onClick}
      className={`flex flex-col gap-1 max-w-[88%] text-left ${mine ? 'self-end items-end' : 'self-start'}`}>
      <div className="flex items-center gap-2 font-mono-soc text-code-sm px-1">
        <span className={mine ? 'text-primary-container' : 'text-on-surface font-semibold'}>{mine ? 'YOU' : m.from.toUpperCase()}</span>
        <span className="text-outline">{m.ts}</span>
        <span className="text-outline">seq {m.seq}</span>
      </div>
      <div className={`rounded-xl ${mine ? 'rounded-tr-sm bg-primary-container/10' : 'rounded-tl-sm bg-surface-container/90'} px-md py-sm ring-1 transition-all ${
        selected ? 'ring-primary-container' : 'ring-transparent hover:ring-outline-variant'
      }`}>
        <p className="font-general text-body-lg text-on-surface leading-relaxed whitespace-pre-wrap break-words">{m.text}</p>
        <div className="mt-1 flex items-center gap-1 font-mono-soc text-[10px] text-secondary">
          <span className="material-symbols-outlined text-[13px]">lock</span>
          {mine ? 'AES-256-GCM encrypted' : 'GCM tag verified · replay-checked'}
          <span className="text-outline ml-2">inspect →</span>
        </div>
      </div>
    </button>
  );
}

function HandshakeTab({ handshake, reveal, isInitiator, phase }) {
  if (!handshake) {
    return (
      <div className="text-outline font-mono-soc text-code-md flex flex-col gap-2">
        <p>No handshake yet.</p>
        <p className="text-[11px] leading-relaxed">
          {isInitiator
            ? 'When Bob joins, you generate fresh X25519, ML-KEM-768 and ML-DSA-65 keys and send a ClientHello.'
            : 'When Alice sends her ClientHello you encapsulate a secret to her ML-KEM key and sign the transcript.'}
        </p>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-sm">
      <div className="flex items-center justify-between">
        <h3 className="font-clash text-headline-sm text-on-surface">
          {isInitiator ? 'Initiator' : 'Responder'} handshake · {handshake.steps.filter(x => !x.wire).length} steps
        </h3>
        {phase === 'secure' && <span className="font-mono text-[11px] text-secondary">{handshake.timing.total_ms.toFixed(1)} ms</span>}
      </div>
      <p className="font-general text-[11px] text-on-surface-variant leading-snug">
        Hybrid: the session key needs <em>both</em> the X25519 secret and the ML-KEM secret, so it stays safe unless both are broken.
      </p>
      <TracePanel steps={handshake.steps} revealSecrets={reveal} animateKey={handshake.steps.length} stepDelay={60} />
    </div>
  );
}

function MessageTab({ m, mine, reveal }) {
  if (!m) {
    return <p className="text-outline font-mono-soc text-code-md">Send or click a message to see its encryption pipeline step by step.</p>;
  }
  const ct = m.payload ? b64ToBytes(m.payload.ciphertext) : null;
  return (
    <div className="flex flex-col gap-sm">
      <div className="flex items-center justify-between gap-2">
        <h3 className={`font-clash text-headline-sm ${m.blocked ? 'text-error' : 'text-on-surface'}`}>
          {m.blocked ? 'Rejected frame' : mine ? 'Encryption pipeline' : 'Decryption pipeline'}
        </h3>
        {!m.blocked && <span className="font-mono text-[11px] text-outline">seq {m.seq}</span>}
      </div>
      <TracePanel steps={m.trace} revealSecrets={reveal} animateKey={m.id} stepDelay={140} />
      {ct && ct.length > 0 && (
        <div className="rounded-lg bg-surface-container-lowest p-sm">
          <div className="mb-1 font-label-sm text-label-sm uppercase tracking-wider text-outline">Ciphertext hex dump</div>
          <HexDump bytes={ct} rows={6} />
        </div>
      )}
    </div>
  );
}

function WireTab({ entries, filter, setFilter, selected, setSelected, endRef }) {
  const frameBytes = selected?.frame ? new TextEncoder().encode(JSON.stringify(selected.frame)) : null;
  return (
    <div className="flex flex-col gap-sm">
      <div className="flex items-center gap-1 font-mono-soc text-[10px]">
        {Object.keys(WIRE_FILTERS).map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-1.5 py-0.5 rounded uppercase ${filter === f ? 'bg-primary-container/20 text-primary-container font-semibold' : 'text-outline hover:bg-surface-container hover:text-on-surface'}`}>
            {f}
          </button>
        ))}
      </div>
      <div className="flex flex-col gap-1 rounded-lg bg-surface-container-lowest/90 p-sm max-h-[38vh] overflow-y-auto scrollbar-subtle scanline font-mono text-[11px]">
        {entries.length === 0 && <div className="text-outline">No frames yet.</div>}
        {entries.map(e => {
          const color = e.dir === 'out' ? 'text-primary-container' : e.dir === 'in' ? 'text-secondary' : 'text-error';
          const tag = { out: 'TX', in: 'RX', err: 'BLOCK', relay: 'RELAY', alert: 'ALERT' }[e.dir];
          return (
            <button key={e.id} onClick={() => setSelected(e)}
              className={`text-left rounded px-1 ${selected?.id === e.id ? 'bg-primary-container/10' : 'hover:bg-surface-container'}`}>
              <span className="text-outline">[{e.ts}]</span>{' '}
              <span className={`font-semibold ${color}`}>{tag}</span>{' '}
              <span className="text-on-surface-variant">{e.type}</span>
              {e.bytes != null && <span className="text-outline"> · {e.bytes} B</span>}
              {Object.entries(e.fields || {}).map(([k, v]) => (
                <span key={k} className="block pl-4 text-[10px] break-all">
                  <span className="text-outline-variant">{k}:</span>{' '}
                  <span className={k === 'DECRYPTED' || k === 'PLAINTEXT' ? 'text-tertiary-container' : e.dir === 'err' ? 'text-error' : 'text-primary'}>{v}</span>
                </span>
              ))}
            </button>
          );
        })}
        <div ref={endRef} />
      </div>
      <div className="rounded-lg bg-surface-container-lowest p-sm">
        <div className="mb-1 font-label-sm text-label-sm uppercase tracking-wider text-outline">
          {frameBytes ? `Raw frame bytes (${frameBytes.length} B, as sent over WebSocket)` : 'Click a frame to dump its raw bytes'}
        </div>
        {frameBytes && <HexDump bytes={frameBytes} rows={8} />}
      </div>
    </div>
  );
}

function KeysCard({ keys, reveal, role, peer }) {
  return (
    <div className="rounded-xl bg-surface-container-lowest/70 ring-1 ring-outline-variant/40 p-md flex flex-col gap-2">
      <span className="font-label-sm text-label-sm uppercase tracking-wider text-outline">Session keys (AES-256)</span>
      {keys ? (
        <>
          {[
            [`${role} → ${peer}`, 'Encrypts what you send', keys.sendFp, keys.send],
            [`${peer} → ${role}`, 'Decrypts what you receive', keys.recvFp, keys.recv],
          ].map(([dir, help, fp, full]) => (
            <div key={dir} className="flex flex-col gap-0.5">
              <div className="flex items-center justify-between font-mono-soc text-[11px]">
                <span className="text-on-surface uppercase">{dir}</span>
                <span className="text-primary">{fp}</span>
              </div>
              <span className="font-general text-[10px] text-outline">{help}</span>
              {reveal && <code className="font-mono text-[10px] text-tertiary-container break-all">{full}</code>}
            </div>
          ))}
          <p className="font-general text-[10px] leading-snug text-on-surface-variant">
            Never transmitted. Both sides derive them independently — your send key equals {peer}'s receive key.
          </p>
        </>
      ) : (
        <p className="font-general text-[11px] text-outline">Derived at the end of the handshake.</p>
      )}
    </div>
  );
}

function TimingCard({ t, isInitiator }) {
  const rows = [
    ['KeyGen', t.keygen_ms, 'bg-indigo-400'],
    ['X25519', t.x25519_ms, 'bg-cyan-400'],
    [isInitiator ? 'ML-KEM decaps' : 'ML-KEM encaps', t.kem_ms, 'bg-violet-400'],
    ['HKDF', t.hkdf_ms, 'bg-teal-400'],
    ['ML-DSA sign', t.sign_ms, 'bg-amber-400'],
    ['ML-DSA verify', t.verify_ms, 'bg-rose-400'],
  ];
  const max = Math.max(...rows.map(r => r[1]), 0.001);
  return (
    <div className="rounded-xl bg-surface-container-lowest/70 ring-1 ring-outline-variant/40 p-md flex flex-col gap-1.5">
      <span className="font-label-sm text-label-sm uppercase tracking-wider text-outline">Handshake timing (this browser)</span>
      {rows.map(([label, ms, color]) => (
        <div key={label} className="flex items-center gap-2 text-[10px] font-mono">
          <span className="text-outline w-20 shrink-0">{label}</span>
          <div className="flex-1 h-1.5 bg-surface-container rounded-full overflow-hidden">
            <div className={`h-full ${color}`} style={{ width: `${(ms / max) * 100}%` }} />
          </div>
          <span className="text-primary-container w-14 text-right">{ms.toFixed(2)}ms</span>
        </div>
      ))}
      {t.total_ms > 0 && <div className="text-right font-mono text-[11px] text-secondary">Total {t.total_ms.toFixed(1)} ms</div>}
    </div>
  );
}
