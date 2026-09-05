/**
 * EveView.jsx — "Adversary Red-Team Intercept Console"
 *
 * Eve receives a mirror of every Alice/Bob frame.
 * She can attempt four attacks via inject channel.
 * All rejections come from real client-side crypto at Alice/Bob — not simulated.
 */

import { useState, useCallback, useRef } from 'react';
import { useWebSocket } from '../hooks/useWebSocket.js';
import { makeEnvelope } from '../crypto/protocol.js';
import { buildReplayFrame } from '../attacks/replay.js';
import { buildTamperFrame } from '../attacks/tamper.js';
import { buildDowngradeFrame } from '../attacks/downgrade.js';
import { buildMitmFrameFresh } from '../attacks/mitm.js';
import CapturedTraffic from '../components/CapturedTraffic.jsx';
import AttackPanel from '../components/AttackPanel.jsx';
import Scoreboard from '../components/Scoreboard.jsx';
import { QRCodeSVG } from 'qrcode.react';

export default function EveView({ roomCode }) {
  const [captured,   setCaptured]  = useState([]);   // mirrored frames
  const [attackLog,  setAttackLog] = useState([]);   // {ts, type, target, reason}
  const [score, setScore] = useState({
    replay: [0, 0], tamper: [0, 0], downgrade: [0, 0], mitm: [0, 0],
  }); // [attempts, blocked]
  const [selected, setSelected] = useState(null);  // selected captured frame index
  const freshSeqRef = useRef(10000);  // counter for tamper fresh seqs

  const handleMessage = useCallback((msg) => {
    if (msg.type === 'mirror') {
      setCaptured(prev => [...prev, {
        id:    Date.now() + Math.random(),
        ts:    msg.payload.ts,
        from:  msg.payload.from,
        frame: msg.payload.frame,
      }]);
      return;
    }

    if (msg.type === 'rejection' || msg.type === 'inject_ok') {
      // Log all relay responses
      setAttackLog(prev => [
        {
          id:     Date.now() + Math.random(),
          ts:     new Date().toISOString(),
          result: msg.type,
          reason: msg.payload?.reason || '',
          target: msg.payload?.target || '',
        },
        ...prev,
      ]);
    }
  }, []);

  const { status: wsStatus, send } = useWebSocket(roomCode, 'eve', {
    onMessage: handleMessage,
  });

  // ── Inject helper ─────────────────────────────────────────────────────────
  const inject = useCallback((target, frame, attackType) => {
    send(makeEnvelope('inject', { target, frame }));
    setScore(prev => ({
      ...prev,
      [attackType]: [prev[attackType][0] + 1, prev[attackType][1]],
    }));
    setAttackLog(prev => [{
      id:     Date.now() + Math.random(),
      ts:     new Date().toISOString(),
      result: 'pending',
      type:   attackType,
      target,
      reason: '...',
    }, ...prev]);
  }, [send]);

  // Update score when rejection comes back
  const handleRejection = useCallback((attackType) => {
    setScore(prev => ({
      ...prev,
      [attackType]: [prev[attackType][0], prev[attackType][1] + 1],
    }));
  }, []);

  // ── Attack handlers ───────────────────────────────────────────────────────
  const doReplay = useCallback(() => {
    if (selected === null) return;
    const entry = captured[selected];
    if (entry.frame.type !== 'data') return alert('Select a data message for replay');
    const target = entry.from === 'alice' ? 'bob' : 'alice';
    inject(target, buildReplayFrame(entry.frame), 'replay');
  }, [selected, captured, inject]);

  const doTamper = useCallback(() => {
    if (selected === null) return;
    const entry = captured[selected];
    if (entry.frame.type !== 'data') return alert('Select a data message for tamper');
    const target = entry.from === 'alice' ? 'bob' : 'alice';
    const freshSeq = freshSeqRef.current++;
    inject(target, buildTamperFrame(entry.frame.payload, freshSeq), 'tamper');
  }, [selected, captured, inject]);

  const doDowngrade = useCallback(() => {
    if (selected === null) return;
    const entry = captured[selected];
    if (entry.frame.type !== 'client_hello') return alert('Select a client_hello for downgrade');
    const target = entry.from === 'alice' ? 'bob' : 'alice';
    inject(target, buildDowngradeFrame(entry.frame.payload), 'downgrade');
  }, [selected, captured, inject]);

  const doMitm = useCallback(async () => {
    if (selected === null) return;
    const entry = captured[selected];
    if (entry.frame.type !== 'client_hello') return alert('Select a client_hello for key substitution');
    const target = entry.from === 'alice' ? 'bob' : 'alice';
    const { frame } = await buildMitmFrameFresh(entry.frame.payload);
    inject(target, frame, 'mitm');
  }, [selected, captured, inject]);

  // ── Export attack log ─────────────────────────────────────────────────────
  const exportLog = () => {
    const blob = new Blob([JSON.stringify(attackLog, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `pqctunnel-attack-log-${roomCode}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const eveUrl = `${window.location.origin}?role=eve&room=${roomCode}`;

  return (
    <div className="eve-layout">
      {/* Header */}
      <header className="eve-header">
        <div className="eve-header-left">
          <span className="eve-title">🔴 EVE — INTERCEPT CONSOLE</span>
          <span className="room-code">Room: {roomCode}</span>
        </div>
        <div className="eve-header-right">
          <span className={`ws-pill ${wsStatus}`}>{wsStatus}</span>
          <button className="btn-export" onClick={exportLog}>
            ↓ Export Log
          </button>
        </div>
      </header>

      <div className="eve-body">
        {/* Left: Captured Traffic */}
        <div className="eve-panel eve-traffic">
          <div className="panel-header">
            <span className="panel-icon">📡</span>
            <span>Captured Traffic</span>
            <span className="panel-badge">{captured.length}</span>
          </div>
          <CapturedTraffic
            entries={captured}
            selected={selected}
            onSelect={setSelected}
          />
        </div>

        {/* Center: Attack Panel + Log */}
        <div className="eve-panel eve-attacks">
          <div className="panel-header">
            <span className="panel-icon">⚔</span>
            <span>Attack Controls</span>
          </div>
          <AttackPanel
            selected={selected !== null ? captured[selected] : null}
            onReplay={doReplay}
            onTamper={doTamper}
            onDowngrade={doDowngrade}
            onMitm={doMitm}
          />

          <div className="panel-header" style={{ marginTop: '1rem' }}>
            <span className="panel-icon">📋</span>
            <span>Results Log</span>
          </div>
          <div className="results-log">
            {attackLog.length === 0 && (
              <div className="log-empty">No attacks attempted yet.</div>
            )}
            {attackLog.map(entry => (
              <div
                key={entry.id}
                className={`log-entry ${entry.result === 'rejection' ? 'rejected' : entry.result === 'inject_ok' ? 'delivered' : 'pending'}`}
              >
                <span className="log-ts">{new Date(entry.ts).toLocaleTimeString()}</span>
                <span className="log-type">{entry.type?.toUpperCase() || entry.result?.toUpperCase()}</span>
                <span className="log-reason">{entry.reason || entry.result}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Scoreboard + QR */}
        <div className="eve-panel eve-sidebar">
          <div className="panel-header">
            <span className="panel-icon">📊</span>
            <span>Scoreboard</span>
          </div>
          <Scoreboard score={score} />

          <div className="panel-header" style={{ marginTop: '1.5rem' }}>
            <span className="panel-icon">📱</span>
            <span>Share Eve Console</span>
          </div>
          <div className="qr-block">
            <QRCodeSVG
              value={eveUrl}
              size={160}
              bgColor="#0f172a"
              fgColor="#f43f5e"
            />
            <div className="qr-label">Scan to join as Eve</div>
          </div>
        </div>
      </div>
    </div>
  );
}
