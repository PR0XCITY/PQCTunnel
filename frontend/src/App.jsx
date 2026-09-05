import { useState } from 'react';
import AliceBobView from './views/AliceBobView.jsx';
import EveView from './views/EveView.jsx';

export default function App() {
  const params = new URLSearchParams(window.location.search);
  const [role]     = useState(params.get('role') || '');
  const [roomCode] = useState((params.get('room') || '').toUpperCase() || '');

  // Landing / room join screen
  if (!role || !roomCode) {
    return <LandingPage />;
  }

  if (role === 'eve') {
    return <EveView roomCode={roomCode} />;
  }

  if (role === 'alice' || role === 'bob') {
    return <AliceBobView roomCode={roomCode} role={role} />;
  }

  return (
    <div className="error-page">
      <p>Invalid role: <strong>{role}</strong>. Use ?role=alice, ?role=bob, or ?role=eve</p>
    </div>
  );
}

function LandingPage() {
  const [room, setRoom]   = useState('');
  const [role, setRole]   = useState('alice');

  const join = () => {
    if (!room.trim()) return;
    window.location.href = `?role=${role}&room=${room.trim().toUpperCase()}`;
  };

  return (
    <div className="landing">
      <div className="landing-card">
        <div className="landing-logo">
          <span className="logo-pq">PQC</span>
          <span className="logo-tunnel">Tunnel</span>
        </div>
        <p className="landing-sub">
          Hybrid post-quantum secure channel.<br />
          ML-KEM-768 + X25519. All crypto runs in your browser.
        </p>

        <div className="form-group">
          <label>Room Code</label>
          <input
            className="input"
            placeholder="e.g. DEMO01"
            value={room}
            onChange={e => setRoom(e.target.value.toUpperCase())}
            onKeyDown={e => e.key === 'Enter' && join()}
            maxLength={10}
          />
        </div>

        <div className="form-group">
          <label>Your Role</label>
          <div className="role-picker">
            {['alice', 'bob', 'eve'].map(r => (
              <button
                key={r}
                className={`role-btn ${role === r ? 'active' : ''} role-${r}`}
                onClick={() => setRole(r)}
              >
                {r === 'alice' ? '🔵 Alice' : r === 'bob' ? '🟢 Bob' : '🔴 Eve'}
              </button>
            ))}
          </div>
        </div>

        <button className="btn-join" onClick={join}>
          {role === 'eve' ? 'Enter Intercept Console' : 'Open Secure Channel'}
        </button>

        <div className="landing-links">
          <a href="https://github.com/PR0XCITY/PQCTunnel" target="_blank" rel="noreferrer">GitHub</a>
          <span>·</span>
          <a href="https://pqctunnel.onrender.com/health" target="_blank" rel="noreferrer">Relay Health</a>
        </div>
      </div>
    </div>
  );
}
