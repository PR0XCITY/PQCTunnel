/** Horizontal bar chart of handshake timing from real performance.now() calls */
export default function HandshakeTiming({ timing, role }) {
  if (!timing) {
    return (
      <div className="timing-empty">
        Timing will appear after handshake completes.
      </div>
    );
  }

  const phases = [
    { key: 'keygen_ms',  label: 'Key Generation',       color: '#6366f1' },
    { key: 'x25519_ms',  label: 'X25519 DH',            color: '#0ea5e9' },
    { key: 'kem_ms',     label: 'ML-KEM-768',           color: '#8b5cf6' },
    { key: 'hkdf_ms',    label: 'HKDF-SHA-256',         color: '#06b6d4' },
    ...(role === 'bob'
      ? [{ key: 'sign_ms',   label: 'ML-DSA-65 Sign',   color: '#f59e0b' }]
      : [{ key: 'verify_ms', label: 'ML-DSA-65 Verify', color: '#10b981' }]),
  ];

  const maxMs = Math.max(...phases.map(p => timing[p.key] || 0), 1);

  return (
    <div className="timing-wrap">
      <div className="timing-total">
        Total: <strong>{timing.total_ms?.toFixed(1)}ms</strong>
      </div>
      {phases.map(p => {
        const ms  = timing[p.key] || 0;
        const pct = (ms / maxMs) * 100;
        return (
          <div key={p.key} className="timing-row">
            <div className="timing-label">{p.label}</div>
            <div className="timing-bar-wrap">
              <div
                className="timing-bar"
                style={{ width: `${pct}%`, background: p.color }}
              />
            </div>
            <div className="timing-ms">{ms.toFixed(1)}ms</div>
          </div>
        );
      })}
      <div className="timing-note">Measured with performance.now() in-browser</div>
    </div>
  );
}
