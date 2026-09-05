/** Eve's mirror feed — scrolling list of all captured frames, selectable */
export default function CapturedTraffic({ entries, selected, onSelect }) {
  if (entries.length === 0) {
    return (
      <div className="traffic-empty">
        Waiting for traffic...<br />
        <small>Alice and Bob must join the same room.</small>
      </div>
    );
  }

  return (
    <div className="traffic-scroll">
      {entries.map((entry, i) => (
        <div
          key={entry.id}
          className={`traffic-entry ${selected === i ? 'sel' : ''} type-${entry.frame.type}`}
          onClick={() => onSelect(i)}
        >
          <div className="te-meta">
            <span className={`te-from from-${entry.from}`}>{entry.from?.toUpperCase()}</span>
            <span className="te-arrow">→</span>
            <span className="te-type">{entry.frame.type}</span>
            <span className="te-ts">{new Date(entry.ts * 1000).toLocaleTimeString()}</span>
          </div>
          {entry.frame.type === 'data' && (
            <div className="te-preview">
              seq={entry.frame.payload.seq} · ct={entry.frame.payload.ciphertext?.slice(0, 16)}...
            </div>
          )}
          {entry.frame.type === 'client_hello' && (
            <div className="te-preview">
              x25519={entry.frame.payload.x25519_pk?.slice(0, 12)}... · role={entry.frame.payload.role}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
