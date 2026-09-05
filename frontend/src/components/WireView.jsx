import { useRef, useEffect } from 'react';

/** Scrolling log of raw wire frames with real hex values */
export default function WireView({ entries }) {
  const bottomRef = useRef(null);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [entries]);

  if (entries.length === 0) {
    return <div className="wire-empty">No frames yet.</div>;
  }

  return (
    <div className="wire-scroll">
      {entries.map(entry => (
        <WireEntry key={entry.id} entry={entry} />
      ))}
      <div ref={bottomRef} />
    </div>
  );
}

function WireEntry({ entry }) {
  const arrow = entry.direction === 'out' ? '↑' : '↓';
  const cls   = entry.isRejection
    ? 'wire-entry rejection'
    : entry.direction === 'out'
    ? 'wire-entry outbound'
    : 'wire-entry inbound';

  const typeLabel = {
    client_hello: 'ClientHello',
    kem_response: 'KemResponse',
    data:         'DataMessage',
    rejection:    'REJECTION',
    error:        'ERROR',
  }[entry.type] || entry.type;

  return (
    <div className={cls}>
      <div className="wire-meta">
        <span className="wire-arrow">{arrow}</span>
        <span className={`wire-type ${entry.type}`}>{typeLabel}</span>
        <span className="wire-ts">{new Date(entry.ts).toLocaleTimeString()}</span>
      </div>
      {entry.fields && (
        <div className="wire-fields">
          {Object.entries(entry.fields).map(([k, v]) => (
            <div key={k} className="wire-field">
              <span className="wire-key">{k}</span>
              <span className={`wire-val ${k === 'decrypted' || k === 'plaintext' ? 'plaintext' : 'hex'}`}>
                {String(v)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
