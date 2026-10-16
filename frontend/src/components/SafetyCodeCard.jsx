/**
 * SafetyCodeCard.jsx
 * Shows the transcript-derived safety code and lets the user record whether it
 * matches the peer's screen. A mismatch means someone substituted keys.
 */

export default function SafetyCodeCard({ safetyCode, verification, onConfirm, phase, peer }) {
  const ready = !!safetyCode && (phase === 'secure' || phase === 'aborted');

  return (
    <div
      className={`rounded-xl p-md flex flex-col gap-2 transition-colors ${
        verification === 'match' ? 'bg-secondary/10 ring-1 ring-secondary/50'
          : verification === 'mismatch' ? 'bg-error/10 ring-1 ring-error/60'
          : 'bg-surface-container-lowest/70 ring-1 ring-outline-variant/40'
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="font-label-sm text-label-sm uppercase tracking-wider text-outline">Safety code</span>
        <span className={`font-mono text-[10px] font-semibold ${
          verification === 'match' ? 'text-secondary' : verification === 'mismatch' ? 'text-error' : 'text-tertiary-container'
        }`}>
          {verification === 'match' ? 'VERIFIED' : verification === 'mismatch' ? 'MITM DETECTED' : ready ? 'UNVERIFIED' : '—'}
        </span>
      </div>

      {ready ? (
        <>
          <div className="flex justify-between text-[22px] leading-none select-all" aria-label="safety code emoji">
            {safetyCode.emoji.map((e, i) => <span key={i}>{e}</span>)}
          </div>
          <div className="text-center font-mono text-[13px] tracking-wider text-on-surface select-all">
            {safetyCode.digits}
          </div>
          {verification === 'unverified' && phase === 'secure' && (
            <>
              <p className="font-general text-[11px] leading-snug text-on-surface-variant">
                Compare with {peer.toUpperCase()}'s screen. Matching codes prove no one swapped keys in between.
              </p>
              <div className="grid grid-cols-2 gap-1.5">
                <button
                  onClick={() => onConfirm(true)}
                  className="rounded-lg bg-secondary/15 px-2 py-1.5 font-label-md text-label-md text-secondary hover:bg-secondary/25"
                >
                  ✓ Matches
                </button>
                <button
                  onClick={() => onConfirm(false)}
                  className="rounded-lg bg-error/15 px-2 py-1.5 font-label-md text-label-md text-error hover:bg-error/25"
                >
                  ✕ Different
                </button>
              </div>
            </>
          )}
        </>
      ) : (
        <p className="font-general text-[11px] text-outline">Appears once the handshake completes.</p>
      )}
    </div>
  );
}
