/**
 * TracePanel.jsx
 * Renders a crypto trace (handshake steps or one message's encrypt/decrypt
 * pipeline) as an animated step list with the real bytes at each stage.
 *
 * Step shape: { label, detail?, value?, ok, ms, secret?, wire?, plain? }
 * Secret values (shared secrets, session keys) are blurred unless revealed.
 */

const fmtMs = (ms) => (ms >= 1 ? `${ms.toFixed(1)} ms` : ms > 0 ? `${(ms * 1000).toFixed(0)} µs` : '');

export default function TracePanel({ steps, revealSecrets, animateKey, stepDelay = 90 }) {
  if (!steps?.length) {
    return <div className="text-outline text-[11px] font-mono-soc p-md">No trace yet.</div>;
  }

  return (
    <ol key={animateKey} className="flex flex-col gap-1.5">
      {steps.map((s, i) => {
        const tone = !s.ok ? 'text-error' : s.wire ? 'text-primary-container' : s.plain ? 'text-tertiary-container' : 'text-secondary';
        return (
          <li
            key={i}
            className="trace-step relative flex gap-2 rounded-lg bg-surface-container-lowest/70 px-sm py-1.5"
            style={{ animationDelay: `${i * stepDelay}ms` }}
          >
            <div className="flex flex-col items-center pt-0.5">
              <span
                className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold font-mono ${
                  !s.ok ? 'bg-error/20 text-error'
                    : s.wire ? 'bg-primary-container/15 text-primary-container'
                    : 'bg-secondary/15 text-secondary'
                }`}
              >
                {!s.ok ? '✕' : s.wire ? '⇄' : i + 1}
              </span>
              {i < steps.length - 1 && <span className="mt-1 w-px flex-1 bg-outline-variant/60" />}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className={`font-mono-soc text-[11px] font-semibold ${tone}`}>{s.label}</span>
                <span className="shrink-0 font-mono text-[10px] text-outline">{fmtMs(s.ms)}</span>
              </div>
              {s.detail && (
                <div className="font-general text-[11px] leading-snug text-on-surface-variant">{s.detail}</div>
              )}
              {s.value != null && s.value !== '' && (
                <pre
                  className={`mt-1 max-h-28 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-container/80 px-1.5 py-1 font-mono text-[10px] leading-relaxed scrollbar-subtle ${
                    s.plain ? 'text-tertiary-container text-[12px] font-general' : 'text-primary'
                  } ${s.secret && !revealSecrets ? 'secret-blur select-none' : ''}`}
                  title={s.secret && !revealSecrets ? 'Secret value — use "Reveal secrets" to show' : undefined}
                >
                  {s.value}
                </pre>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
