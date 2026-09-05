/** Attack scoreboard — attempts vs blocked per attack type */
export default function Scoreboard({ score }) {
  const types = [
    { key: 'replay',    label: 'Replay',    icon: '🔁' },
    { key: 'tamper',    label: 'Tamper',    icon: '🪛' },
    { key: 'downgrade', label: 'Downgrade', icon: '📉' },
    { key: 'mitm',      label: 'Key Sub',   icon: '🔑' },
  ];

  const totalAttempts = types.reduce((s, t) => s + score[t.key][0], 0);
  const totalBlocked  = types.reduce((s, t) => s + score[t.key][1], 0);

  return (
    <div className="scoreboard">
      <div className="sb-totals">
        <div className="sb-total attempts">{totalAttempts}<span>attacks</span></div>
        <div className="sb-total blocked">{totalBlocked}<span>blocked</span></div>
        <div className="sb-total succeeded">0<span>succeeded</span></div>
      </div>

      <div className="sb-rows">
        {types.map(t => {
          const [attempts, blocked] = score[t.key];
          return (
            <div key={t.key} className="sb-row">
              <span className="sb-icon">{t.icon}</span>
              <span className="sb-label">{t.label}</span>
              <span className="sb-count">{attempts} / {blocked}</span>
            </div>
          );
        })}
      </div>

      <div className="sb-note">attempts / blocked</div>
    </div>
  );
}
