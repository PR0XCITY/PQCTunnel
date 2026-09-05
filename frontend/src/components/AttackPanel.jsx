/** Attack control panel — four buttons, each requires a relevant frame to be selected */
export default function AttackPanel({ selected, onReplay, onTamper, onDowngrade, onMitm }) {
  const hasData  = selected?.frame?.type === 'data';
  const hasHello = selected?.frame?.type === 'client_hello';

  return (
    <div className="attack-panel">
      {!selected && (
        <div className="attack-hint">
          Select a frame from the traffic feed to enable attacks.
        </div>
      )}
      {selected && (
        <div className="attack-selected">
          Selected: <span className="sel-type">{selected.frame.type}</span>
          {' '}from <span className="sel-from">{selected.from?.toUpperCase()}</span>
        </div>
      )}

      <div className="attack-grid">
        <AttackBtn
          label="Replay"
          icon="🔁"
          desc="Resend captured message with same seq"
          result='"sequence number N already used"'
          enabled={hasData}
          onClick={onReplay}
          color="var(--amber)"
        />
        <AttackBtn
          label="Tamper"
          icon="🪛"
          desc="Flip ciphertext byte, fresh seq number"
          result='"GCM auth tag mismatch"'
          enabled={hasData}
          onClick={onTamper}
          color="var(--orange)"
        />
        <AttackBtn
          label="Downgrade"
          icon="📉"
          desc="Strip PQC fields from ClientHello"
          result='"malformed ClientHello: PQC fields missing"'
          enabled={hasHello}
          onClick={onDowngrade}
          color="var(--rose)"
        />
        <AttackBtn
          label="Key Sub"
          icon="🔑"
          desc="Replace public keys with Eve's own"
          result='"public key does not match session identity"'
          enabled={hasHello}
          onClick={onMitm}
          color="var(--red)"
        />
      </div>
    </div>
  );
}

function AttackBtn({ label, icon, desc, result, enabled, onClick, color }) {
  return (
    <button
      className={`attack-btn ${enabled ? 'enabled' : 'disabled'}`}
      onClick={enabled ? onClick : undefined}
      style={{ '--btn-color': color }}
    >
      <span className="abt-icon">{icon}</span>
      <span className="abt-label">{label}</span>
      <span className="abt-desc">{desc}</span>
      <span className="abt-result">{result}</span>
    </button>
  );
}
