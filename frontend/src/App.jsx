import { useState } from 'react';
import AliceBobView from './views/AliceBobView';
import EveView from './views/EveView';

function App() {
  const [role, setRole] = useState(null);
  const [room, setRoom] = useState('');
  
  if (role === 'alice' || role === 'bob') {
    return <AliceBobView roomCode={room} role={role} />;
  }
  if (role === 'eve') {
    return <EveView roomCode={room} role="eve" />;
  }

  // Landing Page
  return (
    <div className="landing-theme dark min-h-screen flex items-center justify-center p-4 cyber-grid relative overflow-hidden" style={{ background: 'var(--c-background)' }}>
      {/* Background Ambience */}
      <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(34,229,255,0.03) 0%, transparent 60%)' }} />
      <div className="absolute top-1/4 -left-1/4 w-[500px] h-[500px] rounded-full bg-primary/5 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 -right-1/4 w-[500px] h-[500px] rounded-full bg-error/5 blur-[120px] pointer-events-none" />
      
      <div className="max-w-md w-full bg-surface-container-low/80 backdrop-blur-xl border border-outline-variant/30 rounded-2xl shadow-2xl overflow-hidden relative z-10 glow-cyan-subtle">
        
        {/* Header */}
        <div className="p-8 text-center border-b border-surface-container-highest">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-2xl bg-surface-container-highest flex items-center justify-center shadow-inner relative">
               <span className="material-symbols-outlined text-[32px] text-primary drop-shadow-[0_0_12px_rgba(34,229,255,0.8)]">security</span>
               <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-secondary animate-ping" />
            </div>
          </div>
          <h1 className="font-clash text-display-lg text-on-surface mb-2 tracking-tight">PQCTunnel</h1>
          <p className="font-general text-body-md text-on-surface-variant max-w-sm mx-auto">
            Zero-trust post-quantum secure messenger. ML-KEM-768 + X25519 hybrid key exchange.
          </p>
        </div>
        
        {/* Body */}
        <div className="p-8 flex flex-col gap-6">
          
          <div className="flex flex-col gap-2">
             <label className="font-mono-soc text-code-sm text-outline uppercase tracking-wider ml-1">Tunnel Destination Code</label>
             <div className="relative group">
                <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                  <span className="material-symbols-outlined text-outline-variant text-[18px]">vpn_key</span>
                </div>
                <input 
                  className="w-full bg-surface-container-lowest border border-outline-variant/50 rounded-xl py-3 pl-12 pr-4 text-on-surface font-mono text-lg focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
                  placeholder="e.g. 9988"
                  value={room}
                  onChange={(e) => setRoom(e.target.value)}
                />
             </div>
          </div>

          <div className="flex flex-col gap-3 mt-2">
            <button 
              disabled={!room.trim()}
              onClick={() => setRole('alice')}
              className="w-full relative flex items-center justify-between p-4 rounded-xl border border-outline-variant/30 bg-surface-container hover:bg-surface-container-high transition-all disabled:opacity-50 disabled:cursor-not-allowed group overflow-hidden"
            >
              <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="w-8 h-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold">A</div>
                <div className="flex flex-col items-start">
                  <span className="font-clash text-headline-sm text-on-surface">Join as Alice</span>
                  <span className="font-general text-body-sm text-on-surface-variant">Session Initiator</span>
                </div>
              </div>
              <span className="material-symbols-outlined text-outline group-hover:text-primary transition-colors relative z-10">chevron_right</span>
            </button>

            <button 
              disabled={!room.trim()}
              onClick={() => setRole('bob')}
              className="w-full relative flex items-center justify-between p-4 rounded-xl border border-outline-variant/30 bg-surface-container hover:bg-surface-container-high transition-all disabled:opacity-50 disabled:cursor-not-allowed group overflow-hidden"
            >
              <div className="absolute inset-0 bg-secondary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="w-8 h-8 rounded-full bg-secondary/20 text-secondary flex items-center justify-center font-bold">B</div>
                <div className="flex flex-col items-start">
                  <span className="font-clash text-headline-sm text-on-surface">Join as Bob</span>
                  <span className="font-general text-body-sm text-on-surface-variant">Session Responder</span>
                </div>
              </div>
              <span className="material-symbols-outlined text-outline group-hover:text-secondary transition-colors relative z-10">chevron_right</span>
            </button>

            <div className="h-px bg-surface-container-highest my-2" />

            <button 
              disabled={!room.trim()}
              onClick={() => setRole('eve')}
              className="w-full relative flex items-center justify-between p-4 rounded-xl border border-error/20 bg-error/5 hover:bg-error/10 transition-all disabled:opacity-50 disabled:cursor-not-allowed group overflow-hidden"
            >
               <div className="absolute inset-0 bg-error/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="w-8 h-8 rounded-full bg-error/20 text-error flex items-center justify-center font-bold">E</div>
                <div className="flex flex-col items-start">
                  <span className="font-clash text-headline-sm text-error">Intercept as Eve</span>
                  <span className="font-general text-body-sm text-error/70">Adversary Red-Team Console</span>
                </div>
              </div>
              <span className="material-symbols-outlined text-error/50 group-hover:text-error transition-colors relative z-10">bug_report</span>
            </button>
          </div>

        </div>
        
        {/* Footer */}
        <div className="p-4 text-center bg-surface-container-lowest/50 border-t border-surface-container-highest">
          <span className="font-mono-soc text-[10px] text-outline flex items-center justify-center gap-1">
             <span className="material-symbols-outlined text-[14px]">lock</span>
             NIST SP 800-208 COMPLIANT
          </span>
        </div>
      </div>
    </div>
  );
}

export default App;
