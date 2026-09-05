import { useState, useRef, useEffect } from 'react';

export default function ChatPanel({ messages, role, peer, isSecure, onSend }) {
  const [text, setText]   = useState('');
  const bottomRef         = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = () => {
    if (!isSecure || !text.trim()) return;
    onSend(text.trim());
    setText('');
  };

  return (
    <div className="chat-wrap">
      <div className="chat-messages">
        {messages.length === 0 && (
          <div className="chat-empty">
            {isSecure ? 'Channel secure. Send a message.' : 'Waiting for handshake to complete...'}
          </div>
        )}
        {messages.map(m => (
          <div key={m.id} className={`chat-msg ${m.from === role ? 'mine' : 'theirs'}`}>
            <span className="chat-from">{m.from.toUpperCase()}</span>
            <span className="chat-text">{m.text}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="chat-input-row">
        <input
          className="chat-input"
          placeholder={isSecure ? 'Type a message...' : 'Waiting for secure channel...'}
          value={text}
          disabled={!isSecure}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send()}
        />
        <button className="chat-send" onClick={send} disabled={!isSecure || !text.trim()}>
          Send
        </button>
      </div>
    </div>
  );
}
