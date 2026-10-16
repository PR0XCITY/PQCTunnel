/**
 * useWebSocket.js
 * Manages the WebSocket connection to the PQCTunnel relay.
 *
 * - Events from a superseded socket are ignored (React StrictMode mounts
 *   effects twice in dev, so a first socket is opened and torn down).
 * - Sends made before the socket is open are queued, not dropped.
 * - Unexpected closes reconnect with backoff; a "role already taken" close
 *   (code 4000) is retried briefly, since the old socket may still be closing.
 */

import { useState, useEffect, useRef, useCallback } from 'react';

function defaultRelayUrl() {
  if (import.meta.env.VITE_RELAY_URL) return import.meta.env.VITE_RELAY_URL;
  if (!import.meta.env.DEV) return 'wss://pqctunnel.onrender.com';
  // Same host as the page, so a phone/laptop on the LAN reaches the relay too.
  // "localhost" can resolve to ::1 while the relay listens on IPv4.
  const host = window.location.hostname === 'localhost' ? '127.0.0.1' : window.location.hostname;
  return `ws://${host}:8000`;
}

const RELAY_URL = defaultRelayUrl();
const MAX_ROLE_RETRIES = 5;

export function useWebSocket(roomCode, role, { onMessage, onStatusChange } = {}) {
  const [status, setStatus]   = useState('disconnected'); // disconnected | connecting | connected
  const [error, setError]     = useState(null);
  const wsRef                 = useRef(null);
  const pendingRef            = useRef([]);
  const retryRef              = useRef({ timer: null, attempt: 0, roleRetries: 0, stopped: false });
  const onMessageRef          = useRef(onMessage);
  const onStatusChangeRef     = useRef(onStatusChange);

  useEffect(() => { onMessageRef.current     = onMessage;     }, [onMessage]);
  useEffect(() => { onStatusChangeRef.current = onStatusChange; }, [onStatusChange]);

  const updateStatus = (s) => { setStatus(s); onStatusChangeRef.current?.(s); };

  const connect = useCallback(() => {
    if (!roomCode || !role) return;
    const r = retryRef.current;
    r.stopped = false;
    clearTimeout(r.timer);

    const url = `${RELAY_URL}/ws/${encodeURIComponent(roomCode)}/${role}`;
    updateStatus('connecting');
    setError(null);

    const ws = new WebSocket(url);
    wsRef.current = ws;
    const current = () => wsRef.current === ws;
    let roleTaken = false;

    ws.onopen = () => {
      if (!current()) return;
      r.attempt = 0;
      updateStatus('connected');
      for (const data of pendingRef.current.splice(0)) ws.send(data);
    };

    ws.onmessage = (evt) => {
      if (!current()) return;
      let msg;
      try { msg = JSON.parse(evt.data); } catch { return; }
      if (msg.type === 'rejection' && /already taken/.test(msg.payload?.reason ?? '')) {
        roleTaken = true;
        if (r.roleRetries >= MAX_ROLE_RETRIES) setError(msg.payload.reason);
        return;
      }
      r.roleRetries = 0;
      onMessageRef.current?.(msg);
    };

    ws.onerror = () => {
      if (current()) setError(`Cannot reach relay at ${RELAY_URL}`);
    };

    ws.onclose = () => {
      if (!current()) return;
      updateStatus('disconnected');
      pendingRef.current = [];   // frames for the old connection's session are stale
      if (r.stopped) return;
      let delay;
      if (roleTaken) {
        if (r.roleRetries++ >= MAX_ROLE_RETRIES) return;
        delay = 400;
      } else {
        delay = Math.min(10000, 500 * 2 ** r.attempt++);
      }
      r.timer = setTimeout(connect, delay);
    };
  }, [roomCode, role]);

  const disconnect = useCallback(() => {
    const r = retryRef.current;
    r.stopped = true;
    clearTimeout(r.timer);
    const ws = wsRef.current;
    wsRef.current = null;
    pendingRef.current = [];
    ws?.close();
  }, []);

  const send = useCallback((data) => {
    const raw = JSON.stringify(data);
    const ws = wsRef.current;
    if (ws?.readyState === WebSocket.OPEN) ws.send(raw);
    else pendingRef.current.push(raw);
  }, []);

  // Auto-connect when room and role are provided
  useEffect(() => {
    if (roomCode && role) connect();
    return () => disconnect();
  }, [roomCode, role, connect, disconnect]);

  return { status, error, send, connect, disconnect, relayUrl: RELAY_URL };
}
