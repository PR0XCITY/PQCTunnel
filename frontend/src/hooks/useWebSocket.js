/**
 * useWebSocket.js
 * Manages the WebSocket connection to the PQCTunnel relay.
 * Handles connect, disconnect, reconnect, and message queuing.
 */

import { useState, useEffect, useRef, useCallback } from 'react';

const RELAY_URL = import.meta.env.VITE_RELAY_URL || 'wss://pqctunnel.onrender.com';

export function useWebSocket(roomCode, role, { onMessage, onStatusChange } = {}) {
  const [status, setStatus]   = useState('disconnected'); // disconnected | connecting | connected
  const [error, setError]     = useState(null);
  const wsRef                 = useRef(null);
  const onMessageRef          = useRef(onMessage);
  const onStatusChangeRef     = useRef(onStatusChange);

  useEffect(() => { onMessageRef.current     = onMessage;     }, [onMessage]);
  useEffect(() => { onStatusChangeRef.current = onStatusChange; }, [onStatusChange]);

  const connect = useCallback(() => {
    if (!roomCode || !role) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const url = `${RELAY_URL}/ws/${roomCode}/${role}`;
    setStatus('connecting');
    setError(null);
    onStatusChangeRef.current?.('connecting');

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      onStatusChangeRef.current?.('connected');
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        onMessageRef.current?.(msg);
      } catch {
        // Ignore non-JSON frames
      }
    };

    ws.onerror = () => {
      setError('WebSocket connection error');
    };

    ws.onclose = () => {
      setStatus('disconnected');
      onStatusChangeRef.current?.('disconnected');
    };
  }, [roomCode, role]);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
  }, []);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  // Auto-connect when room and role are provided
  useEffect(() => {
    if (roomCode && role) connect();
    return () => disconnect();
  }, [roomCode, role, connect, disconnect]);

  return { status, error, send, connect, disconnect };
}
