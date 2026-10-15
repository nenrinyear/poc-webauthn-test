'use client';
import { createContext, useContext, useState, type ReactNode } from 'react';
import type { AuthenticationResponseJSON } from '@simplewebauthn/browser';
export type LabEvent = {
  side: 'browser' | 'server';
  action: string;
  purpose: string;
  result: string;
  details?: unknown;
  time?: string;
};
type LabState = {
  events: LabEvent[];
  record: (event: LabEvent) => void;
  clear: () => void;
  lastAssertion?: AuthenticationResponseJSON;
  saveAssertion: (value: AuthenticationResponseJSON) => void;
};
const LabContext = createContext<LabState | null>(null);
const MAX_EVENTS = 80;

export const isDevelopment = process.env.NODE_ENV === 'development';
export function LabProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<LabEvent[]>([]);
  const [lastAssertion, saveAssertion] = useState<AuthenticationResponseJSON>();
  function record(event: LabEvent) {
    if (isDevelopment)
      setEvents((previousEvents) => [
        ...previousEvents.slice(-(MAX_EVENTS - 1)),
        { ...event, time: new Date().toLocaleTimeString('ja-JP') },
      ]);
  }
  function clear() {
    setEvents([]);
    saveAssertion(undefined);
  }

  return (
    <LabContext.Provider
      value={{
        events,
        record,
        clear,
        lastAssertion,
        saveAssertion,
      }}
    >
      {children}
    </LabContext.Provider>
  );
}
export function useLab() {
  const value = useContext(LabContext);
  if (!value) throw new Error('LabProvider missing');
  return value;
}
