'use client';
import { createContext, useContext, useState, type ReactNode } from 'react';
import type { AuthenticationResponseJSON } from '@simplewebauthn/browser';
export type Event = {
  side: 'browser' | 'server';
  action: string;
  purpose: string;
  result: string;
  details?: unknown;
  time?: string;
};
type LabState = {
  events: Event[];
  record: (event: Event) => void;
  clear: () => void;
  lastAssertion?: AuthenticationResponseJSON;
  saveAssertion: (value: AuthenticationResponseJSON) => void;
};
const Context = createContext<LabState | null>(null);
export const dev = process.env.NODE_ENV === 'development';
export function LabProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [lastAssertion, saveAssertion] = useState<AuthenticationResponseJSON>();
  function record(event: Event) {
    if (dev)
      setEvents((old) => [
        ...old.slice(-79),
        { ...event, time: new Date().toLocaleTimeString('ja-JP') },
      ]);
  }
  return (
    <Context.Provider
      value={{
        events,
        record,
        clear: () => {
          setEvents([]);
          saveAssertion(undefined);
        },
        lastAssertion,
        saveAssertion,
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function useLab() {
  const value = useContext(Context);
  if (!value) throw new Error('LabProvider missing');
  return value;
}
