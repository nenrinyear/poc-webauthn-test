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

// レイアウト配下の画面で記録を共有する。永続化しないため、再読み込みで消える。
export function LabProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<LabEvent[]>([]);
  const [lastAssertion, saveAssertion] = useState<AuthenticationResponseJSON>();

  function record(event: LabEvent) {
    // 本番では記録せず、開発時も直近80件に絞ってメモリの増加を抑える。
    if (isDevelopment)
      setEvents((previousEvents) => [
        ...previousEvents.slice(-(MAX_EVENTS - 1)),
        { ...event, time: new Date().toLocaleTimeString('ja-JP') },
      ]);
  }

  function clear() {
    // 記録と実験用の応答を一緒に消し、消去前の応答が再利用されないようにする。
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
