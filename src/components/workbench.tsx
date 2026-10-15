'use client';

import Link from 'next/link';
import { useLab, isDevelopment } from './lab-context';
import { AccountPanel, LoginPanel, RegisterPanel } from './workbench-panels';
import { LabPanel } from './lab-panel';
import { useWorkbench, type WorkbenchMode } from './use-workbench';

export function Workbench({ mode }: { mode: WorkbenchMode }) {
  const lab = useLab();
  const workbench = useWorkbench(mode);
  const { busy, disabled, message, supported } = workbench;

  return (
    <>
      {supported === false && (
        <p className="notice">
          このブラウザではWebAuthnが利用できません。localhostを対応ブラウザで開いてください。
        </p>
      )}
      {mode === 'register' && (
        <RegisterPanel
          username={workbench.username}
          setUsername={workbench.setUsername}
          busy={busy}
          disabled={disabled}
          onRegister={workbench.registerAccount}
        />
      )}
      {mode === 'login' && (
        <LoginPanel busy={busy} disabled={disabled} onLogin={workbench.login} />
      )}
      {mode === 'account' && (
        <AccountPanel
          profile={workbench.profile}
          loaded={workbench.loaded}
          busy={busy}
          disabled={disabled}
          onLogout={workbench.logout}
          onAddPasskey={workbench.addPasskey}
        />
      )}
      {message && (
        <p className="notice" role="status" aria-live="polite">
          {message}{' '}
          {(mode === 'login' || mode === 'register') && (
            <Link href="/account">ユーザー情報へ →</Link>
          )}
        </p>
      )}
      {mode === 'lab' && (
        <LabPanel
          busy={busy}
          disabled={disabled}
          onLogin={workbench.login}
          onExperiment={workbench.experiment}
        />
      )}
      {isDevelopment && mode !== 'lab' && (
        <section className="panel compact">
          <h2>今回の処理を追跡</h2>
          <p>
            ブラウザとサーバーの記録: {lab.events.length}件。
            <Link href="/lab">検証画面で詳細を見る →</Link>
          </p>
        </section>
      )}
    </>
  );
}
