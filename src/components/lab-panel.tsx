'use client';

import type { RejectionExperiment } from '@/lib/webauthn-debug';
import { useLab } from './lab-context';
import { TraceView } from './trace-view';

// 種類とラベルを同じ場所で定義し、ボタンの表示と実行内容がずれないようにする。
const experiments: { kind: RejectionExperiment; label: string }[] = [
  { kind: 'replay', label: '応答を再送' },
  { kind: 'challenge', label: 'challengeを改変' },
  { kind: 'origin', label: 'Originを改変' },
  { kind: 'rpid', label: 'rpIdHashを改変' },
];

export function LabPanel({
  busy,
  disabled,
  onLogin,
  onExperiment,
}: {
  busy: boolean;
  disabled: boolean;
  onLogin: () => void;
  onExperiment: (kind: RejectionExperiment) => void;
}) {
  const lab = useLab();

  return (
    <>
      <section className="panel">
        <h1>WebAuthn フローを観察する</h1>
        <p>
          登録・ログイン画面の操作が、この画面にも記録されます。記録はこのタブのメモリ内に保持し、リロードで消去します。
        </p>
        <div className="flow">
          <div>
            <b>1. サーバー</b>
            <span>challengeを生成・保存</span>
          </div>
          <div>
            <b>2. ブラウザ → 認証器</b>
            <span>鍵の作成 / 署名・本人確認</span>
          </div>
          <div>
            <b>3. サーバー</b>
            <span>応答を検証・DB更新</span>
          </div>
          <div>
            <b>4. アプリ</b>
            <span>セッションでログイン管理</span>
          </div>
        </div>
        <p>
          公開鍵は署名の検証に使います。秘密鍵は認証器やパスキープロバイダーが管理し、このアプリは取得しません。同期型パスキーでは、プロバイダーにより鍵が同期される場合があります。
        </p>
        <h2>拒否の再現</h2>
        <p className="muted">
          まず正常な認証を実行して応答を取得します。再送は使用済みチャレンジで拒否。改変実験は新しいチャレンジを取得して実施します。既存のログイン状態は失敗しても継続します。
        </p>
        <div className="actions">
          <button disabled={disabled} onClick={onLogin}>
            正常な認証
          </button>
          {experiments.map(({ kind, label }) => (
            <button
              className="secondary"
              key={kind}
              disabled={busy || !lab.lastAssertion}
              onClick={() => onExperiment(kind)}
            >
              {label}
            </button>
          ))}
        </div>
        <p className="muted">
          画面実験の改変は署名も壊します。各条件を単独で変更した正しい署名の入力による検証は{' '}
          <code>pnpm test</code> を参照してください。
        </p>
      </section>
      <TraceView />
    </>
  );
}
