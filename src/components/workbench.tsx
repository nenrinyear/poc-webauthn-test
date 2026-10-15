'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { useLab, dev, type Event } from './lab-context';

type Profile = {
  user: { username: string; createdAt: number };
  passkeys: {
    id: string;
    counter: number;
    transports: string[];
    deviceType: string;
    backedUp: boolean;
    createdAt: number;
    lastUsedAt: number | null;
  }[];
};
type Reply = {
  options:
    | PublicKeyCredentialCreationOptionsJSON
    | PublicKeyCredentialRequestOptionsJSON;
  trace?: Event[];
  error?: string;
  verified?: boolean;
};
export function Workbench({
  mode,
}: {
  mode: 'register' | 'login' | 'account' | 'lab';
}) {
  const lab = useLab();
  const [username, setUsername] = useState('');
  const [profile, setProfile] = useState<Profile>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [supported, setSupported] = useState<boolean>();
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    setSupported(browserSupportsWebAuthn() && window.isSecureContext);
    if (mode === 'account') {
      fetch('/api/me', { cache: 'no-store' })
        .then(async (r) => {
          if (r.ok) setProfile(await r.json());
          else setMessage('ログインが必要です。');
        })
        .catch(() => setMessage('サーバーに接続できません。'))
        .finally(() => setLoaded(true));
    }
  }, [mode]);
  async function refresh() {
    const response = await fetch('/api/me', { cache: 'no-store' });
    setProfile(response.ok ? await response.json() : undefined);
  }
  async function api(path: string, body: unknown = {}): Promise<Reply> {
    lab.record({
      side: 'browser',
      action: `POST /api/${path}`,
      purpose: 'ブラウザからサーバーへ送信。CookieはHttpOnlyで表示対象外。',
      result: 'info',
      details: body,
    });
    const response = await fetch(`/api/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data: Reply = await response.json();
    lab.record({
      side: 'browser',
      action: `HTTP ${response.status} /api/${path}`,
      purpose: 'サーバーから受信したJSON。ヘッダーとCookieは収集しない。',
      result: response.ok ? 'passed' : 'failed',
      details: data,
    });
    data.trace?.forEach(lab.record);
    if (!response.ok)
      throw new Error(data.error ?? 'リクエストが失敗しました。');
    return data;
  }
  async function run(work: () => Promise<void>) {
    setBusy(true);
    setMessage('');
    try {
      await work();
    } catch (error) {
      const reason = error instanceof Error ? error.message : '不明なエラー';
      setMessage(reason);
      lab.record({
        side: 'browser',
        action: '操作終了 / エラー',
        purpose:
          'キャンセル、ブラウザの制約、またはサーバーの拒否。サーバー検証の成否とは区別する。',
        result: 'failed',
        details: { reason },
      });
    } finally {
      setBusy(false);
    }
  }
  async function register(add: boolean) {
    const base = add ? 'passkeys' : 'register';
    const { options } = await api(`${base}/options`, add ? {} : { username });
    lab.record({
      side: 'browser',
      action: 'navigator.credentials.create()',
      purpose:
        '認証器にdiscoverable credentialの生成とローカルの本人確認を要求。秘密鍵はJSへ返らない。',
      result: 'info',
    });
    const credential = await startRegistration({
      optionsJSON: options as PublicKeyCredentialCreationOptionsJSON,
    });
    lab.record({
      side: 'browser',
      action: '登録レスポンス取得',
      purpose: 'ブラウザが得たデータ。サーバーで検証されるまでは信頼しない。',
      result: 'info',
      details: {
        credential,
        clientData: decodeClientData(credential.response.clientDataJSON),
      },
    });
    await api(`${base}/verify`, { credential });
    setMessage(
      add
        ? 'パスキーを追加しました。'
        : 'アカウントを作成し、ログインしました。',
    );
    if (add) await refresh();
  }
  async function login() {
    const { options } = await api('authenticate/options');
    lab.record({
      side: 'browser',
      action: 'navigator.credentials.get()',
      purpose:
        'ユーザー名を送らずにパスキーを選択。認証器がauthenticatorDataとclientDataJSONのハッシュに署名する。',
      result: 'info',
    });
    const credential = await startAuthentication({
      optionsJSON: options as PublicKeyCredentialRequestOptionsJSON,
    });
    lab.record({
      side: 'browser',
      action: '認証レスポンス取得',
      purpose:
        'clientDataJSONの復号表示は観察用。内容の信頼性はサーバーの署名検証で判断する。',
      result: 'info',
      details: {
        credential,
        clientData: decodeClientData(credential.response.clientDataJSON),
      },
    });
    await api('authenticate/verify', { credential });
    if (dev) lab.saveAssertion(credential);
    setMessage('パスキー認証に成功しました。ユーザー情報を確認できます。');
  }
  async function experiment(kind: 'replay' | 'challenge' | 'origin' | 'rpid') {
    if (!lab.lastAssertion)
      throw new Error('先に「正常な認証」を実行してください。');
    const credential: AuthenticationResponseJSON = structuredClone(
      lab.lastAssertion,
    );
    if (kind !== 'replay') {
      const { options } = await api('authenticate/options');
      const data = decodeClientData(
        credential.response.clientDataJSON,
      ) as Record<string, unknown>;
      data.challenge =
        kind === 'challenge'
          ? 'intentionally-wrong-challenge'
          : options.challenge;
      if (kind === 'origin') data.origin = 'https://unexpected.example';
      credential.response.clientDataJSON = encode(JSON.stringify(data));
      if (kind === 'rpid') {
        const bytes = decode(credential.response.authenticatorData);
        bytes[0] ^= 0xff;
        credential.response.authenticatorData = encode(bytes);
      }
    }
    lab.record({
      side: 'browser',
      action: `拒否実験: ${kind}`,
      purpose:
        'コピーした応答を通常の検証APIへ送信。改変すると署名も無効になるため、独立した原因の確認は自動テストで行う。',
      result: 'info',
    });
    try {
      await api('authenticate/verify', { credential });
      setMessage('予期しない成功です。サーバーの検証結果を確認してください。');
    } catch (error) {
      setMessage(
        `拒否を確認しました: ${error instanceof Error ? error.message : '検証失敗'}。詳細は下のサーバー記録を参照してください。`,
      );
    }
  }
  const disabled = busy || supported !== true;
  return (
    <>
      {supported === false && (
        <p className="notice">
          このブラウザではWebAuthnが利用できません。localhostを対応ブラウザで開いてください。
        </p>
      )}
      {mode === 'register' && (
        <section className="panel narrow">
          <h1>アカウントを作成</h1>
          <p>ユーザー名を入力してパスキーを登録してください。</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => register(false));
            }}
          >
            <label htmlFor="username">
              ユーザー名<span className="required">必須</span>
            </label>
            <input
              id="username"
              aria-describedby="username-hint"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              pattern="[a-zA-Z0-9_-]{3,32}"
              minLength={3}
              maxLength={32}
              autoComplete="username"
              placeholder="researcher_01"
            />
            <small id="username-hint">
              英数字・_・- / 3〜32文字（大文字と小文字を区別）
            </small>
            <button disabled={disabled} type="submit">
              {busy ? '処理中…' : 'パスキーを登録して作成'}
            </button>
          </form>
          <p className="muted">
            すでに登録済みの場合は <Link href="/login">ログイン</Link>
          </p>
        </section>
      )}
      {mode === 'login' && (
        <section className="panel narrow">
          <h1>パスキーでログイン</h1>
          <p>ユーザー名の入力は不要です。</p>
          <button disabled={disabled} onClick={() => void run(login)}>
            {busy ? '検証中…' : 'パスキーを選んでログイン'}
          </button>
          <p className="muted">
            初めての方は <Link href="/register">アカウント作成</Link>
          </p>
        </section>
      )}
      {mode === 'account' && (
        <section className="panel">
          <h1>ユーザー情報とパスキー</h1>
          {!loaded ? (
            <p>読み込み中…</p>
          ) : !profile ? (
            <p>
              <Link href="/login">ログイン画面へ</Link>
            </p>
          ) : (
            <>
              <div className="account-head">
                <div>
                  <h2>{profile.user.username}</h2>
                  <p>
                    作成日: {date(profile.user.createdAt)} /
                    セッションの有効期限: 発行から8時間
                  </p>
                </div>
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      await api('logout');
                      setProfile(undefined);
                      setMessage('ログアウトしました。');
                    })
                  }
                >
                  ログアウト
                </button>
              </div>
              <h2>
                登録済みパスキー{' '}
                <span className="count">{profile.passkeys.length}</span>
              </h2>
              <div className="key-list">
                {profile.passkeys.map((key, i) => (
                  <article className="key" key={key.id}>
                    <h3>パスキー {profile.passkeys.length - i}</h3>
                    <dl>
                      <dt>Credential ID</dt>
                      <dd>
                        <code>{key.id}</code>
                      </dd>
                      <dt>署名カウンター</dt>
                      <dd>
                        {key.counter}
                        {key.counter === 0 && '（常に0の認証器もあります）'}
                      </dd>
                      <dt>デバイス / バックアップ</dt>
                      <dd>
                        {key.deviceType} / {key.backedUp ? 'あり' : 'なし'}
                      </dd>
                      <dt>Transport</dt>
                      <dd>{key.transports.join(', ') || '未提供'}</dd>
                      <dt>登録 / 最終認証</dt>
                      <dd>
                        {date(key.createdAt)} /{' '}
                        {key.lastUsedAt
                          ? date(key.lastUsedAt)
                          : 'まだ認証していません'}
                      </dd>
                    </dl>
                  </article>
                ))}
              </div>
              <button
                disabled={disabled}
                onClick={() => void run(() => register(true))}
              >
                パスキーを追加
              </button>
            </>
          )}
        </section>
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
              <button disabled={disabled} onClick={() => void run(login)}>
                正常な認証
              </button>
              {(['replay', 'challenge', 'origin', 'rpid'] as const).map(
                (kind, i) => (
                  <button
                    className="secondary"
                    key={kind}
                    disabled={busy || !lab.lastAssertion}
                    onClick={() => void run(() => experiment(kind))}
                  >
                    {
                      [
                        '応答を再送',
                        'challengeを改変',
                        'Originを改変',
                        'rpIdHashを改変',
                      ][i]
                    }
                  </button>
                ),
              )}
            </div>
            <p className="muted">
              画面実験の改変は署名も壊します。各条件を単独で変更した正しい署名の入力による検証は{' '}
              <code>pnpm test</code> を参照してください。
            </p>
          </section>
          <TraceView />
        </>
      )}
      {dev && mode !== 'lab' && (
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
function TraceView() {
  const lab = useLab();
  return (
    <section className="panel">
      <div className="account-head">
        <h2>
          通信と検証の記録 <span className="count">{lab.events.length}</span>
        </h2>
        <button className="secondary" onClick={lab.clear}>
          記録を消去
        </button>
      </div>
      <p className="muted">
        青: ブラウザの観測（未検証の入力を含む） / 緑:
        サーバーの処理結果。JSONにはchallenge、ユーザー名、Credential
        IDが含まれます。共有前に確認してください。Cookie・セッション識別子・秘密鍵は記録しません。
      </p>
      {!lab.events.length && (
        <p className="empty">
          まだ記録がありません。アカウントを作成するか、正常な認証を実行してください。
        </p>
      )}
      <ol className="events">
        {lab.events.map((e, i) => (
          <li className={`event ${e.side}`} key={i}>
            <div className="event-title">
              <span className="badge">
                {e.side === 'browser' ? 'BROWSER' : 'SERVER'}
              </span>
              <b>{e.action}</b>
              <span className={`result ${e.result}`}>{e.result}</span>
              <time>{e.time}</time>
            </div>
            <p>{e.purpose}</p>
            {e.details !== undefined && (
              <details>
                <summary>JSON / 詳細を表示</summary>
                <pre>{JSON.stringify(e.details, null, 2)}</pre>
              </details>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
function decode(value: string) {
  return Uint8Array.from(
    atob(value.replace(/-/g, '+').replace(/_/g, '/')),
    (c) => c.charCodeAt(0),
  );
}
function encode(value: string | Uint8Array) {
  const bytes =
    typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return btoa(Array.from(bytes, (n) => String.fromCharCode(n)).join(''))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function decodeClientData(value: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(decode(value)));
  } catch {
    return { error: 'clientDataJSONをデコードできません' };
  }
}
function date(value: number) {
  return new Date(value).toLocaleString('ja-JP');
}
