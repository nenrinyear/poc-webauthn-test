'use client';

import Link from 'next/link';

export type Profile = {
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

type ActionState = { busy: boolean; disabled: boolean };

// 入力値と操作コールバックを受け取り、登録フォームの表示を担当する。
export function RegisterPanel({
  username,
  setUsername,
  busy,
  disabled,
  onRegister,
}: ActionState & {
  username: string;
  setUsername: (value: string) => void;
  onRegister: () => void;
}) {
  return (
    <section className="panel narrow">
      <h1>アカウントを作成</h1>
      <p>ユーザー名を入力してパスキーを登録してください。</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onRegister();
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
  );
}

export function LoginPanel({
  busy,
  disabled,
  onLogin,
}: ActionState & { onLogin: () => void }) {
  return (
    <section className="panel narrow">
      <h1>パスキーでログイン</h1>
      <p>ユーザー名の入力は不要です。</p>
      <button disabled={disabled} onClick={onLogin}>
        {busy ? '検証中…' : 'パスキーを選んでログイン'}
      </button>
      <p className="muted">
        初めての方は <Link href="/register">アカウント作成</Link>
      </p>
    </section>
  );
}

// 読み込み中・未ログイン・ログイン済みの3つの表示を切り替える。
export function AccountPanel({
  profile,
  loaded,
  busy,
  disabled,
  onLogout,
  onAddPasskey,
}: ActionState & {
  profile?: Profile;
  loaded: boolean;
  onLogout: () => void;
  onAddPasskey: () => void;
}) {
  return (
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
                作成日: {formatDate(profile.user.createdAt)} /
                セッションの有効期限: 発行から8時間
              </p>
            </div>
            <button className="secondary" disabled={busy} onClick={onLogout}>
              ログアウト
            </button>
          </div>
          <h2>
            登録済みパスキー{' '}
            <span className="count">{profile.passkeys.length}</span>
          </h2>
          <div className="key-list">
            {profile.passkeys.map((passkey, index) => (
              <article className="key" key={passkey.id}>
                <h3>パスキー {profile.passkeys.length - index}</h3>
                <dl>
                  <dt>Credential ID</dt>
                  <dd>
                    <code>{passkey.id}</code>
                  </dd>
                  <dt>署名カウンター</dt>
                  <dd>
                    {passkey.counter}
                    {passkey.counter === 0 && '（常に0の認証器もあります）'}
                  </dd>
                  <dt>デバイス / バックアップ</dt>
                  <dd>
                    {passkey.deviceType} / {passkey.backedUp ? 'あり' : 'なし'}
                  </dd>
                  <dt>Transport</dt>
                  <dd>{passkey.transports.join(', ') || '未提供'}</dd>
                  <dt>登録 / 最終認証</dt>
                  <dd>
                    {formatDate(passkey.createdAt)} /{' '}
                    {passkey.lastUsedAt
                      ? formatDate(passkey.lastUsedAt)
                      : 'まだ認証していません'}
                  </dd>
                </dl>
              </article>
            ))}
          </div>
          <button disabled={disabled} onClick={onAddPasskey}>
            パスキーを追加
          </button>
        </>
      )}
    </section>
  );
}

function formatDate(value: number) {
  return new Date(value).toLocaleString('ja-JP');
}
