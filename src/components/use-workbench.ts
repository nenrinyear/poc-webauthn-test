'use client';
import { useEffect, useState } from 'react';
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { useLab, isDevelopment, type LabEvent } from './lab-context';
import {
  decodeBase64url,
  encodeBase64url,
  decodeClientData,
  type RejectionExperiment,
} from '@/lib/webauthn-debug';
import type { Profile } from './workbench-panels';

export type WorkbenchMode = 'register' | 'login' | 'account' | 'lab';

type ApiReply<Payload> = Payload & {
  trace?: LabEvent[];
  error?: string;
};

export function useWorkbench(mode: WorkbenchMode) {
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
        .then(async (response) => {
          if (response.ok) setProfile(await response.json());
          else setMessage('ログインが必要です。');
        })
        .catch(() => setMessage('サーバーに接続できません。'))
        .finally(() => setLoaded(true));
    }
  }, [mode]);

  async function refreshProfile() {
    const response = await fetch('/api/me', { cache: 'no-store' });
    setProfile(response.ok ? await response.json() : undefined);
  }

  async function postApi<Payload extends object = object>(
    path: string,
    body: unknown = {},
  ): Promise<ApiReply<Payload>> {
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
    const data: ApiReply<Payload> = await response.json();
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

  async function register(addingPasskey: boolean) {
    const base = addingPasskey ? 'passkeys' : 'register';
    const { options } = await postApi<{
      options: PublicKeyCredentialCreationOptionsJSON;
    }>(`${base}/options`, addingPasskey ? {} : { username });
    lab.record({
      side: 'browser',
      action: 'navigator.credentials.create()',
      purpose:
        '認証器にdiscoverable credentialの生成とローカルの本人確認を要求。秘密鍵はJSへ返らない。',
      result: 'info',
    });
    const credential = await startRegistration({
      optionsJSON: options,
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
    await postApi(`${base}/verify`, { credential });
    setMessage(
      addingPasskey
        ? 'パスキーを追加しました。'
        : 'アカウントを作成し、ログインしました。',
    );
    if (addingPasskey) await refreshProfile();
  }

  async function login() {
    const { options } = await postApi<{
      options: PublicKeyCredentialRequestOptionsJSON;
    }>('authenticate/options');
    lab.record({
      side: 'browser',
      action: 'navigator.credentials.get()',
      purpose:
        'ユーザー名を送らずにパスキーを選択。認証器がauthenticatorDataとclientDataJSONのハッシュに署名する。',
      result: 'info',
    });
    const credential = await startAuthentication({
      optionsJSON: options,
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
    await postApi('authenticate/verify', { credential });
    if (isDevelopment) lab.saveAssertion(credential);
    setMessage('パスキー認証に成功しました。ユーザー情報を確認できます。');
  }

  async function experiment(kind: RejectionExperiment) {
    if (!lab.lastAssertion)
      throw new Error('先に「正常な認証」を実行してください。');
    const credential: AuthenticationResponseJSON = structuredClone(
      lab.lastAssertion,
    );
    if (kind !== 'replay') {
      const { options } = await postApi<{
        options: PublicKeyCredentialRequestOptionsJSON;
      }>('authenticate/options');
      const data = decodeClientData(
        credential.response.clientDataJSON,
      ) as Record<string, unknown>;
      data.challenge =
        kind === 'challenge'
          ? 'intentionally-wrong-challenge'
          : options.challenge;
      if (kind === 'origin') data.origin = 'https://unexpected.example';
      credential.response.clientDataJSON = encodeBase64url(
        JSON.stringify(data),
      );
      if (kind === 'rpid') {
        const bytes = decodeBase64url(credential.response.authenticatorData);
        bytes[0] ^= 0xff;
        credential.response.authenticatorData = encodeBase64url(bytes);
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
      await postApi('authenticate/verify', { credential });
      setMessage('予期しない成功です。サーバーの検証結果を確認してください。');
    } catch (error) {
      setMessage(
        `拒否を確認しました: ${error instanceof Error ? error.message : '検証失敗'}。詳細は下のサーバー記録を参照してください。`,
      );
    }
  }

  async function logout() {
    await postApi('logout');
    setProfile(undefined);
    setMessage('ログアウトしました。');
  }

  return {
    username,
    setUsername,
    profile,
    loaded,
    busy,
    supported,
    message,
    disabled: busy || supported !== true,
    registerAccount: () => {
      void run(() => register(false));
    },
    addPasskey: () => {
      void run(() => register(true));
    },
    login: () => {
      void run(login);
    },
    logout: () => {
      void run(logout);
    },
    experiment: (kind: RejectionExperiment) => {
      void run(() => experiment(kind));
    },
  };
}
