import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
} from '@simplewebauthn/server';
import { CHALLENGE_TTL, SESSION_TTL, configuration } from './config';
import { transaction } from './db';

// APIへ返すエラーコード・HTTPステータスと、開発時だけ表示する詳細をまとめる。
export class AuthError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 400,
    public detail?: string,
  ) {
    super(message);
  }
}

export type User = { id: string; username: string; created_at: number };

// ceremonyは、登録・追加登録・認証の開始から検証までを結び付ける一時情報。
type Ceremony = {
  kind: 'register' | 'add' | 'authenticate';
  challenge: string;
  user_id: string | null;
  username: string | null;
  session_hash: string | null;
  expires_at: number;
};

// SQLiteの列名と保存形式に合わせた型。秘密鍵は含まれない。
type StoredCredential = {
  id: string;
  user_id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string;
  device_type: string;
  backed_up: number;
  created_at: number;
  last_used_at: number | null;
};

// Cookieの生値をDBへ保存せず、照合にはSHA-256ハッシュを使う。
export const hash = (value: string) =>
  createHash('sha256').update(value).digest('hex');

const createToken = () => randomBytes(32).toString('base64url');

export type Trace = {
  side: 'server';
  action: string;
  purpose: string;
  result: 'passed' | 'failed' | 'info';
  details?: unknown;
};

// チャレンジの消費、WebAuthn検証、DB更新の順序をここで管理する。
export class AuthService {
  constructor(
    readonly db: DatabaseSync,
    readonly now = () => Date.now(),
  ) {}

  cleanup() {
    this.db
      .prepare('DELETE FROM ceremonies WHERE expires_at <= ?')
      .run(this.now());
    this.db
      .prepare('DELETE FROM sessions WHERE expires_at <= ?')
      .run(this.now());
  }

  session(sessionToken?: string): User | undefined {
    if (!sessionToken) return;

    // Cookieが残っていても、サーバー側の期限を過ぎたセッションは認めない。
    return this.db
      .prepare(
        `SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
      WHERE s.token_hash=? AND s.expires_at>?`,
      )
      .get(hash(sessionToken), this.now()) as User | undefined;
  }

  requireSession(sessionToken?: string) {
    const user = this.session(sessionToken);
    if (!user)
      throw new AuthError('SESSION_REQUIRED', 'ログインが必要です。', 401);

    return user;
  }

  logout(sessionToken?: string) {
    if (sessionToken) {
      this.db
        .prepare('DELETE FROM sessions WHERE token_hash=?')
        .run(hash(sessionToken));

      // ログアウトしたセッションから始めたパスキー追加も無効にする。
      this.db
        .prepare('DELETE FROM ceremonies WHERE session_hash=?')
        .run(hash(sessionToken));
    }
  }

  list(userID: string) {
    const rows = this.db
      .prepare(
        'SELECT * FROM credentials WHERE user_id=? ORDER BY created_at DESC',
      )
      .all(userID) as StoredCredential[];

    // 一覧画面で使う情報に絞り、検証用の公開鍵はAPIへ返さない。
    return rows.map((credential) => ({
      id: credential.id,
      counter: credential.counter,
      transports: JSON.parse(credential.transports) as AuthenticatorTransport[],
      deviceType: credential.device_type,
      backedUp: Boolean(credential.backed_up),
      createdAt: credential.created_at,
      lastUsedAt: credential.last_used_at,
    }));
  }

  private issueSession(userID: string, previous?: string) {
    // 認証成功時は以前のセッションを失効させ、新しいトークンに入れ替える。
    this.logout(previous);

    const sessionToken = createToken();
    this.db
      .prepare('INSERT INTO sessions VALUES (?, ?, ?)')
      .run(hash(sessionToken), userID, this.now() + SESSION_TTL);

    return sessionToken;
  }

  invalidateCeremony(ceremonyToken?: string) {
    if (!ceremonyToken) return;

    this.db
      .prepare('DELETE FROM ceremonies WHERE token_hash=?')
      .run(hash(ceremonyToken));
  }

  private saveCeremony(
    ceremony: Omit<Ceremony, 'expires_at'>,
    previous?: string,
  ) {
    this.cleanup();

    // 同じブラウザでやり直した場合、直前のチャレンジを使えなくする。
    this.invalidateCeremony(previous);

    const ceremonyToken = createToken();
    this.db
      .prepare('INSERT INTO ceremonies VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(
        hash(ceremonyToken),
        ceremony.kind,
        ceremony.challenge,
        ceremony.user_id,
        ceremony.username,
        ceremony.session_hash,
        this.now() + CHALLENGE_TTL,
      );

    return ceremonyToken;
  }

  private consumeCeremony(
    ceremonyToken: string | undefined,
    kind: Ceremony['kind'],
    session?: string,
  ) {
    if (!ceremonyToken)
      throw new AuthError(
        'CEREMONY_MISSING',
        'チャレンジがありません。使用済みの場合は再送を拒否します。',
      );

    // 非同期の検証より先に、取得と削除を1つのSQLで行う。
    // 並行する再送を防ぎ、検証に失敗したチャレンジも再利用させない。
    const ceremony = this.db
      .prepare('DELETE FROM ceremonies WHERE token_hash=? RETURNING *')
      .get(hash(ceremonyToken)) as Ceremony | undefined;

    if (!ceremony)
      throw new AuthError(
        'CEREMONY_USED',
        'チャレンジは使用済み、または存在しません。',
      );

    if (ceremony.expires_at <= this.now())
      throw new AuthError(
        'CEREMONY_EXPIRED',
        'チャレンジの有効期限が切れています。',
      );

    if (ceremony.kind !== kind)
      throw new AuthError('CEREMONY_KIND', '処理の種類が一致しません。');

    // 追加登録は、開始したときと同じセッション・同じ所有者に限る。
    if (
      kind === 'add' &&
      (ceremony.session_hash !== hash(session ?? '') ||
        this.requireSession(session).id !== ceremony.user_id)
    ) {
      throw new AuthError(
        'SESSION_MISMATCH',
        '登録を開始したログイン状態と一致しません。',
        401,
      );
    }

    return ceremony;
  }

  private requireAvailableUsername(username: string) {
    const existingUser = this.db
      .prepare('SELECT 1 FROM users WHERE username=?')
      .get(username);

    if (existingUser) {
      throw new AuthError(
        'USERNAME_TAKEN',
        'このユーザー名は使用されています。',
        409,
      );
    }
  }

  async registrationOptions(
    username: unknown,
    addingPasskey: boolean,
    session?: string,
    previous?: string,
  ) {
    // 新規登録ではIDだけを予約し、応答の検証が成功するまでユーザーを保存しない。
    let user: Pick<User, 'id' | 'username'>;
    if (addingPasskey) user = this.requireSession(session);
    else {
      if (
        typeof username !== 'string' ||
        !/^[a-zA-Z0-9_-]{3,32}$/.test(username)
      ) {
        throw new AuthError(
          'USERNAME_INVALID',
          'ユーザー名は英数字・_・-の3〜32文字で指定してください。',
        );
      }
      this.requireAvailableUsername(username);

      user = { id: createToken(), username };
    }
    const config = configuration();

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userName: user.username,
      userID: new Uint8Array(Buffer.from(user.id, 'base64url')),
      attestationType: 'none',
      timeout: CHALLENGE_TTL,
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      excludeCredentials: addingPasskey
        ? this.list(user.id).map((credential) => ({
            id: credential.id,
            transports: credential.transports,
          }))
        : [],
    });

    // ブラウザへ渡すchallengeと、HttpOnly Cookieで戻るトークンを対応付ける。
    const ceremony = this.saveCeremony(
      {
        kind: addingPasskey ? 'add' : 'register',
        challenge: options.challenge,
        user_id: user.id,
        username: user.username,
        session_hash: addingPasskey ? hash(session!) : null,
      },
      previous,
    );

    return { options, ceremony };
  }

  async authenticationOptions(previous?: string) {
    // credentialを限定せず、認証器に保存されたパスキーを利用者に選んでもらう。
    const options = await generateAuthenticationOptions({
      rpID: configuration().rpID,
      userVerification: 'required',
      allowCredentials: [],
      timeout: CHALLENGE_TTL,
    });

    // ブラウザへ渡すchallengeと、HttpOnly Cookieで戻るトークンを対応付ける。
    const ceremony = this.saveCeremony(
      {
        kind: 'authenticate',
        challenge: options.challenge,
        user_id: null,
        username: null,
        session_hash: null,
      },
      previous,
    );

    return { options, ceremony };
  }

  async register(
    response: RegistrationResponseJSON,
    addingPasskey: boolean,
    ceremonyToken?: string,
    session?: string,
    trace: Trace[] = [],
  ) {
    const ceremony = this.consumeCeremony(
      ceremonyToken,
      addingPasskey ? 'add' : 'register',
      session,
    );
    this.traceConsumed(trace, ceremony);

    // ブラウザが返した内容を信用せず、保存した期待値と照合する。
    const config = configuration();
    const result = await this.verify(() =>
      verifyRegistrationResponse({
        response,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: true,
        requireUserPresence: true,
        supportedAlgorithmIDs: [-7, -257],
      }),
    );

    if (!result.verified || !result.registrationInfo)
      throw new AuthError(
        'REGISTRATION_REJECTED',
        '登録レスポンスを検証できません。',
      );

    const info = result.registrationInfo;
    this.traceVerified(trace, 'register');

    // ユーザー・公開鍵・初回セッションを一括保存し、途中失敗で片方だけ残さない。
    const newSession = transaction(this.db, () => {
      // 非同期検証を待つ間のログアウトや、同名ユーザーの作成を再確認する。
      if (addingPasskey) this.requireSession(session);
      else {
        this.requireAvailableUsername(ceremony.username!);
        this.db
          .prepare('INSERT INTO users VALUES (?, ?, ?)')
          .run(ceremony.user_id!, ceremony.username!, this.now());
      }

      this.db
        .prepare(
          `INSERT INTO credentials
        (id,user_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,?,?,?,?,?,?,?)`,
        )
        .run(
          info.credential.id,
          ceremony.user_id!,
          info.credential.publicKey,
          info.credential.counter,
          JSON.stringify(info.credential.transports ?? []),
          info.credentialDeviceType,
          Number(info.credentialBackedUp),
          this.now(),
        );

      // 追加登録では現在のセッションをそのまま使う。
      return addingPasskey
        ? undefined
        : this.issueSession(ceremony.user_id!, session);
    });

    trace.push({
      side: 'server',
      action: 'DB commit',
      purpose: 'ユーザーと公開鍵を一括保存。秘密鍵は受信・保存しない。',
      result: 'passed',
    });

    return { session: newSession };
  }

  async authenticate(
    response: AuthenticationResponseJSON,
    ceremonyToken?: string,
    previousSession?: string,
    trace: Trace[] = [],
  ) {
    const ceremony = this.consumeCeremony(ceremonyToken, 'authenticate');
    this.traceConsumed(trace, ceremony);

    const stored = this.db
      .prepare('SELECT * FROM credentials WHERE id=?')
      .get(response.id) as StoredCredential | undefined;

    if (!stored)
      throw new AuthError(
        'CREDENTIAL_UNKNOWN',
        '登録済みのパスキーを確認できません。',
      );

    // ユーザー名を受け取らない認証なので、userHandleと保存済みcredentialの所有者を照合する。
    if (
      !response.response.userHandle ||
      response.response.userHandle !== stored.user_id
    ) {
      throw new AuthError(
        'USER_HANDLE_MISMATCH',
        'パスキーの所有者とuserHandleが一致しません。',
      );
    }
    const config = configuration();
    const result = await this.verify(() =>
      verifyAuthenticationResponse({
        response,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: true,
        credential: {
          id: stored.id,
          publicKey: new Uint8Array(stored.public_key),
          counter: stored.counter,
          transports: JSON.parse(stored.transports) as AuthenticatorTransport[],
        },
      }),
    );

    if (!result.verified)
      throw new AuthError(
        'AUTHENTICATION_REJECTED',
        '署名の検証に失敗しました。',
      );

    this.traceVerified(trace, 'authenticate');
    const info = result.authenticationInfo;

    const newSession = transaction(this.db, () => {
      // 読み取り時のカウンターと一致するときだけ更新する。
      // 別の認証が先に成功した場合、古い応答で新しい値を上書きしない。
      const updated = this.db
        .prepare(
          `UPDATE credentials SET counter=?, backed_up=?, device_type=?, last_used_at=?
        WHERE id=? AND counter=?`,
        )
        .run(
          info.newCounter,
          Number(info.credentialBackedUp),
          info.credentialDeviceType,
          this.now(),
          stored.id,
          stored.counter,
        );

      if (updated.changes !== 1)
        throw new AuthError(
          'COUNTER_RACE',
          '認証状態が更新されました。再度認証してください。',
        );

      // カウンター更新とセッション発行は、両方とも成功したときだけ確定する。
      return this.issueSession(stored.user_id, previousSession);
    });

    trace.push({
      side: 'server',
      action: 'セッション発行',
      purpose:
        'カウンター更新と同じトランザクションで、推測困難なセッションを保存。Cookie値は表示しない。',
      result: 'passed',
      details: {
        previousCounter: stored.counter,
        newCounter: info.newCounter,
        userVerified: info.userVerified,
      },
    });

    return { session: newSession };
  }

  private async verify<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      // ライブラリの詳細エラーは開発用に残し、通常の応答は共通メッセージにする。
      throw new AuthError(
        'WEBAUTHN_REJECTED',
        'WebAuthnレスポンスの検証に失敗しました。',
        400,
        error instanceof Error
          ? error.message.slice(0, 300)
          : 'Unknown verification error',
      );
    }
  }

  private traceConsumed(trace: Trace[], ceremony: Ceremony) {
    trace.push({
      side: 'server',
      action: 'チャレンジの消費',
      purpose:
        '期限・用途を確認し、検証前にDBから削除して再送と並行利用を防ぐ。',
      result: 'passed',
      details: {
        expectedChallenge: ceremony.challenge,
        expectedOrigin: configuration().origin,
        expectedRPID: configuration().rpID,
      },
    });
  }

  private traceVerified(trace: Trace[], kind: 'register' | 'authenticate') {
    trace.push({
      side: 'server',
      action: 'SimpleWebAuthnによる検証',
      result: 'passed',
      purpose:
        kind === 'authenticate'
          ? '保存済み公開鍵で署名を検証。challenge・Origin・rpIdHash・UP・UV・カウンターを確認。'
          : 'challenge・Origin・rpIdHash・UP・UV・認証器データ・公開鍵の形式を確認。attestation=noneは認証器の出自を保証しない。',
    });
  }
}
