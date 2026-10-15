import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/server';
import { AuthService, AuthError, hash } from '../src/lib/auth';
import { openDatabase } from '../src/lib/db';
import { CHALLENGE_TTL, SESSION_TTL } from '../src/lib/config';

// 認証器の代わりに鍵と署名を作る処理はテスト専用。アプリ本体の検証はSimpleWebAuthnに委ねる。
const b64 = (data: Uint8Array | string) =>
  Buffer.from(data).toString('base64url');
const sha = (data: Uint8Array | string) =>
  createHash('sha256').update(data).digest();
// P-256の公開鍵を、WebAuthnで扱うCOSE形式へ変換する。
function keyPair() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
      [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
    ]),
  );
  return { privateKey: pair.privateKey, cose, id: b64(randomBytes(32)) };
}

type FixtureKey = ReturnType<typeof keyPair>;

// RP IDのハッシュに、フラグ1バイトとカウンター4バイトを続ける。
function authData(rp = 'localhost', flags = 0x05, counter = 1) {
  const tail = Buffer.alloc(5);
  tail[0] = flags;
  tail.writeUInt32BE(counter, 1);
  return Buffer.concat([sha(rp), tail]);
}

// 正常な登録応答を基本に、changesで拒否条件だけを差し替える。
function registration(
  options: PublicKeyCredentialCreationOptionsJSON,
  key: FixtureKey,
  changes: {
    challenge?: string;
    origin?: string;
    rp?: string;
    flags?: number;
  } = {},
): RegistrationResponseJSON {
  const id = Buffer.from(key.id, 'base64url');
  const length = Buffer.alloc(2);
  length.writeUInt16BE(id.length);
  const data = Buffer.concat([
    authData(changes.rp, changes.flags ?? 0x45, 0),
    Buffer.alloc(16),
    length,
    id,
    key.cose,
  ]);
  return {
    id: key.id,
    rawId: key.id,
    type: 'public-key',
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      clientDataJSON: b64(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: changes.challenge ?? options.challenge,
          origin: changes.origin ?? 'http://localhost:3000',
          crossOrigin: false,
        }),
      ),
      attestationObject: b64(
        isoCBOR.encode(
          new Map<string, string | Uint8Array | Map<string, never>>([
            ['fmt', 'none'],
            ['attStmt', new Map<string, never>()],
            ['authData', new Uint8Array(data)],
          ]),
        ),
      ),
      transports: ['internal'],
    },
  };
}

// 改変した内容に対して署名し、署名破損と各検証条件の失敗を区別する。
function assertion(
  challenge: string,
  userID: string,
  key: FixtureKey,
  changes: {
    origin?: string;
    rp?: string;
    flags?: number;
    counter?: number;
    userHandle?: string | null;
    type?: string;
    signingKey?: KeyObject;
  } = {},
): AuthenticationResponseJSON {
  const client = Buffer.from(
    JSON.stringify({
      type: changes.type ?? 'webauthn.get',
      challenge,
      origin: changes.origin ?? 'http://localhost:3000',
      crossOrigin: false,
    }),
  );
  const data = authData(changes.rp, changes.flags, changes.counter);
  const signature = sign(
    'sha256',
    Buffer.concat([data, sha(client)]),
    changes.signingKey ?? key.privateKey,
  );
  return {
    id: key.id,
    rawId: key.id,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64(client),
      authenticatorData: b64(data),
      signature: b64(signature),
      userHandle:
        changes.userHandle === undefined
          ? userID
          : (changes.userHandle ?? undefined),
    },
  };
}

// 時計を注入し、実際に待たずにチャレンジとセッションの期限を検証する。
function setup() {
  const db = openDatabase(':memory:');
  let clock = Date.now();
  return {
    db,
    service: new AuthService(db, () => clock),
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

async function account(service: AuthService, name = 'researcher') {
  const key = keyPair();
  const start = await service.registrationOptions(name, false);
  const result = await service.register(
    registration(start.options, key),
    false,
    start.ceremony,
  );
  return { key, session: result.session!, userID: start.options.user.id };
}

async function rejectsReason(work: Promise<unknown>, pattern: RegExp) {
  await assert.rejects(
    work,
    (error) =>
      error instanceof AuthError && pattern.test(error.detail ?? error.message),
  );
}
const count = (
  db: ReturnType<typeof openDatabase>,
  table: 'users' | 'credentials' | 'sessions',
) =>
  (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;

test('registration is staged; verified registration atomically creates user, credential and session', async () => {
  const { db, service } = setup();
  const start = await service.registrationOptions('researcher', false);
  assert.equal(count(db, 'users'), 0);
  assert.equal(count(db, 'credentials'), 0);
  assert.equal(start.options.authenticatorSelection?.residentKey, 'required');
  assert.equal(
    start.options.authenticatorSelection?.userVerification,
    'required',
  );
  const key = keyPair();
  const result = await service.register(
    registration(start.options, key),
    false,
    start.ceremony,
  );
  assert.equal(service.session(result.session)?.username, 'researcher');
  assert.equal(count(db, 'users'), 1);
  assert.equal(count(db, 'credentials'), 1);
  assert.equal(count(db, 'sessions'), 1);
  assert.equal(
    db.prepare('SELECT token_hash FROM sessions').get()?.token_hash,
    hash(result.session!),
  );
  assert.equal(service.list(start.options.user.id)[0].counter, 0);
  assert.ok(
    !JSON.stringify(service.list(start.options.user.id)).includes('public_key'),
  );
  db.close();
});
for (const [label, change, pattern] of [
  ['challenge', { challenge: 'wrong' }, /challenge/i],
  ['Origin', { origin: 'https://evil.example' }, /origin/i],
  ['RP ID', { rp: 'evil.example' }, /RP ID|RPID|rpIdHash/i],
  ['UV', { flags: 0x41 }, /user verification/i],
  ['UP', { flags: 0x44 }, /user presence|User not present/i],
] as const) {
  test(`registration rejects wrong ${label} and leaves no account, key or session`, async () => {
    const { db, service } = setup();
    const start = await service.registrationOptions('researcher', false);
    await rejectsReason(
      service.register(
        registration(start.options, keyPair(), change),
        false,
        start.ceremony,
      ),
      pattern,
    );
    assert.equal(count(db, 'users'), 0);
    assert.equal(count(db, 'credentials'), 0);
    assert.equal(count(db, 'sessions'), 0);
    await assert.rejects(
      service.register(
        registration(start.options, keyPair()),
        false,
        start.ceremony,
      ),
      { code: 'CEREMONY_USED' },
    );
    db.close();
  });
}
test('discoverable login succeeds, updates counter and rotates old session; replay is rejected', async () => {
  const { db, service } = setup();
  const a = await account(service);
  const start = await service.authenticationOptions();
  assert.deepEqual(start.options.allowCredentials, []);
  const response = assertion(start.options.challenge, a.userID, a.key);
  const result = await service.authenticate(
    response,
    start.ceremony,
    a.session,
  );
  assert.equal(service.session(result.session)?.id, a.userID);
  assert.equal(service.session(a.session), undefined);
  assert.equal(service.list(a.userID)[0].counter, 1);
  const before = count(db, 'sessions');
  await assert.rejects(service.authenticate(response, start.ceremony), {
    code: 'CEREMONY_USED',
  });
  assert.equal(count(db, 'sessions'), before);
  db.close();
});
for (const [label, changes, pattern] of [
  ['Origin (correct signature)', { origin: 'https://evil.example' }, /origin/i],
  ['RP ID (correct signature)', { rp: 'evil.example' }, /RP ID|RPID|rpIdHash/i],
  ['UV (correct signature)', { flags: 0x01 }, /user verification/i],
  [
    'UP (correct signature)',
    { flags: 0x04 },
    /user presence|User not present/i,
  ],
  ['type (correct signature)', { type: 'webauthn.create' }, /type/i],
  ['counter rollback', { counter: 0 }, /counter/i],
  ['mismatched userHandle', { userHandle: 'another-user' }, /userHandle/i],
  ['missing userHandle', { userHandle: null }, /userHandle/i],
  [
    'signature with a different key',
    { signingKey: keyPair().privateKey },
    /署名/,
  ],
] as const) {
  test(`authentication rejects ${label}, without session issuance or counter mutation`, async () => {
    const { db, service } = setup();
    const a = await account(service);
    db.prepare('UPDATE credentials SET counter=1').run();
    const start = await service.authenticationOptions();
    const response = assertion(start.options.challenge, a.userID, a.key, {
      counter: 2,
      ...changes,
    });
    await rejectsReason(
      service.authenticate(response, start.ceremony),
      pattern,
    );
    assert.equal(count(db, 'sessions'), 1);
    assert.equal(service.list(a.userID)[0].counter, 1);
    await assert.rejects(service.authenticate(response, start.ceremony), {
      code: 'CEREMONY_USED',
    });
    db.close();
  });
}
test('a response signed for an old challenge is rejected by a fresh ceremony', async () => {
  const { db, service } = setup();
  const a = await account(service);
  const first = await service.authenticationOptions();
  const old = assertion(first.options.challenge, a.userID, a.key);
  const fresh = await service.authenticationOptions(first.ceremony);
  await rejectsReason(service.authenticate(old, fresh.ceremony), /challenge/i);
  assert.equal(count(db, 'sessions'), 1);
  assert.equal(service.list(a.userID)[0].counter, 0);
  db.close();
});
test('challenge expiry, browser binding and ceremony type are enforced', async () => {
  const { db, service, advance } = setup();
  const a = await account(service);
  const start = await service.authenticationOptions();
  const response = assertion(start.options.challenge, a.userID, a.key);
  await assert.rejects(service.authenticate(response, 'other-browser-token'), {
    code: 'CEREMONY_USED',
  });
  advance(CHALLENGE_TTL);
  await assert.rejects(service.authenticate(response, start.ceremony), {
    code: 'CEREMONY_EXPIRED',
  });
  const wrongKind = await service.registrationOptions('seconduser', false);
  await assert.rejects(service.authenticate(response, wrongKind.ceremony), {
    code: 'CEREMONY_KIND',
  });
  db.close();
});
test('only the same authenticated session may add credentials; logout invalidates pending additions', async () => {
  const { db, service } = setup();
  const a = await account(service);
  await assert.rejects(service.registrationOptions('', true), {
    code: 'SESSION_REQUIRED',
  });
  const start = await service.registrationOptions('', true, a.session);
  assert.equal(start.options.user.id, a.userID);
  assert.equal(start.options.excludeCredentials?.[0].id, a.key.id);
  const key = keyPair();
  await assert.rejects(
    service.register(
      registration(start.options, key),
      true,
      start.ceremony,
      'wrong-session',
    ),
    AuthError,
  );
  assert.equal(count(db, 'credentials'), 1);
  const valid = await service.registrationOptions('', true, a.session);
  await service.register(
    registration(valid.options, key),
    true,
    valid.ceremony,
    a.session,
  );
  assert.equal(count(db, 'credentials'), 2);
  const pending = await service.registrationOptions('', true, a.session);
  service.logout(a.session);
  assert.equal(service.session(a.session), undefined);
  await assert.rejects(
    service.register(
      registration(pending.options, keyPair()),
      true,
      pending.ceremony,
      a.session,
    ),
    AuthError,
  );
  assert.equal(count(db, 'credentials'), 2);
  db.close();
});
test('concurrent duplicate username registration permits only one complete account', async () => {
  const { db, service } = setup();
  const one = await service.registrationOptions('same_name', false);
  const two = await service.registrationOptions('same_name', false);
  const results = await Promise.allSettled([
    service.register(registration(one.options, keyPair()), false, one.ceremony),
    service.register(registration(two.options, keyPair()), false, two.ceremony),
  ]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(count(db, 'users'), 1);
  assert.equal(count(db, 'credentials'), 1);
  assert.equal(count(db, 'sessions'), 1);
  db.close();
});
test('duplicate credential insertion rolls back creation of a new user', async () => {
  const { db, service } = setup();
  const a = await account(service);
  const start = await service.registrationOptions('new_name', false);
  await assert.rejects(
    service.register(registration(start.options, a.key), false, start.ceremony),
  );
  assert.equal(count(db, 'users'), 1);
  assert.equal(count(db, 'credentials'), 1);
  assert.equal(count(db, 'sessions'), 1);
  db.close();
});
test('parallel submissions of the same challenge succeed at most once', async () => {
  const { db, service } = setup();
  const a = await account(service);
  const start = await service.authenticationOptions();
  const response = assertion(start.options.challenge, a.userID, a.key);
  const results = await Promise.allSettled([
    service.authenticate(response, start.ceremony),
    service.authenticate(response, start.ceremony),
  ]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(service.list(a.userID)[0].counter, 1);
  db.close();
});
test('concurrent different challenges cannot overwrite an incremented counter', async () => {
  const { db, service } = setup();
  const a = await account(service);
  const one = await service.authenticationOptions();
  const two = await service.authenticationOptions();
  const results = await Promise.allSettled([
    service.authenticate(
      assertion(one.options.challenge, a.userID, a.key),
      one.ceremony,
    ),
    service.authenticate(
      assertion(two.options.challenge, a.userID, a.key),
      two.ceremony,
    ),
  ]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(service.list(a.userID)[0].counter, 1);
  db.close();
});
test('zero counters remain supported; session expires at the server deadline', async () => {
  const { db, service, advance } = setup();
  const a = await account(service);
  const start = await service.authenticationOptions();
  const result = await service.authenticate(
    assertion(start.options.challenge, a.userID, a.key, { counter: 0 }),
    start.ceremony,
  );
  assert.ok(service.session(result.session));
  advance(SESSION_TTL);
  assert.equal(service.session(result.session), undefined);
  await assert.rejects(service.registrationOptions('', true, result.session), {
    code: 'SESSION_REQUIRED',
  });
  db.close();
});
test('SQLite persists users, credentials and sessions across reopening', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'webauthn-lab-'));
  const path = join(dir, 'test.sqlite');
  let db = openDatabase(path);
  try {
    const a = await account(new AuthService(db));
    db.close();
    db = openDatabase(path);
    const service = new AuthService(db);
    assert.equal(service.session(a.session)?.id, a.userID);
    const start = await service.authenticationOptions();
    await service.authenticate(
      assertion(start.options.challenge, a.userID, a.key),
      start.ceremony,
    );
    assert.equal(service.list(a.userID)[0].counter, 1);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('HTTP endpoints enforce Origin, content type, body limits and session authorization', async () => {
  const { NextRequest } = await import('next/server');
  const { POST, GET } = await import('../src/app/api/[...path]/route');
  const db = openDatabase(':memory:');
  const globalDB = globalThis as typeof globalThis & { labDB?: typeof db };
  globalDB.labDB = db;
  const context = (path: string) => ({
    params: Promise.resolve({ path: path.split('/') }),
  });
  const request = (
    path: string,
    body: string,
    headers: Record<string, string> = {},
  ) =>
    new NextRequest(`http://localhost:3000/api/${path}`, {
      method: 'POST',
      headers: {
        origin: 'http://localhost:3000',
        'content-type': 'application/json',
        ...headers,
      },
      body,
    });
  try {
    const denied = await POST(
      request('authenticate/options', '{}', { origin: 'https://evil.example' }),
      context('authenticate/options'),
    );
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).code, 'REQUEST_ORIGIN');
    assert.equal(
      (
        await POST(
          request('authenticate/options', '{}', {
            'content-type': 'text/plain',
          }),
          context('authenticate/options'),
        )
      ).status,
      415,
    );
    assert.equal(
      (
        await POST(
          request('authenticate/options', 'bad json'),
          context('authenticate/options'),
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await POST(
          request(
            'authenticate/options',
            JSON.stringify({ long: 'x'.repeat(65536) }),
          ),
          context('authenticate/options'),
        )
      ).status,
      413,
    );
    assert.equal(
      (
        await POST(
          request('passkeys/options', '{}'),
          context('passkeys/options'),
        )
      ).status,
      401,
    );
    const me = await GET(
      new NextRequest('http://localhost:3000/api/me'),
      context('me'),
    );
    assert.equal(me.status, 401);
    assert.equal(me.headers.get('cache-control'), 'no-store');
    assert.equal(
      (
        await POST(
          request('authenticate/verify', '{}'),
          context('authenticate/verify'),
        )
      ).status,
      400,
    );
    assert.equal(
      (await POST(request('unknown', '{}'), context('unknown'))).status,
      404,
    );
  } finally {
    delete globalDB.labDB;
    db.close();
  }
});
test('HTTP registration, login and logout use HttpOnly cookies and never expose session tokens in JSON', async () => {
  const { NextRequest } = await import('next/server');
  const { POST, GET } = await import('../src/app/api/[...path]/route');
  const db = openDatabase(':memory:');
  const globalDB = globalThis as typeof globalThis & { labDB?: typeof db };
  globalDB.labDB = db;
  const oldEnv = process.env.NODE_ENV;
  Object.assign(process.env, { NODE_ENV: 'development' });
  const context = (path: string) => ({
    params: Promise.resolve({ path: path.split('/') }),
  });
  const jar = new Map<string, string>();
  async function post(path: string, body: unknown) {
    const result = await POST(
      new NextRequest(`http://localhost:3000/api/${path}`, {
        method: 'POST',
        headers: {
          origin: 'http://localhost:3000',
          'content-type': 'application/json',
          cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
        },
        body: JSON.stringify(body),
      }),
      context(path),
    );
    for (const c of result.cookies.getAll()) {
      if (c.maxAge === 0) jar.delete(c.name);
      else jar.set(c.name, c.value);
      assert.ok(result.headers.get('set-cookie')?.includes('HttpOnly'));
      assert.ok(result.headers.get('set-cookie')?.includes('SameSite=strict'));
    }
    const data = await result.json();
    for (const value of jar.values())
      assert.ok(!JSON.stringify(data).includes(value));
    assert.equal(result.headers.get('cache-control'), 'no-store');
    return { result, data };
  }
  try {
    const start = await post('register/options', { username: 'http_user' });
    assert.equal(start.result.status, 200);
    assert.ok(start.data.trace);
    const key = keyPair();
    const registered = await post('register/verify', {
      credential: registration(start.data.options, key),
    });
    assert.equal(registered.result.status, 200);
    assert.ok(jar.has('lab_session'));
    assert.ok(!jar.has('lab_ceremony'));
    const firstToken = jar.get('lab_session')!;
    const me = await GET(
      new NextRequest('http://localhost:3000/api/me', {
        headers: { cookie: `lab_session=${firstToken}` },
      }),
      context('me'),
    );
    const profile = await me.json();
    assert.equal(profile.user.username, 'http_user');
    assert.equal(profile.passkeys.length, 1);
    assert.ok(!JSON.stringify(profile).includes('public_key'));
    await post('logout', {});
    assert.equal(jar.size, 0);
    const loginStart = await post('authenticate/options', {});
    const credential = assertion(
      loginStart.data.options.challenge,
      start.data.options.user.id,
      key,
    );
    const authenticated = await post('authenticate/verify', { credential });
    assert.equal(authenticated.result.status, 200);
    assert.ok(jar.has('lab_session'));
    assert.notEqual(jar.get('lab_session'), firstToken);
    const replay = await post('authenticate/verify', { credential });
    assert.equal(replay.result.status, 400);
    assert.equal(replay.data.code, 'CEREMONY_MISSING');
    const loggedIn = jar.get('lab_session');
    Object.assign(process.env, { NODE_ENV: 'production' });
    const productionStart = await post('authenticate/options', {});
    assert.ok(!('trace' in productionStart.data));
    const bad = assertion('wrong-challenge', start.data.options.user.id, key);
    const productionRejected = await post('authenticate/verify', {
      credential: bad,
    });
    assert.equal(productionRejected.result.status, 400);
    assert.ok(!('trace' in productionRejected.data));
    assert.ok(
      !JSON.stringify(productionRejected.data).includes('wrong-challenge'),
    );
    assert.equal(jar.get('lab_session'), loggedIn);
    const logout = await post('logout', {});
    assert.equal(logout.result.status, 200);
    assert.equal(count(db, 'sessions'), 0);
  } finally {
    if (oldEnv === undefined) Reflect.deleteProperty(process.env, 'NODE_ENV');
    else Object.assign(process.env, { NODE_ENV: oldEnv });
    delete globalDB.labDB;
    db.close();
  }
});
