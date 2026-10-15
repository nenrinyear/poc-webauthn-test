import { NextRequest, NextResponse } from 'next/server';
import { AuthService, AuthError, hash, type Trace } from '@/lib/auth';
import { database } from '@/lib/db';
import { CEREMONY_COOKIE, SESSION_COOKIE, CHALLENGE_TTL, SESSION_TTL, configuration, isDevelopment } from '@/lib/config';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const paths = ['register/options', 'register/verify', 'passkeys/options', 'passkeys/verify', 'authenticate/options', 'authenticate/verify', 'logout'];
const cookieOptions = () => ({ httpOnly: true, sameSite: 'strict' as const, secure: configuration().secure, path: '/' });
function json(value: unknown, status = 200) {
  return NextResponse.json(value, { status, headers: { 'Cache-Control': 'no-store' } });
}
async function bodyOf(request: Request): Promise<Record<string, unknown>> {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new AuthError('CONTENT_TYPE', 'application/jsonが必要です。', 415);
  }
  const reader = request.body?.getReader();
  if (!reader) throw new AuthError('BODY_MISSING', 'JSONボディが必要です。');
  let size = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 64 * 1024) { await reader.cancel(); throw new AuthError('BODY_TOO_LARGE', 'リクエストが大きすぎます。', 413); }
    chunks.push(value);
  }
  let result: unknown;
  try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AuthError('JSON_INVALID', 'JSONが不正です。'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new AuthError('JSON_INVALID', 'JSONオブジェクトが必要です。');
  return result as Record<string, unknown>;
}
export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join('/');
  if (path !== 'me') return json({ error: 'Not found' }, 404);
  const service = new AuthService(database());
  const user = service.session(request.cookies.get(SESSION_COOKIE)?.value);
  if (!user) return json({ user: null }, 401);
  return json({ user: { username: user.username, createdAt: user.created_at }, passkeys: service.list(user.id) });
}
export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join('/');
  if (!paths.includes(path)) return json({ error: 'Not found' }, 404);
  const trace: Trace[] = [];
  const service = new AuthService(database());
  const session = request.cookies.get(SESSION_COOKIE)?.value;
  const ceremony = request.cookies.get(CEREMONY_COOKIE)?.value;
  const verify = path.endsWith('/verify');
  try {
    if (request.headers.get('origin') !== configuration().origin) {
      throw new AuthError('REQUEST_ORIGIN', 'HTTP Originが期待値と一致しません。', 403);
    }
    const body = await bodyOf(request);
    let response: NextResponse;
    if (path.endsWith('/options')) {
      const result = path === 'authenticate/options' ? await service.authenticationOptions(ceremony) :
        await service.registrationOptions(body.username, path.startsWith('passkeys/'), session, ceremony);
      trace.push({ side: 'server', action: 'options生成', purpose: '暗号学的乱数のchallengeを生成。ブラウザとHttpOnly Cookieで紐付け、DBに2分間保存。', result: 'passed',
        details: { rpID: configuration().rpID, origin: configuration().origin, expiresInSeconds: CHALLENGE_TTL / 1000, userVerification: 'required' } });
      response = json({ options: result.options, ...(isDevelopment() ? { trace } : {}) });
      response.cookies.set(CEREMONY_COOKIE, result.ceremony, { ...cookieOptions(), maxAge: CHALLENGE_TTL / 1000 });
    } else if (verify) {
      const credential = body.credential;
      if (!credential || typeof credential !== 'object' || Array.isArray(credential) ||
          typeof (credential as { id?: unknown }).id !== 'string' ||
          !(credential as { response?: unknown }).response) {
        throw new AuthError('CREDENTIAL_INVALID', 'credentialの形式が不正です。');
      }
      const result = path === 'authenticate/verify' ?
        await service.authenticate(body.credential as AuthenticationResponseJSON, ceremony, session, trace) :
        await service.register(body.credential as RegistrationResponseJSON, path.startsWith('passkeys/'), ceremony, session, trace);
      response = json({ verified: true, ...(isDevelopment() ? { trace } : {}) });
      response.cookies.set(CEREMONY_COOKIE, '', { ...cookieOptions(), maxAge: 0 });
      if (result.session) response.cookies.set(SESSION_COOKIE, result.session, { ...cookieOptions(), maxAge: SESSION_TTL / 1000 });
    } else {
      service.logout(session);
      if (ceremony) service.db.prepare('DELETE FROM ceremonies WHERE token_hash=?').run(hash(ceremony));
      response = json({ ok: true });
      response.cookies.set(SESSION_COOKIE, '', { ...cookieOptions(), maxAge: 0 });
      response.cookies.set(CEREMONY_COOKIE, '', { ...cookieOptions(), maxAge: 0 });
    }
    return response;
  } catch (error) {
    const expected = error instanceof AuthError;
    const status = expected ? error.status : 500;
    const code = expected ? error.code : 'REQUEST_FAILED';
    const message = expected ? error.message : '処理を完了できませんでした。最初からやり直してください。';
    if (isDevelopment()) trace.push({ side: 'server', action: '処理拒否', purpose: '検証に失敗したため、今回の処理ではセッションを発行しない。', result: 'failed',
      details: { code, reason: expected ? (error.detail ?? error.message) : 'サーバー内部エラー' } });
    const response = json({ error: message, code, ...(isDevelopment() ? { trace } : {}) }, status);
    if (verify) {
      if (ceremony) service.db.prepare('DELETE FROM ceremonies WHERE token_hash=?').run(hash(ceremony));
      response.cookies.set(CEREMONY_COOKIE, '', { ...cookieOptions(), maxAge: 0 });
    }
    return response;
  }
}
