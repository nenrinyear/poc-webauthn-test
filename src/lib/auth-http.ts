import { NextResponse } from 'next/server';
import { AuthError } from './auth';
import { configuration } from './config';

const MAX_BODY_BYTES = 64 * 1024;

export const cookieOptions = () => ({
  httpOnly: true,
  sameSite: 'strict' as const,
  secure: configuration().secure,
  path: '/',
});
export function json(value: unknown, status = 200) {
  return NextResponse.json(value, {
    status,
    headers: { 'Cache-Control': 'no-store' },
  });
}
export async function readJsonBody(
  request: Request,
): Promise<Record<string, unknown>> {
  if (
    !request.headers
      .get('content-type')
      ?.toLowerCase()
      .startsWith('application/json')
  ) {
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
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new AuthError('BODY_TOO_LARGE', 'リクエストが大きすぎます。', 413);
    }
    chunks.push(value);
  }
  let result: unknown;
  try {
    result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new AuthError('JSON_INVALID', 'JSONが不正です。');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result))
    throw new AuthError('JSON_INVALID', 'JSONオブジェクトが必要です。');
  return result as Record<string, unknown>;
}
