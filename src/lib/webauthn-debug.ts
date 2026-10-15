export type RejectionExperiment = 'replay' | 'challenge' | 'origin' | 'rpid';

// WebAuthnのJSON形式で使うURL安全なBase64表現を、バイト列へ戻す。
export function decodeBase64url(value: string) {
  return Uint8Array.from(
    atob(value.replace(/-/g, '+').replace(/_/g, '/')),
    (c) => c.charCodeAt(0),
  );
}

export function encodeBase64url(value: string | Uint8Array) {
  const bytes =
    typeof value === 'string' ? new TextEncoder().encode(value) : value;

  return btoa(Array.from(bytes, (n) => String.fromCharCode(n)).join(''))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// 内容の表示・改変実験用のデコード。署名やOriginの正当性を検証する処理ではない。
export function decodeClientData(value: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64url(value)));
  } catch {
    return { error: 'clientDataJSONをデコードできません' };
  }
}
