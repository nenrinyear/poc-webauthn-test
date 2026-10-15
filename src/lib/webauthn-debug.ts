export type RejectionExperiment = 'replay' | 'challenge' | 'origin' | 'rpid';

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
export function decodeClientData(value: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64url(value)));
  } catch {
    return { error: 'clientDataJSONをデコードできません' };
  }
}
