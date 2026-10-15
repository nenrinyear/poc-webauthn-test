export function configuration() {
  const origin = process.env.APP_ORIGIN ?? 'http://localhost:3000';
  const url = new URL(origin);
  if (url.origin !== origin || url.hostname !== 'localhost' || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('APP_ORIGIN must be an exact localhost origin, without a trailing slash');
  }
  return { origin, rpID: 'localhost', rpName: 'WebAuthn Research Lab', secure: url.protocol === 'https:' };
}
export const CHALLENGE_TTL = 2 * 60 * 1000;
export const SESSION_TTL = 8 * 60 * 60 * 1000;
export const SESSION_COOKIE = 'lab_session';
export const CEREMONY_COOKIE = 'lab_ceremony';
export const isDevelopment = () => process.env.NODE_ENV === 'development';
