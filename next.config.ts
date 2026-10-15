import type { NextConfig } from 'next';
const config: NextConfig = {
  serverExternalPackages: ['@simplewebauthn/server'],
  async headers() {
    return [{ source: '/:path*', headers: [
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'Referrer-Policy', value: 'no-referrer' },
      { key: 'Permissions-Policy', value: 'publickey-credentials-create=(self), publickey-credentials-get=(self)' },
    ] }];
  },
};
export default config;
