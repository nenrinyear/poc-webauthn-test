import type { Metadata } from 'next';
import Link from 'next/link';
import { LabProvider } from '@/components/lab-context';
import './globals.css';
export const metadata: Metadata = {
  title: 'WebAuthn Research Lab',
  description:
    'パスキーの登録・認証とサーバー検証を観察する研究用アプリケーション',
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ja">
      <body>
        <LabProvider>
          <header>
            <Link className="brand" href="/">
              ◈{' '}
              <span>
                WebAuthn <b>Research Lab</b>
              </span>
            </Link>
            <nav aria-label="メインナビゲーション">
              <Link href="/register">アカウント作成</Link>
              <Link href="/login">ログイン</Link>
              <Link href="/account">ユーザー情報</Link>
              {process.env.NODE_ENV === 'development' && (
                <Link href="/lab">開発・検証</Link>
              )}
            </nav>
          </header>
          <main>{children}</main>
        </LabProvider>
      </body>
    </html>
  );
}
