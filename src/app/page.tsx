import Link from 'next/link';

export default function Home() {
  return (
    <section className="panel narrow">
      <h1>WebAuthn 検証</h1>
      <div className="actions">
        <Link className="button" href="/register">アカウント作成</Link>
        <Link className="button secondary" href="/login">ログイン</Link>
        <Link className="button secondary" href="/account">ユーザー情報</Link>
        {process.env.NODE_ENV === 'development' && (
          <Link className="button secondary" href="/lab">開発・検証</Link>
        )}
      </div>
    </section>
  );
}
