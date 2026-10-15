'use client';

import { useLab } from './lab-context';

export function TraceView() {
  const lab = useLab();
  return (
    <section className="panel">
      <div className="account-head">
        <h2>
          通信と検証の記録 <span className="count">{lab.events.length}</span>
        </h2>
        <button className="secondary" onClick={lab.clear}>
          記録を消去
        </button>
      </div>
      <p className="muted">
        青: ブラウザの観測（未検証の入力を含む） / 緑:
        サーバーの処理結果。JSONにはchallenge、ユーザー名、Credential
        IDが含まれます。共有前に確認してください。Cookie・セッション識別子・秘密鍵は記録しません。
      </p>
      {!lab.events.length && (
        <p className="empty">
          まだ記録がありません。アカウントを作成するか、正常な認証を実行してください。
        </p>
      )}
      <ol className="events">
        {lab.events.map((event, index) => (
          <li className={`event ${event.side}`} key={index}>
            <div className="event-title">
              <span className="badge">
                {event.side === 'browser' ? 'BROWSER' : 'SERVER'}
              </span>
              <b>{event.action}</b>
              <span className={`result ${event.result}`}>{event.result}</span>
              <time>{event.time}</time>
            </div>
            <p>{event.purpose}</p>
            {event.details !== undefined && (
              <details>
                <summary>JSON / 詳細を表示</summary>
                <pre>{JSON.stringify(event.details, null, 2)}</pre>
              </details>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
