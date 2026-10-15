# WebAuthn Research Lab

大学の研究活動向けに、パスキー登録・ユーザー名不要の認証・サーバー側セッションと、その検証過程を観察するローカル実験環境です。**本番運用可能な認証基盤ではありません。** 暗号処理とWebAuthn応答の検証はSimpleWebAuthnに委ねています。

## 環境構築と起動

- Node.js **22.13以上**（Node.js 24 LTSを推奨）。`node:sqlite`を使用するため、古いNode.jsでは起動できません。Node.jsの版によってSQLiteの実験的機能に関する警告が出ます。
- pnpm 12.10.1（`packageManager`参照）。依存関係は`pnpm-lock.yaml`に固定。
- WebAuthn対応ブラウザと、本人確認・discoverable credentialに対応した認証器。端末の生体認証・PIN、セキュリティキーなどが必要です。

```sh
pnpm install --frozen-lockfile
# 設定を変更する場合のみ。デフォルトでlocalhost:3000を使用します。
cp .env.example .env.local
pnpm dev
```

[http://localhost:3000](http://localhost:3000) を開きます。`127.0.0.1`やLAN内のIPアドレスではなく、**localhost**を使ってください。HTTPのlocalhostはWebAuthnを使用できる信頼可能なローカル環境として扱われます。通常の外部サイトではHTTPSが必要です。

ポートを変更する場合は`.env.local`の`APP_ORIGIN`を`http://localhost:3001`などに変更し、`pnpm dev --port 3001`と合わせます。Originはスキーム・ホスト・ポートを含む完全一致、末尾の`/`は付けません。RP IDはポートを含まない`localhost`に固定。Hostヘッダーから期待値を自動決定しません。localhost以外を設定すると起動時の処理を拒否します。

| 設定 | デフォルト | 用途 |
| --- | --- | --- |
| `APP_ORIGIN` | `http://localhost:3000` | HTTP OriginとWebAuthn clientDataJSONの期待Origin |
| `DATABASE_PATH` | `./data/lab.sqlite` | SQLiteファイルの保存先（サーバープロセスの作業ディレクトリ基準） |

```sh
pnpm typecheck
pnpm test
pnpm build
pnpm start
```

`pnpm start`はビルド済みアプリの確認用です。`NODE_ENV=production`では`/lab`は404になり、APIの詳細トレースも返しません。ビルド成功は、本番運用の安全性を保証しません。

## 実際に操作する

1. `/register`でユーザー名（英数字・`_`・`-`、3〜32文字、大文字小文字を区別）を入力し、端末などにパスキーを登録します。
2. 登録の検証が成功するとアカウントが作成され、そのアカウントでログインします。キャンセルや検証失敗ではユーザー・公開鍵は保存されません。
3. `/account`で登録済みパスキー、署名カウンター、transport、バックアップ状態を確認します。ログイン中に別の認証器を選んでパスキーを追加できます。同じパスキーの重複登録はブラウザへの除外指定とDBの一意制約で防ぎます。
4. ログアウト後、`/login`でパスキーを選びます。ユーザー名は送信せず、Credential IDとuserHandleから所有者を特定します。
5. 開発時は同じタブのリンクから`/lab`に移動すると、それまでの送受信とサーバー検証の記録を追跡できます。フルリロード、別タブへの移動、記録の消去で失われます。

OSの認証ダイアログでの生体認証やPIN入力は、利用者が行ってください。ユーザー検証に対応しないキーや、discoverable credentialの空き容量がないキーでは登録できません。失敗時は処理を最初からやり直します。

## システム構成

```text
ブラウザ / React Client Components
  └─ @simplewebauthn/browser → WebAuthn API → 認証器 / パスキープロバイダー
  └─ JSON + HttpOnly Cookie
       ↓
Next.js App Router / Node.js Route Handler
  ├─ HTTP Origin・入力形式・ログイン権限の確認
  ├─ AuthService / SimpleWebAuthn server
  └─ node:sqlite → ローカルSQLite（WAL・外部キー・トランザクション）
```

主要な実装:

- `src/lib/auth.ts`: 登録・認証・チャレンジの消費・セッション管理
- `src/lib/db.ts`: SQLiteのスキーマとトランザクション
- `src/lib/config.ts`: 固定RP ID、Origin、期限、開発環境判定
- `src/app/api/[...path]/route.ts`: APIとCookieの設定、開発用の検証結果
- `src/components/workbench.tsx`: ユーザー画面、ブラウザのWebAuthn呼び出し、拒否実験
- `src/components/lab-context.tsx`: タブ内メモリに限定した開発用記録
- `tests/auth.test.ts`: 本物のライブラリと独立したソフトウェア認証器入力を使用したテスト
- `tests/e2e/passkey.spec.ts`: Chromiumの仮想認証器を利用したブラウザテスト

使用バージョンは`package.json`参照。実装時点ではNext.js 16.4.1、React 19.3.1、SimpleWebAuthn server 14.0.3 / browser 14.0.0を採用。ES256とRS256を登録・検証の両方で明示して使用します。

## 登録フロー

1. サーバーはユーザー名の形式と既存ユーザーを確認。WebAuthn用のランダムな32バイトのuser IDを生成します。この段階ではユーザー行を作りません。
2. `generateRegistrationOptions()`でchallengeを生成。`residentKey: required`、`userVerification: required`、`attestation: none`を指定します。
3. challengeと予定ユーザー情報を`ceremonies`に2分間保存。ランダムなフロー用Cookieのハッシュに紐付けます。追加登録では、ログイン済みユーザーと開始時のセッションにも紐付けます。
4. ブラウザの`startRegistration({ optionsJSON })`が`navigator.credentials.create()`を実行。認証器が鍵を生成し、公開鍵を含むレスポンスを返します。秘密鍵はこのアプリに渡りません。
5. サーバーはフローCookieに対応するchallengeを**原子的に削除してから**、期限・用途・追加登録時のセッションを確認。失敗しても再利用できません。
6. `verifyRegistrationResponse()`でchallenge、Origin、RP IDに対応するハッシュ、UP/UV、公開鍵の形式などを検証します。
7. 検証が成功した場合だけ、ユーザー・credential・初回セッションを同じトランザクションで保存。名前の競合やcredential重複で失敗した場合は全体をロールバックします。

追加登録は開始時と完了時にログインが必要です。セッションの期限切れ・ログアウト・別セッションへの置換後は追加できません。公開鍵保存直前のトランザクションでもセッションを再確認します。

`attestation: none`では、認証器メーカーやハードウェアの真正性を保証しません。登録時に必ず署名付きattestationが返るわけでもありません。新規登録成功を、実在人物の確認や特定ハードウェアによる保証とは解釈しません。

## 認証フロー

1. `generateAuthenticationOptions()`で新しいchallengeを生成し保存。`allowCredentials: []`で特定ユーザーのCredential ID一覧を渡さず、認証器内のdiscoverable credentialから選択させます。UVを必須にします。
2. `startAuthentication({ optionsJSON })`から`navigator.credentials.get()`を呼び出します。認証器は`authenticatorData || SHA-256(clientDataJSON)`に対応する署名を生成します。
3. サーバーはフロー用challengeを一回限りで消費。Credential IDから保存済み公開鍵を取得し、返されたuserHandleがそのcredentialの所有者IDと一致することを確認します。
4. `verifyAuthenticationResponse()`がchallenge、`webauthn.get`という処理種別、Origin、rpIdHash、UP、UV、署名カウンター、署名などを検証します。ブラウザから送られた公開鍵は使用しません。
5. 成功時だけカウンター・バックアップ状態・最終利用日時を更新し、新しいセッションを保存。元のセッションがあれば無効化します。カウンターは比較更新で並行実行による古い状態の上書きを防ぎます。

全ての検証を通過するまでは新しいセッションを発行しません。認証失敗では**すでに存在するセッションを失効させない**ため、拒否実験後も元のログイン状態が残る場合があります。

## API

全POSTは`Content-Type: application/json`と、設定されたHTTP `Origin`が必要です。入力は実際に読み取った本文のサイズで64KiBに制限。全APIレスポンスは`Cache-Control: no-store`です。

| メソッド / パス | 役割 | JSON入力 / 権限 |
| --- | --- | --- |
| `POST /api/register/options` | 新規登録用challenge・optionsを生成 | `{ username }` |
| `POST /api/register/verify` | 登録を検証してアカウント作成・セッション発行 | `{ credential }`とフローCookie |
| `POST /api/passkeys/options` | ログイン中のユーザーに追加登録optionsを生成 | `{}`、セッション必須 |
| `POST /api/passkeys/verify` | 追加登録を検証・保存 | `{ credential }`、開始時と同じ有効なセッション必須 |
| `POST /api/authenticate/options` | ユーザー名不要の認証optionsを生成 | `{}` |
| `POST /api/authenticate/verify` | 署名等を検証・状態更新・セッション発行 | `{ credential }`とフローCookie |
| `GET /api/me` | 自分のユーザー情報・パスキー一覧 | セッション必須、未認証は401 |
| `POST /api/logout` | サーバー側セッションと未完了フローを無効化 | `{}` |

options APIは`{ options }`を返し、verify APIは成功時`{ verified: true }`を返します。開発環境のみ`trace`を追加。失敗時は`{ error, code }`と適切なHTTPステータス。詳細なライブラリエラーは開発時のtraceにのみ含めます。

## DBに保存する情報

| テーブル | 保存内容 |
| --- | --- |
| `users` | ランダムuser ID（WebAuthn userHandleと共通）、一意のユーザー名、作成日時 |
| `credentials` | Credential ID、所有者ID、COSE公開鍵（BLOB）、署名カウンター、transport配列、デバイス種別、バックアップ状態、登録日時、最終認証日時 |
| `ceremonies` | フロー用トークンのSHA-256ハッシュ、challenge、用途、予定ユーザー情報、追加登録時のセッションハッシュ、失効時刻 |
| `sessions` | 256ビットのランダムセッショントークンのSHA-256ハッシュ、所有者ID、絶対失効時刻 |

秘密鍵、PIN、生体情報は保存しません。challengeは機密値ではありませんが、有効なフローCookieとの対応が必要です。セッション値・フローCookieの生値はDBに保存しません。公開鍵は秘密ではありませんが、通常の一覧APIには含めません。

SQLiteファイル・WAL等はGit管理から除外しています。新しいデータディレクトリの作成時は権限`0700`を指定しますが、DBは暗号化しておらず、同じOSユーザーによる読み取りや既存ディレクトリの権限は管理しません。SQLiteの状態はファイルに永続化され、アプリ再起動後も有効期限内のセッションを使えます。

リセットする場合は**サーバーを停止してから**`data/`配下のSQLiteと関連ファイルを削除してください（カスタム保存先はそのパス）。これはサーバーのアカウントを消す操作であり、端末・パスキープロバイダーに保存されたパスキーは別途削除が必要です。

## セキュリティ検証と目的

| 検証・管理 | 目的 |
| --- | --- |
| 乱数challengeと一致確認 | 今回の認証要求への応答であることを確認 |
| 2分の期限・原子的DELETE | 古い応答や同時再送の再利用を拒否。失敗した試行も消費 |
| フロー用HttpOnly Cookie | challengeを開始したブラウザのフローに紐付け |
| HTTP Origin完全一致 | 状態変更APIへの別Originからの要求を拒否。WebAuthn内部のOrigin検証とは別の層 |
| clientDataJSONのOrigin・処理種別 | 期待するサイトと登録/認証の用途に合う応答かを確認 |
| authenticatorDataのrpIdHash | 正しいRPのcredentialが使用されたかを確認 |
| 保存済み公開鍵による署名検証 | 対応する秘密鍵による今回の署名であることを確認 |
| UP（User Presence）・UV（User Verification）必須 | 認証器による利用者の操作とローカル本人確認を要求 |
| Credential IDとuserHandleの所有者一致 | 別アカウントのパスキーや取り違えを拒否 |
| 署名カウンター検証・比較更新 | 対応認証器での巻き戻りや競合を検出 |
| DBトランザクション・一意制約 | 不完全なアカウントや重複credentialを残さない |
| セッションのサーバー失効・8時間の絶対期限 | ブラウザのCookie存在だけに依存せず、ログイン状態を判断 |
| ログイン時のセッション再発行 | 既存セッションをそのまま認証成功の識別子として再利用しない |

Cookieは`HttpOnly`、`SameSite=Strict`、`Path=/`、Domain指定なし。セッションは8時間、フローは2分。`Secure`は設定OriginがHTTPSの場合に有効です。HTTP localhostでの実験では無効にし、起動をlocalhostにバインドします。このHTTP構成を外部公開に流用しないでください。アプリの画面は`X-Frame-Options: DENY`で埋め込みを防ぎます。

失効済みのchallenge・セッション行は新しいoptions生成時に清掃します。清掃前であっても期限を過ぎた状態は使用できません。同じブラウザで新しいフローを開始すると前のフローを破棄するため、複数タブで登録・認証を同時に開始しないでください。

### WebAuthnの性質と、アプリ実装に依存する性質

**仕様の仕組み**は、RPにスコープされた公開鍵credential、Originを含むclientData、RP IDハッシュを含む認証器データ、challenge、署名、UP/UVフラグを提供することです。これらをブラウザ・認証器が正しく生成し、RPが正しく検証するという前提で、認証をサイトに紐付けてフィッシングや応答の使い回しに対抗します。WebAuthnの署名は、後続の全HTTPリクエストを保護するものではありません。

**このアプリの責任**は、信頼できる期待Origin/RP IDを設定し、challengeを正しく生成・期限管理・一回限りで消費し、credentialとアカウントを対応させ、ライブラリの検証を省略せず、成功後にだけDB更新とセッション発行を行うことです。セッションのCookie属性、CSRF対策、DBの整合性、デバッグ情報の扱いもWebAuthn自体が自動的に保証するものではありません。

- UVは認証器によるローカルの利用者検証を表します。生体認証だけとは限らず、PINや端末の認証も使われます。このアプリは実在人物の身元を確認しません。
- 秘密鍵が**このWebアプリに返らない**ことと、鍵が**物理端末から一切出ない**ことは別です。同期型パスキーではプロバイダーが秘密鍵を管理・同期します。
- 署名カウンターが常に0の認証器もあります。`0 → 0`を許容するライブラリの判断に従い、再送防止をカウンターだけに依存させません。カウンターにより全ての複製や侵害を検出できるとは主張しません。
- attestation=noneでは認証器の出自を検証しません。同期・バックアップ状態も、実際のバックアップ内容をサーバーが監査した結果ではありません。
- 正しいパスキー認証でも、XSS、セッション窃取、悪意ある拡張機能、侵害された端末・サーバー、危険な復旧経路を自動的には解決しません。

## 開発画面と拒否実験

`pnpm dev`でのみ`/lab`を利用できます。

- **BROWSER**: 送信JSON、受信JSON、デコードしたclientDataJSON、WebAuthn API呼び出しとブラウザエラー。受信データの表示は、信頼性の検証ではありません。
- **SERVER**: challenge生成、保存された期待値、期限・用途の確認と一回限りの消費、ライブラリ検証、DB保存、カウンター更新、セッション発行、失敗理由。
- サーバーの「検証passed」はライブラリ全体の成功を確認した後にのみ記録。失敗時はライブラリが最初に返した理由を表示し、後続の検証も成功したとは表示しません。DB保存に失敗した場合は、検証passedの後に処理拒否が記録されます。
- 最新80件をタブ内のReact stateに保持。サーバーにトレース一覧APIや永続ログはなく、他のタブ・利用者の記録を閲覧できません。
- Cookie・Set-Cookieヘッダー、フロー識別子、セッション識別子、秘密鍵は収集しません。challenge、Credential ID、userHandle、ユーザー名、署名は含まれるため、スクリーンショットなどを共有する前に確認してください。

「正常な認証」で成功した応答をメモリに保持し、次の実験を実行できます。

| 操作 | 入力・期待する拒否 |
| --- | --- |
| 応答を再送 | 使用済みの応答を再送。フローCookie/保存済みchallengeがなく拒否 |
| challengeを改変 | 新しいフローで誤ったchallengeの応答を送信し拒否 |
| Originを改変 | 新しいchallengeに合わせ、Originを変更して拒否 |
| rpIdHashを改変 | 新しいchallengeに合わせ、RP IDハッシュの1バイトを変更して拒否 |

画面上の改変は署名も無効にします。現在のライブラリが署名より先にchallenge・Origin・RP IDを検証するため、その失敗理由を観察できますが、検証順序そのものは仕様上の保証ではありません。署名の正常性を保って一つの要因だけを変える検証は、自動テストで行います。本来のAPIの検証を緩めたり、特別に認証を成功させるデバッグ用APIを追加したりしていません。

## テスト

`pnpm test`はネットワーク・実機・既存DBに依存しません。テストコード内だけでソフトウェア認証器の鍵とCBORデータを生成し、実際のSimpleWebAuthn検証関数に通します。署名生成はNode.js標準cryptoを使用し、独自の暗号アルゴリズムは実装していません。

27件のテストで、正常登録・認証、各拒否条件、再送、期限・用途・フロー紐付け、userHandle、UP/UV、署名・カウンター、同時再送・状態更新競合、追加登録の権限、登録競合・ロールバック、セッション失効・ログアウト、SQLite再接続での永続化、APIのOrigin・入力制限・Cookie・開発限定traceを確認します。Origin/RP ID/UV/UP不一致の認証入力にも**その入力に対する正しい署名**を付け、署名破損とは独立した拒否であることを確認します。

ブラウザの統合テスト:

```sh
pnpm exec playwright install chromium
# 起動済みのpnpm devを停止してから実行してください（Next.jsの開発ビルドロックを共有するため）。
pnpm test:e2e
# インストール済みのGoogle Chromeを使う場合:
PLAYWRIGHT_CHANNEL=chrome pnpm test:e2e
```

localhost:3100にテストサーバーを起動し、メモリ内の隔離DBとChromiumの仮想CTAP2認証器を使用します。画面からの登録・ユーザー名不要ログイン・追加登録・CookieのJavaScriptからの不可視性・全拒否実験・トレースの消去を確認します。OSの生体認証・実機セキュリティキー・同期プロバイダーの動作を保証するテストではありません。

## 制約と実運用に必要な追加対策

研究用の単一Node.jsプロセス・ローカルSQLiteを前提とします。Node.js用の実装でありEdge Runtimeは使用しません。DBの同期アクセスは大規模負荷向けではありません。パスワード認証、本人確認、アカウント復旧、パスキー削除・表示名変更、メール確認は未実装です。全てのパスキーを失うと、このアプリには復旧経路がありません。

実運用では少なくとも次の設計・検証が別途必要です。

- HTTPS、実ドメインのRP/Origin設計、適切なSecure CookieとHTTPS終端、ネットワーク境界の設定
- レート制限・登録濫用対策・容量制限・失効行の定期清掃・可用性と負荷試験
- XSS対策、CSP、依存パッケージの継続更新と脆弱性管理
- 追加登録など重要操作の直前の再認証、セッション失効一覧・端末管理・監査
- 安全な復旧・アカウント削除・本人確認の設計と、登録済みcredentialのライフサイクル管理
- DBの権限、暗号化の要否、バックアップ・復元、複数インスタンスでの整合性
- 対応ブラウザ・認証器・プロバイダーでの実機検証、プライバシー方針とデータ保持方針

ユーザー名の存在は登録APIで判別可能です。追加登録は有効なセッションを持つことだけを条件とし、直前の再認証は要求しません。HTTP localhostの安全性はローカル環境の信頼を前提とし、他のローカルプロセスや同一OSユーザーからの侵害を防ぐ仕組みではありません。

## 参考資料

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) — 登録・認証の処理、clientData、authenticatorData、RP ID、署名カウンター
- [SimpleWebAuthn server v14](https://simplewebauthn.dev/docs/packages/server) — options生成・検証・credential永続化
- [SimpleWebAuthn browser v14](https://simplewebauthn.dev/docs/packages/browser) — `startRegistration({ optionsJSON })` / `startAuthentication({ optionsJSON })`
- [SimpleWebAuthn Passkeys](https://simplewebauthn.dev/docs/advanced/passkeys) — discoverable credential、UV、同期型パスキー
- [Next.js Route Handlers](https://nextjs.org/docs/app/getting-started/route-handlers) — App RouterのAPI実装
- [Next.js cookies](https://nextjs.org/docs/app/api-reference/functions/cookies) — Cookie属性とレスポンス
- [Node.js SQLite](https://nodejs.org/api/sqlite.html) — `DatabaseSync`とローカル永続化
- [Chrome DevTools Protocol WebAuthn](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/) — 統合テストの仮想認証器
