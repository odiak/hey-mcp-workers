# HEY MCP on Cloudflare Workers

[English](README.md) | 日本語

自分のHEYアカウントを、OAuthでMCPクライアントに接続する単一ユーザー専用のサーバーです。ソースコードの公開と、デプロイ先の利用権限は別です。管理用シークレットを持つ所有者が承認した連携だけが利用できます。

## 構成

- **Workers secrets**: `ENCRYPTION_KEY`（Base64の32ランダムbytes）と、別の`ADMIN_SECRET`（32文字以上）。
- **Owner Durable Object**: HEYの認証情報・install_idをAES-256-GCMで暗号化して保存。管理セッション、連携権限、失効状態、HEYのトークン更新も管理。
- **Workers KV**: CloudflareのOAuthライブラリがクライアント登録・認可コード・MCPのトークンを管理。HEYの認証情報は入れません。
- **Streamable HTTP MCP**: `/mcp`。MCP SDK v2とAgentsのstateless handlerを使用。
- **管理画面**: `/admin`。認証情報のアップロード・接続確認・連携一覧・無効化・認証情報の削除。

管理画面では暗号化キーを入力しません。キーはサーバー側のsecretから取得し、保存後の復号確認もサーバーで行います。

## ローカルで動かす

Node.js 24以降とnpmを使用します。

```sh
npm ci
npm run setup:local
npm run dev
```

`setup:local`は独立した2つのランダムなsecretを、Gitで無視される`.dev.vars`へ権限0600で生成します。既存ファイルは上書きしません。値をコンソールへ出力しないので、ローカルエディタで`ADMIN_SECRET`を確認し、[管理画面](http://localhost:8787/admin)へログインしてください。

## HEYの認証情報を準備する

普段のCLIの認証情報と分けるため、Worker専用のディレクトリで、自分のマシンから対話的にログインします。

```sh
XDG_CONFIG_HOME="$HOME/.config/hey-mcp-bootstrap" \
  HEY_NO_KEYRING=1 HEY_BASE_URL=https://app.hey.com hey auth login
```

管理画面で次の2ファイルを選択します。

- `~/.config/hey-mcp-bootstrap/hey/credentials.json`
- `~/.config/hey-mcp-bootstrap/hey/install_id`

保存後に「HEYへの接続を確認」を実行してください。アップロード成功と、HEYの認証成功は別の状態として表示します。

アップロード後、このディレクトリをローカルCLIの通常操作に使わないでください。同じrefresh tokenをCLIとWorkerで更新すると競合します。ローカルに生成された認証ファイルは平文なので、アップロード・接続確認後は安全な場所での保管または削除を行ってください。HEYの認証は`oauth_type: oauth`に限定し、session cookie方式や独自の接続先には対応しません。

## Cloudflareへデプロイする

1. `wrangler.jsonc`の`PUBLIC_ORIGIN`を、使用する公開HTTPS origin（末尾の`/`なし）に変更します。カスタムドメインなら対応する`routes`も設定します。
2. 対象CloudflareアカウントとWorker名を確認します。現在のWranglerでは、IDを省略した`OAUTH_KV`は初回デプロイ時に作成できます。既存KVを使う場合は、そのnamespace IDを設定してください。
3. 本番専用のsecretを生成して登録し、デプロイします。

```sh
npm run setup:production
npx wrangler secret bulk .local/secrets-production.json
npm run types
npm run deploy
```

`secret bulk`はCloudflareへの変更・デプロイを伴います。`.dev.vars`のローカルsecretは本番へ自動転送されません。本番の管理ログインには`.local/secrets-production.json`内の`ADMIN_SECRET`を使います。secretsやHEYの認証情報をGit・チャット・スクリーンショットへ貼らないでください。

本番の暗号化キーは安全にバックアップしてください。キーを失うと保存した認証情報は復号できません。キーを変更するときは、まず専用のHEYログインをやり直し、新しいキーを登録したあとで新しい認証情報をアップロードしてください。既存の暗号文を再暗号化するキー移行機能はありません。管理用シークレットを変更すると、既存の管理セッションは無効になります。MCP連携は一覧から別途無効化してください。

## MCPクライアントを接続する

クライアントに`https://<PUBLIC_ORIGINのホスト>/mcp`を登録してください。認可コード＋PKCE S256によるOAuthを使い、管理ログイン後、連携名・リダイレクト先・権限を確認して毎回承認します。

| Scope | 許可する操作 |
| --- | --- |
| `hey:read` | メール、検索、連絡先、カレンダーなどの読み取り。既定で付与。 |
| `hey:write` | 下書きの保存、メールの整理、連絡先やTodoなどの変更。読み取りも必要。 |
| `hey:send` | メールの送信・予約送信。書き込みも必要。 |

access tokenは15分、refresh tokenは30日です。MCP用refresh tokenは更新時にローテーションします。30日経った連携は再承認してください。同じクライアントから再承認しても、以前の連携は自動で取り消しません。一覧で個別に無効化できます。

連携の無効化は新しいMCP操作とMCPトークン発行・更新に効きます。OAuth KVに古い記録が残っていても、Durable Objectの失効状態で拒否します。すでにHEYへ送信済みのリクエストは取り消せません。管理画面の「認証情報と全連携を無効にする」は、Workerの保存データを削除して連携を無効化します。HEY側のデバイスセッションを取り消す操作ではありません。

## ツールと使い方

参考にしたHEY CLIのMCPと同じ7ドメイン、71操作を実装しています。

| ツール | 内容 |
| --- | --- |
| `hey_boxes` | Imbox、Feed、Paper Trail、各種スタック、グループ、変更一覧 |
| `hey_search` | 詳細検索と検索条件 |
| `hey_threads` | スレッド、メッセージ、下書き、返信、送信、整理 |
| `hey_contacts` | 連絡先、メモ、Screener |
| `hey_todos` | Todoの作成・変更・完了・削除。読み取りは`hey_calendar`経由。 |
| `hey_calendar` | カレンダー一覧とrecordingsの読み取り |
| `hey_identity` | アカウント・送信者・ユーザーなどのidentity情報 |

各ツールは`action`、`params`、任意の`account_id`を受け取ります。`action: "describe"`で利用可能な操作を列挙し、`params: { "action": "get_topic" }`のように指定するとその操作の入力スキーマを取得できます。操作名はAPI operation IDをsnake_caseにしたものです。`account_id`はSDKと同じ`filtered_account_id`として渡します。アカウントの認可境界ではありません。

```json
{"action":"get_topic","params":{"topicId":123}}
```

結果の形式は`{status, data, location?, next_page?, next_since?, next_v?}`です。ページ送りは数値のページ番号ではなく、返されたcursorを対応する`page`などのパラメーターへ渡してください。返されたURLを任意にfetchするツールはありません。

書き込み操作は自動再送しません。401ではHEYの認証情報を更新しますが、書き込み自体は再送せず、成否確認を促します。読み取り操作は更新後に1回だけ再試行します。通信失敗や429/5xxで認証情報を捨てません。refresh endpointが4xxの`invalid_grant`を返した場合は再ログインが必要になります。

メッセージの保存・更新では、`entry.status: "drafted"`と予約送信フィールドなしの場合だけ、`hey:send`を持たない連携でも実行できます。`UpdateMessage`はパッチではなく置換なので、更新前に現在の内容を読み、件名・本文・宛先・予約を意識して指定してください。CLIの高水準なコマンドをそのまま実行するサーバーではありません。MCPドメインに含まれないイベント編集・habits・journal等は未対応です。

## セキュリティ上の範囲

- AES-GCMは保存データ単独の流出への対策です。Workerの実行権限・デプロイ権限を奪われた場合には復号され得ます。
- 管理セッションはランダムなtokenを使い、保存先にはそのSHA-256ハッシュだけを置きます。cookieはSecure/HttpOnly/SameSite=Strict、有効期限1時間。変更操作はOriginとCSRF tokenを検証します。
- 管理ログインはIPごとに10回/10分、動的クライアント登録は30回/1時間に制限します。公開DCR endpointはクライアント登録だけで、HEYへのアクセスは所有者の承認までできません。
- OAuthのclient metadataは信用せずHTML escapeし、外部のロゴ・スクリプトを読み込みません。承認画面はブラウザにひも付く一度限りのhandleを使います。
- HEYへの接続先とrefresh endpointは固定。アップロードされた任意のURLや、APIのリダイレクトへ認証情報を送信しません。
- 読み取り専用はツール一覧・MCPの実行・Durable Objectの実行の各段階で確認します。メール本文は外部から届くデータなので、AIへの指示として信用しないでください。
- 自前のログにはイベント名・HTTP status等だけを記録します。認証情報、token、本文、client metadata、完全なrequest URLは記録しません。Cloudflareのログ・traceではquery stringを除去し、invocation logは無効化しています。

## 開発・検証

```sh
npm run types
npm run check
npm test
npm run build
```

テストはCloudflareのWorkers runtime上で実行します。実際のHEYの認証情報を使わず、暗号化、入力検証、権限、CSRF、PKCE、OAuthのコード交換・更新・失効、HEYの更新競合とエラー処理を検証します。`build`はdry-runであり、本番デプロイではありません。

APIモデルを更新するときは、HEY CLIのcheckoutを指定します。

```sh
npm run sync:model -- /path/to/basecamp/hey-cli
```

生成元のcommit・SDK snapshot・操作数は`src/model/provenance.json`に記録します。モデルを更新したら、送信につながる操作の分類とスキーマの変更を確認してください。

## 参照・ライセンス

このプロジェクトは[MITライセンス](LICENSE)で公開します。Copyright (c) 2026 Kaido Iwamoto.

HEYの認証・install_id・refresh処理とMCPドメインの構成は[basecamp/hey-cli](https://github.com/basecamp/hey-cli)を参考にしています。APIモデルはCLIに含まれる[basecamp/hey-sdk](https://github.com/basecamp/hey-sdk)のsnapshotから派生しています。上流のMITライセンスは`licenses/`に同梱しています。このプロジェクトはHEYの公式ホスト型サービスではありません。

OAuthの実装は[workers-oauth-provider](https://github.com/cloudflare/workers-oauth-provider)、MCP transportは[Cloudflare Agents handler](https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/)を使用します。
