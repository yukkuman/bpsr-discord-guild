# Guild Chat Forwarder

Star Resonance のギルドチャットだけを Discord Webhook に転送するシンプルなツールです。コンソールにも「名前: メッセージ」で表示されます。

## 使う人向け（exe）
1. 前提: Windows、Npcap が入っていること（管理者権限は不要）。
2. `dist` 内の3つを同じフォルダに置く: 
	- bpsr-discord-guild.exe
	- cap.node（node_modules/cap/build/Release/cap.node からコピー済みのもの）
	- config.yaml（`webhook.guild` に Discord Webhook URL を書く）
3. bpsr-discord-guild.exe をダブルクリックするだけで開始。コンソールに「名前: メッセージ」が流れ、同じ内容が Webhook に送信されます。

## 開発者向け（ソースからビルドする場合）
1. 前提: Node.js 18 系、Npcap、`npm install`
2. 実行: `npm start`（CONFIG 環境変数で設定ファイルを変えられます）
3. exe ビルド: `npm run build:win` で `dist/bpsr-discord-guild.exe` が生成されます。生成後、`node_modules/cap/build/Release/cap.node` を dist にコピーしてください。

## 免責
- 利用は自己責任でお願いします。
- Webhook URL や個人情報は第三者に公開しないでください。
