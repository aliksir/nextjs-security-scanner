# nextjs-security-scanner

Next.jsプロジェクトの CVE-2025-55182（React2Shell）脆弱性とクレデンシャル露出を検出するBashスクリプト。依存ゼロ。

## CVE-2025-55182: React2Shell

CVSS: **10.0 (CRITICAL)** | CWE-502: 信頼されていないデータのデシリアライゼーション | SNORT SID: 65554

Next.jsのServer Componentsにおけるデシリアライゼーション脆弱性。攻撃者は細工したHTTPリクエストをServer Componentのエンドポイントに送信するだけで、認証なしにサーバー上で任意のコードを実行できる。

Cisco Talosの報告では、攻撃グループ UAT-10608 がこの脆弱性を利用し、766以上のホストからNEXUS Listener V3でクレデンシャルを窃取した。

**影響バージョン（NVD確認済み）:**

| パッケージ | 脆弱バージョン |
|-----------|--------------|
| Next.js | 15.0.0–15.0.4, 15.1.0–15.1.8, 15.2.0–15.2.5, 15.3.0–15.3.5, 15.4.0–15.4.7, 15.5.0–15.5.6, 15.6.0, 16.0.0–16.0.6 |
| React   | 19.0.0, 19.1.0, 19.1.1, 19.2.0 |

**参考:**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- Cisco Talos: https://blog.talosintelligence.com/ で "React2Shell" を検索

## スキャン内容

| Phase | 対象 | 内容 |
|-------|------|------|
| 1 | Next.jsバージョン | `package.json`、`package-lock.json`、`yarn.lock` からバージョンを取得し、脆弱範囲と照合 |
| 2 | Reactバージョン | 同様にReactの脆弱バージョン（19.0.0, 19.1.0, 19.1.1, 19.2.0）を検出 |
| 3 | App Router / Server Components | `app/` ディレクトリと `"use server"` ディレクティブの検出。脆弱バージョン+Server Components = 攻撃可能状態 |
| 4 | クレデンシャル露出 | `.env*` ファイル、`next.config.*`、ソースコード内のAPIキー・シークレットパターン検出（`.env.example` と `.env.sample` は除外） |
| 5 | SSH鍵・秘密ファイル | `id_rsa`、`*.pem`、`*.p12` 等の秘密鍵ファイル、`.ssh/` ディレクトリの不適切な配置 |
| 6 | クラウド設定 | Docker Composeのハードコードシークレット、K8sサービスアカウントトークン露出、AWS IMDSv2ヒント |
| 7 | IOC（侵害指標） | Cisco Talos由来のC2 IPアドレス、`/tmp/` ドットプレフィックスファイル（Linux） |

**C2 IPアドレス（Cisco Talos）:**
```
144.172.102.88 / 172.86.127.128 / 144.172.112.136 / 144.172.117.112
```

## インストール

インストール不要。ダウンロードして実行するだけ:

```bash
curl -O https://raw.githubusercontent.com/aliksir/nextjs-security-scanner/main/scan.sh
bash scan.sh [対象ディレクトリ]
```

クローンする場合:

```bash
git clone https://github.com/aliksir/nextjs-security-scanner.git
bash nextjs-security-scanner/scan.sh /path/to/your/nextjs-app
```

## 使い方

```bash
# カレントディレクトリをスキャン
bash scan.sh

# 特定のプロジェクトをスキャン
bash scan.sh /path/to/nextjs-app

# CI/CDで使用（0以外の終了コードでパイプライン失敗）
bash scan.sh . || exit 1
```

**終了コード:**
| コード | 意味 |
|--------|------|
| `0` | 問題なし |
| `1` | 警告あり（クレデンシャルパターン検出、要確認） |
| `2` | 深刻な問題あり（脆弱バージョン確認、即時対応が必要） |

## 出力例

```
=== Next.js Security Scanner ===
Target: /home/user/myapp
Date: 2026-04-04 12:00
CVE: CVE-2025-55182 (React2Shell, CVSS 10.0)

[Phase 1] Next.js version check
  [CRITICAL] Next.js v15.2.4 is vulnerable to CVE-2025-55182 (React2Shell)
             -> package.json: "next": "^15.2.4"
             -> This version allows unauthenticated RCE via deserialization of Server Components

[Phase 2] React version check
  [CRITICAL] React v19.1.0 is in the CVE-2025-55182 vulnerable list

[Phase 3] App Router / Server Components detection
  [INFO]     App Router detected (app/ directory exists)
  [CRITICAL] Vulnerable Next.js + Server Components = active attack surface for React2Shell

...

=== Scan Summary ===
  CRITICAL : 3
  WARNING  : 0
  INFO     : 2

CRITICAL issues found. Immediate action required.
```

## 修復手順

**即座にアップグレード:**

```bash
npm install next@latest
npm install react@latest react-dom@latest
```

パッチ済みバージョンは https://github.com/vercel/next.js/releases で確認。

**攻撃を受けた可能性がある場合:**

1. 全シークレットをローテーション（APIキー、DB認証情報、JWTシークレット、SSH鍵、クラウドIAM）
2. 侵害後の痕跡を確認:
   ```bash
   ps aux | grep -E '\.sh|\.py'        # 不審なプロセス
   crontab -l; cat /etc/cron*          # cronの変更
   ss -tnp | grep -E '144\.172|172\.86'  # C2への通信
   ls -la /tmp/ | grep '^\.'           # /tmp/ の異常ファイル
   ```
3. C2 IPをファイアウォールでブロック: `144.172.102.88`, `172.86.127.128`, `144.172.112.136`, `144.172.117.112`
4. SNORTルール SID: 65554 を有効化

## Claude Codeスキルとして使用

`claude-code/SKILL.md` をスキルとして登録すると、Claude Codeから直接呼び出せる。

トリガーキーワード: "Next.jsセキュリティチェック", "CVE-2025-55182", "React2Shell", "Next.js脆弱性スキャン"

## 免責事項

本ツールは**防御的セキュリティ目的**でのみ提供されます。ローカルファイルに対する読み取り専用のチェックのみを実行し、ネットワーク接続・外部へのデータ送信・エクスプロイトの実行は一切行いません。

脆弱性情報とIOCデータはNVD、Cisco Talos等の公開情報に基づいています。誤検知が発生する可能性があり、また全ての攻撃ベクトルを検出できるわけではありません。専門家によるセキュリティ監査・ペネトレーションテスト・ベンダー提供のセキュリティパッチの代替にはなりません。

**利用は自己責任で行ってください。** 本ツールの使用により生じたいかなる損害についても、作者は一切の責任を負いません。

## ライセンス

MIT — [LICENSE](LICENSE) を参照
