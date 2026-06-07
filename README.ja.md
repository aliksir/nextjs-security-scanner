> English version: [README.md](README.md)

# nextjs-security-scanner

CVE-2025-55182 (React2Shell) および認証情報の漏洩を Next.js プロジェクトで検出する Bash スクリプト。依存パッケージなし。

## CVE-2025-55182: React2Shell

CVSS: **10.0 (CRITICAL)** | CWE-502: 信頼できないデータのデシリアライゼーション | SNORT SID: 65554

Next.js Server Components における信頼できないデータのデシリアライゼーションにより、認証なしでリモートコード実行（RCE）が可能になる脆弱性。攻撃者は任意の Next.js Server Component エンドポイントに細工した HTTP リクエストを送信し、サーバー側でペイロードがデシリアライズされて任意のコードが実行される。

**影響を受けるバージョン:**

| パッケージ | 脆弱なバージョン範囲 |
|-----------|-------------------|
| Next.js | 15.0.0--15.0.4, 15.1.0--15.1.8, 15.2.0--15.2.5, 15.3.0--15.3.5, 15.4.0--15.4.7, 15.5.0--15.5.6, 15.6.0, 16.0.0--16.0.6 |
| React   | 19.0.0, 19.1.0, 19.1.1, 19.2.0 |

**参考情報:**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- Cisco Talos: https://blog.talosintelligence.com/ で "React2Shell" を検索

## スキャン内容

**Phase 1 -- Next.js バージョン確認:** `package.json`、`package-lock.json`、`yarn.lock` を読み取り、インストール済みの Next.js バージョンを特定し、脆弱なバージョン範囲と照合する。

**Phase 2 -- React バージョン確認:** React についても同様のアプローチで確認（19.0.0, 19.1.0, 19.1.1, 19.2.0）。

**Phase 3 -- App Router / Server Components 検出:** `app/` ディレクトリおよび `"use server"` ディレクティブを検出する。脆弱なバージョンで Server Components が有効な場合、攻撃対象となる。

**Phase 4 -- 認証情報の漏洩検出:** `.env*` ファイル（`.env.example` と `.env.sample` は除外）、`next.config.*`、ソースファイルを対象に、API キー、データベース URL、JWT シークレット、ハードコードされたシークレットプレフィックス（`sk-`、`AKIA`、`ghp_`、`npm_`）を検出する。

**Phase 5 -- SSH 鍵の検出:** プロジェクト内にコミットされた秘密鍵ファイル（`id_rsa`、`*.pem`、`*.p12` など）や `.ssh/` ディレクトリを検出する。

**Phase 6 -- クラウド設定の検出:** Docker Compose ファイル内のハードコードされたシークレット、Kubernetes マニフェスト内のサービスアカウントトークンの露出、AWS SDK 利用における IMDSv2 のヒントを確認する。

**Phase 7 -- IOC チェック:** Cisco Talos インテリジェンスに基づく C2 IP アドレスの検出と、不審な `/tmp/` ドットファイルパターン（Linux）を検索する。

```
C2 IPs (Cisco Talos): 144.172.102.88 / 172.86.127.128 / 144.172.112.136 / 144.172.117.112
```

**Phase 8 -- サマリー:** CRITICAL/WARNING/INFO のカウントと修復手順を表示する。

## インストール

インストール不要。ダウンロードして実行するだけ:

```bash
curl -O https://raw.githubusercontent.com/aliksir/nextjs-security-scanner/main/scan.sh
bash scan.sh [target-directory]
```

または clone:

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

# CI/CD で使用（終了コードが 0 以外ならパイプラインを失敗させる）
bash scan.sh . || exit 1
```

**終了コード:**
- `0` -- 問題なし
- `1` -- 警告（認証情報のパターンが検出された、要確認）
- `2` -- 重大（脆弱なバージョンが確認された、即座の対応が必要）

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

=== Remediation (CVE-2025-55182) ===

1. Upgrade Next.js to a patched version:
   npm install next@latest
...
```

## 修復方法

**直ちにアップグレード:**

```bash
npm install next@latest
npm install react@latest react-dom@latest
```

各マイナーシリーズの最初のパッチ済みバージョンは https://github.com/vercel/next.js/releases で確認できる。

**攻撃が疑われる場合:**
1. すべてのシークレットをローテーションする（API キー、データベース認証情報、JWT シークレット、SSH 鍵、クラウド IAM）
2. 攻撃後のアーティファクトを確認する:
   ```bash
   ps aux | grep -E '\.sh|\.py'
   crontab -l; cat /etc/cron*
   ss -tnp | grep -E '144\.172|172\.86'
   ls -la /tmp/ | grep '^\.'
   ```
3. ファイアウォールで C2 IP をブロック: `144.172.102.88`、`172.86.127.128`、`144.172.112.136`、`144.172.117.112`
4. SNORT ルール SID: 65554 を有効化

## Claude Code スキルとしての利用

```bash
bash scan.sh [target-directory]
```

トリガーキーワード: "next.js security check", "CVE-2025-55182", "React2Shell", "Next.js vulnerability scan"

スキルラッパーの詳細は `claude-code/SKILL.md` を参照。

---

## 免責事項

本ツールは**防御目的のセキュリティ利用のみ**を目的として提供される。ローカル環境でのみ動作し、プロジェクトファイルに対して読み取り専用のチェックのみを実行する。ネットワーク接続は行わず、外部へのデータ送信は一切なく、エクスプロイトも実行しない。

脆弱性情報および IOC データは公開情報（NVD、Cisco Talos）に基づいている。本スキャナーは誤検知を生じる可能性があり、特定の攻撃ベクターを検出できない場合がある。プロフェッショナルなセキュリティ監査、ペネトレーションテスト、ベンダー提供のセキュリティパッチに代わるものではない。

**利用は自己責任で行うこと。** 本ツールの使用に起因する損害について、作者は一切の責任を負わない。

## ライセンス

MIT -- [LICENSE](LICENSE) を参照
