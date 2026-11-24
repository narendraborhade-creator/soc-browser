# SOC Analyst Browser (v0.2.0)

A standalone, hardened Electron (`WebContentsView`) browser built specifically for SOC triage, phishing investigation, and threat-intel enrichment.

## Why sites like `reddit.com` work here

1. **Real `WebContentsView` rendering** (no `iframe` or legacy `<webview>`), eliminating `X-Frame-Options` and CSP framing blocks.
2. **Chrome User-Agent + `Sec-CH-UA` normalization** (`src/main/hardening/BrowserSpoof.ts`): strips `Electron/x.x` from request headers and sends matching Chromium Client Hints so Reddit and Cloudflare treat the browser as standard desktop Chrome.
3. **Proper popup & OAuth handling** (`src/main/cases/CaseManager.ts`): `target="_blank"` links open in a new tab inside the same ephemeral case partition, while login/OAuth popups open in a sandboxed child window sharing that case session.

## Included Features

- **Ephemeral per-case tab isolation:** Uses `session.fromPartition("case-...")` without `persist:`, keeping cookies, cache, and storage strictly in RAM and wiping them when the case closes.
- **Encrypted SQLite Case History Vault (`src/main/storage/VaultDb.ts`):** Persists case snapshots (defanged URLs, IOCs, redirects, screenshot hashes, quarantined downloads, analyst notes) in `better-sqlite3` with WAL mode, `secure_delete = ON`, and authenticated **AES-256-GCM** payload encryption backed by an OS-keychain master key (`safeStorage`).
- **Direct Splunk HEC Push (`src/main/export/SplunkHecClient.ts`):** Sends structured `soc_browser:case` events directly to your Splunk HTTP Event Collector with encrypted token storage and an optional self-signed TLS toggle for local Splunk labs.
- **CDP network, redirect & screenshot capture:** Attaches Chrome DevTools Protocol (`1.3`) to record HTTP requests, redirect chains, remote IPs, HAR 1.2 exports, and SHA-256 hashed PNG screenshots.
- **Live IOC extractor & enrichment:** Extracts IPv4, domains, URLs, MD5, SHA-1, and SHA-256 from live traffic and visible DOM text, copies defanged indicators (`hxxps://`, `[.]`), and queries VirusTotal v3 / AbuseIPDB v2.
- **Proxy switching & WebRTC hardening:** Switch per-case between Direct, Tor (`socks5://127.0.0.1:9050`), or a custom HTTP/SOCKS5 proxy, enforce `disable_non_proxied_udp` on WebRTC, strip cross-origin `Referer` headers, and auto-quarantine downloads to `.quarantine` with SHA-256 hashes.
- **Case exporters:** One-click export to Splunk JSON, Jira Markdown, TheHive observables JSON, and HAR 1.2.

## Quick Start

```bash
npm install
npm run dev
```

`postinstall` runs `electron-builder install-app-deps` to align `better-sqlite3` with your local Electron ABI. Open the **Keys** tab to configure VirusTotal, AbuseIPDB, and Splunk HEC, then use the **Vault** tab to save and inspect encrypted case snapshots.
