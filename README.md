<div align="center">

# ApkBugFinder

### Drop an APK. Get a security report in seconds.

**The modern OWASP MASVS scanner for Android — built for developers, pentesters, and security teams who want answers, not a wall of terminal text.**

<br />

[![GitHub stars](https://img.shields.io/github/stars/alexbieber/ApkBugFinder?style=for-the-badge&logo=github&color=10b981)](https://github.com/alexbieber/ApkBugFinder/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)](LICENSE)
[![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS-10b981?style=for-the-badge&logo=owasp)](https://mobile-security.gitbook.io/masvs/)
[![Next.js](https://img.shields.io/badge/Next.js-15-000?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![Go](https://img.shields.io/badge/Go-Scanner-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)

<br />

[Live Demo](#-quick-start) · [Features](#-why-apkbugfinder) · [Deploy](#-deploy-in-minutes) · [API](#-api) · [Contribute](#-contribute)

<br />

```
   📱  Upload APK  →  ⚙️  JADX Decompile  →  🔍  70+ MASVS Rules  →  📊  Actionable Report
```

</div>

---

## The problem

Your Android app ships Friday. Security review is due Thursday. You don't have MobSF running, your pentester is booked, and **APKHunt** gives you a 3,000-line terminal dump nobody wants to read.

**You need to know:**
- Is the app debuggable in production?
- Are API keys hardcoded in the source?
- Is cleartext traffic allowed?
- Are WebViews exposing JavaScript bridges?
- Which exported components are attack surface?

**You need answers in minutes — not days.**

---

## The solution

**ApkBugFinder** is a full-stack Android security scanner that combines the proven [APKHunt](https://github.com/Cyber-Buddy/APKHunt) analysis engine with a **beautiful web dashboard** your whole team can actually use.

> Upload an APK → get a prioritized findings report mapped to **OWASP MASVS**, **CWE**, severity, evidence snippets, and remediation guidance.

No Linux-only CLI. No unreadable logs. No guesswork.

---

## Why ApkBugFinder?

<table>
<tr>
<td width="50%">

### What you're leaving behind

- ❌ Terminal-only output
- ❌ Linux-only tooling
- ❌ Plain `.txt` reports
- ❌ No severity prioritization
- ❌ Manual grep through decompiled code
- ❌ One APK at a time, no history

</td>
<td width="50%">

### What you get with ApkBugFinder

- ✅ **Stunning web UI** — drag, drop, done
- ✅ **macOS + Linux + Docker** — works everywhere
- ✅ **JSON export** + scan history
- ✅ **Critical → Info** severity dashboard
- ✅ **70+ automated MASVS rules** on decompiled Java
- ✅ **Batch-ready** CLI + HTTP API

</td>
</tr>
</table>

### Built on what the industry already trusts

ApkBugFinder doesn't reinvent static analysis — it **levels up** the stack security professionals already rely on:

| Engine | What it does |
|--------|----------------|
| **dex2jar** | Converts APK bytecode to analyzable JAR |
| **JADX** | Decompiles to readable Java source |
| **MASVS rules** | 70+ grep-based checks across V1–V8 |
| **Go scanner** | Fast, modular, API-ready backend |
| **Next.js UI** | Modern dashboard deployable on Vercel |

Same DNA as APKHunt. **10× better experience.**

---

## Who is this for?

| Audience | How ApkBugFinder helps |
|----------|------------------------|
| **Android Developers** | Catch debuggable builds, hardcoded secrets, and weak crypto *before* release |
| **Security Engineers** | Standardize MASVS coverage across every app in your portfolio |
| **Penetration Testers** | Kick off engagements with instant SAST — focus manual testing on what matters |
| **Startups & Agencies** | Ship client apps with a security report you can actually attach to a deliverable |
| **Bug Bounty Hunters** | Quickly map attack surface: exports, WebViews, intents, network config |

---

## Features

### Core scanning

- **Full APKHunt parity** — JADX + dex2jar + grep on decompiled `.java` and `resources/*.xml`
- **70+ OWASP MASVS checks** — MSTG-STORAGE, CRYPTO, NETWORK, PLATFORM, CODE, RESILIENCE
- **Manifest intelligence** — permissions, exported components, backup/debug flags, SDK versions
- **Evidence with line numbers** — see exactly where the issue lives in decompiled source

### Advanced detection (beyond APKHunt)

- **Cloud & API secrets** — AWS keys, Google API keys, Stripe live keys, JWT tokens
- **Weak cryptography** — AES/ECB, MD5, static IVs, insecure random
- **WebView attack surface** — JS bridges, file access, SSL error handlers
- **Injection sinks** — SQLi, XSS, OS command execution patterns

### Dashboard & workflow

- **Severity-filtered findings** — Critical / High / Medium / Low / Info at a glance
- **MASVS + CWE mapping** — every finding linked to industry standards
- **One-click JSON export** — plug into CI, ticketing, or compliance workflows
- **Scan history** — compare runs without re-uploading
- **Scanner health indicator** — know instantly if full JADX engine is online

---

## See it in action

```bash
# One command. Full stack running locally.
docker compose up --build
```

Open **http://localhost:3000** → drop an APK → watch the magic.

**Real scan on [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) (OWASP training app):**

| Metric | Result |
|--------|--------|
| Scan time | ~16 seconds |
| Total findings | **44** |
| Critical | Debuggable app in production |
| High | SQL injection sinks, hardcoded secrets, WebView JS bridge |
| Medium | Cleartext traffic, clipboard usage, external storage |

That's the kind of report that gets a security review *started* — not stalled.

---

## Quick start

### Option A — Docker (recommended)

```bash
git clone https://github.com/alexbieber/ApkBugFinder.git
cd ApkBugFinder
docker compose up --build
```

| Service | URL |
|---------|-----|
| Web UI | http://localhost:3000 |
| Scanner API | http://localhost:8080/api/v1/health |

### Option B — Local dev

**1. Install tools**
```bash
brew install go jadx dex2jar   # macOS
```

**2. Start the scanner**
```bash
make scanner
```

**3. Start the web UI**
```bash
cp .env.example .env.local
npm install
npm run dev
```

### Option C — CLI (headless / CI)

```bash
cd scanner
go run ./cmd/apkbugfinder -p /path/to/app.apk
go run ./cmd/apkbugfinder -m /path/to/apks/
```

---

## Deploy in minutes

### Web UI → [Vercel](https://vercel.com)

1. Import [alexbieber/ApkBugFinder](https://github.com/alexbieber/ApkBugFinder) on Vercel
2. Click **Deploy** — zero config needed for the frontend
3. Set one env var: `SCANNER_API_URL` → your scanner host URL

### Scanner → Railway / Fly.io / any Docker host

```bash
docker build -f docker/Dockerfile.scanner -t apkbugfinder-scanner .
docker run -p 8080:8080 apkbugfinder-scanner
```

> **Why two services?** JADX decompilation needs a real server — it can't run on Vercel serverless. Split architecture = fast global UI + powerful scan engine.

---

## MASVS coverage

ApkBugFinder maps findings to the [OWASP Mobile Application Security Verification Standard](https://mobile-security.gitbook.io/masvs/):

| Category | Examples |
|----------|----------|
| **V2 — Storage** | SharedPreferences, SQLite, Firebase, logs, clipboard, hardcoded secrets |
| **V3 — Crypto** | Weak algorithms, static IVs, insecure random, hardcoded keys |
| **V4 — Auth** | Cookie handling, biometric implementation |
| **V5 — Network** | MITM risks, cleartext traffic, cert pinning, hostname verification |
| **V6 — Platform** | SQLi, XSS, WebView, implicit intents, exported components |
| **V7 — Code Quality** | Debuggable flag, StrictMode, obfuscation |
| **V8 — Resilience** | Root/debug/emulator detection, SafetyNet |

Every finding includes **MASVS ID**, **CWE reference**, **severity**, **evidence**, and **remediation**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  🌐  Next.js Web UI                                      │
│  Drag & drop · Dashboard · Export · Scan history         │
└────────────────────────────┬─────────────────────────────┘
                             │  POST /api/scan
┌────────────────────────────▼─────────────────────────────┐
│  ⚡  Go Scanner API                                       │
│                                                          │
│  APK ──► dex2jar ──► JADX ──► 70+ MASVS rules ──► JSON   │
└──────────────────────────────────────────────────────────┘
```

---

## API

Integrate ApkBugFinder into your pipeline:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | `GET` | Scanner status + dependency check |
| `/api/v1/scan` | `POST` | Upload APK (`multipart/form-data`, field: `apk`) |

**Example:**
```bash
curl -X POST -F "apk=@app-release.apk" http://localhost:8080/api/v1/scan
```

Returns structured JSON with `findings[]`, `stats`, `appInfo`, and `durationMs`.

---

## ApkBugFinder vs APKHunt

| | [APKHunt](https://github.com/Cyber-Buddy/APKHunt) | **ApkBugFinder** |
|---|:---:|:---:|
| Web UI | ❌ | ✅ |
| Interactive dashboard | ❌ | ✅ |
| Severity prioritization | ❌ | ✅ |
| JSON / export | ❌ | ✅ |
| macOS support | ❌ | ✅ |
| HTTP API | ❌ | ✅ |
| Docker one-liner | ❌ | ✅ |
| JADX + dex2jar engine | ✅ | ✅ |
| 70+ MASVS rules | ✅ | ✅ |
| Advanced secret detection | ❌ | ✅ |
| Vercel-ready frontend | ❌ | ✅ |

**APKHunt proved the engine works. ApkBugFinder makes it usable.**

---

## Project structure

```
ApkBugFinder/
├── src/                 # Next.js web UI
├── scanner/             # Go engine (JADX + MASVS rules)
│   ├── cmd/apkbugfinder/
│   └── internal/
│       ├── decompile/   # jadx + dex2jar
│       ├── engine/      # scan orchestration
│       ├── rules/       # 70+ MASVS checks
│       └── grep/        # pattern engine
├── docker/              # Production Dockerfiles
└── docker-compose.yml   # One-command local stack
```

---

## Roadmap

- [ ] HTML / PDF report export
- [ ] SARIF output for GitHub Advanced Security
- [ ] CI/CD GitHub Action (`scan-apk.yml`)
- [ ] APK version diff — new vs fixed findings
- [ ] Custom YAML rule plugins
- [ ] Team workspaces + auth

**Want a feature?** [Open an issue](https://github.com/alexbieber/ApkBugFinder/issues) or submit a PR.

---

## Contribute

ApkBugFinder is open source and built for the security community.

1. **Star the repo** — it helps others discover the project
2. **Report bugs** — [GitHub Issues](https://github.com/alexbieber/ApkBugFinder/issues)
3. **Add MASVS rules** — edit `scanner/internal/rules/rules.go`
4. **Improve the UI** — PRs welcome on `src/components/`

---

## Requirements

| Component | Requirements |
|-----------|-------------|
| **Scanner** | Go 1.22+, jadx, d2j-dex2jar, grep |
| **Web UI** | Node.js 18+ |

---

## License

MIT — free for personal and commercial use.

---

## Disclaimer

ApkBugFinder is intended for **legitimate security testing and code review only**. Only scan applications you own or have explicit permission to analyze. The authors are not responsible for misuse.

---

<div align="center">

**If ApkBugFinder saved you hours on a security review, consider giving it a star.**

[![Star on GitHub](https://img.shields.io/github/stars/alexbieber/ApkBugFinder?style=social)](https://github.com/alexbieber/ApkBugFinder/stargazers)

Built with care for the Android security community.

[⬆ Back to top](#apkbugfinder)

</div>
