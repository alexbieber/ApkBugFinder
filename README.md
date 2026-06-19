# Apkbugfinder

Advanced OWASP MASVS static security analyzer for Android APK files — web UI + Go scanner engine.

**Matches [APKHunt](https://github.com/Cyber-Buddy/APKHunt) technology stack** (JADX, dex2jar, grep-on-decompiled-Java) with **70+ MASVS rules**, then adds advanced secret detection and a modern dashboard.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Next.js Web UI (Vercel)                                │
│  Upload APK → /api/scan proxy → Scanner API             │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│  Go Scanner API (Docker / Railway / Fly.io)             │
│  1. d2j-dex2jar  →  JAR                                 │
│  2. jadx --deobf →  Java sources + manifest           │
│  3. grep rules   →  MASVS findings (APKHunt parity)     │
│  4. advanced     →  AWS/Stripe/JWT secret detection     │
└─────────────────────────────────────────────────────────┘
```

## APKHunt parity

| APKHunt | Apkbugfinder |
|---------|--------------|
| Go monolith CLI | Go modular API + CLI |
| JADX + dex2jar | Same pipeline |
| grep on `.java` / `.xml` | Native Go grep engine (same patterns) |
| OWASP MASVS v1.5 MSTG IDs | Same MSTG-* rule IDs |
| Linux only | macOS + Linux via Docker |
| TXT output | JSON + interactive web UI |
| Single file 3100 lines | Plugin-style `rules.go` |

### MASVS coverage (70+ checks)

- **V2** Storage: SharedPreferences, SQLite, Firebase, logs, clipboard, hardcoded secrets
- **V3** Crypto: weak algorithms, static IVs, insecure random
- **V4** Auth: cookies, biometrics
- **V5** Network: MITM, TLS, cleartext, cert pinning, hostname verification
- **V6** Platform: SQLi, XSS, WebView, intents, permissions, serialization
- **V7** Code: debuggable, StrictMode, obfuscation
- **V8** Resilience: root/debug/emulator detection, SafetyNet

### Advanced (on top of APKHunt)

- AWS / Google API / Stripe / JWT secret patterns
- AES-ECB / MD5 detection in decompiled source
- Component export summary in UI
- MASVS reference links per finding
- Scan history + JSON export

## Quick start (Docker — recommended)

```bash
# Build and run scanner + web UI
docker compose up --build

# Web UI:  http://localhost:3000
# Scanner: http://localhost:8080/api/v1/health
```

## Local development

### 1. Scanner (requires Go 1.22+, jadx, dex2jar, grep)

```bash
# macOS
brew install go jadx dex2jar

# Start scanner API
make scanner
# or: cd scanner && go run ./cmd/apkbugfinder -serve
```

### 2. Web UI

```bash
cp .env.example .env.local
npm install
npm run dev
```

Open http://localhost:3000 — the UI detects scanner health automatically.

### CLI (APKHunt-style)

```bash
cd scanner
go run ./cmd/apkbugfinder -p /path/to/app.apk
go run ./cmd/apkbugfinder -m /path/to/apks/
```

## Deploy

### Web UI → Vercel

1. Push to GitHub
2. Import on [vercel.com](https://vercel.com)
3. Set environment variable:
   - `SCANNER_API_URL` = your scanner host (Railway/Fly.io URL)

The UI on Vercel proxies scans to your scanner — JADX cannot run on Vercel serverless.

### Scanner → Railway / Fly.io / any Docker host

Deploy `docker/Dockerfile.scanner`:

```bash
docker build -f docker/Dockerfile.scanner -t apkbugfinder-scanner .
docker run -p 8080:8080 apkbugfinder-scanner
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Scanner status + tool check |
| `/api/v1/scan` | POST | Upload APK (`multipart`, field: `apk`) |

## Project structure

```
Apkbugfinder/
├── src/                    # Next.js web UI
├── scanner/                # Go scanner (APKHunt engine)
│   ├── cmd/apkbugfinder/   # CLI + HTTP server
│   └── internal/
│       ├── decompile/      # jadx + dex2jar
│       ├── engine/         # scan orchestration
│       ├── grep/           # pattern matching
│       ├── manifest/       # AndroidManifest parsing
│       └── rules/          # all MASVS rules
├── docker/                 # Dockerfiles
└── docker-compose.yml
```

## Requirements

**Scanner host:** Go 1.22+, jadx, d2j-dex2jar, grep  
**Web UI:** Node.js 18+

## License

MIT

## Disclaimer

For legitimate security testing only. Scan apps you own or have permission to analyze.
