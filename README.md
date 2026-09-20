# Chrollo

Chrollo is a repository security review workspace built by **Phantom Troupe** for HackSpire. It creates an isolated shallow clone of an authorized public GitHub repository, scans it without executing project code, normalizes the evidence, and records reviewer decisions.

## What works

- Real shallow cloning of public GitHub repositories
- Built-in source security rules for command injection, NoSQL injection, XSS, unsafe evaluation and disabled TLS checks
- Secret detection with evidence redaction
- Dependency baseline checks for known vulnerable package versions
- Normalized severity, evidence, remediation and scoring
- Persistent scan history in a local JSON store
- Approve/dismiss review decisions
- Optional Gemini explanations when a key is explicitly configured
- Static demo fallback when the UI is opened without the Node service
- Responsive review UI and WebMCP finding lookup
- Docker support and automated tests

Chrollo never runs code from a scanned repository. Clones are stored in a random operating-system temporary directory and removed after each scan.

## Requirements

- Node.js 20 or newer
- Git available on `PATH`
- Internet access for cloning public repositories

## Run locally

```powershell
npm start
```

Open <http://127.0.0.1:4173>. No package installation is required because the application uses only Node.js built-ins.

For development with automatic restart:

```powershell
npm run dev
```

## Optional Gemini explanations

Copy `.env.example` to `.env`, set `GEMINI_API_KEY`, then load those variables before starting the process. Evidence is sent to Gemini only when the key is configured and the reviewer clicks **Explain with AI**.

## Verify

```powershell
npm run check
npm test
```

## API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service and AI configuration status |
| `GET` | `/api/scans` | Recent scan summaries |
| `POST` | `/api/scans` | Scan `{ "repositoryUrl": "https://github.com/owner/repo" }` |
| `GET` | `/api/scans/:id` | Full normalized scan |
| `POST` | `/api/scans/:id/rescan` | Clone and scan the repository again |
| `POST` | `/api/scans/:id/findings/:findingId/decision` | Approve or reject a recommendation |
| `POST` | `/api/scans/:id/findings/:findingId/explain` | Request an optional Gemini explanation |

## Project structure

```text
dist/               browser application
server/app.js       HTTP server and API routing
server/repository.js isolated Git clone lifecycle
server/scanners.js  source, secret and dependency scanners
server/service.js   audit orchestration and decisions
server/store.js     persistent scan history
test/               automated tests
```

## Scope and safety

The built-in scanner is an explainable hackathon implementation, not a replacement for a commercial SAST platform. Before production use, add authentication, per-user authorization, rate limiting, a job queue, database-backed storage, container-level clone isolation, and mature tools such as Semgrep, Gitleaks and OSV-Scanner.
