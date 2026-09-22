# Chrollo

Chrollo is a repository security review workspace built by **Phantom Troupe** for HackSpire. Locally it creates an isolated shallow Git clone; on Vercel it downloads a commit-pinned GitHub archive. It scans the snapshot without executing project code, normalizes the evidence, and records reviewer decisions.

## What works

- Real shallow cloning of public GitHub repositories
- GitHub metadata preflight with configurable repository-size limits
- Built-in source security rules for command injection, NoSQL injection, XSS, unsafe evaluation and disabled TLS checks
- Secret detection with evidence redaction
- Dependency baseline checks for known vulnerable package versions
- Live OSV.dev dependency queries with an offline fallback
- OSV coverage for npm, Python, Go, Ruby, Composer and Rust lock files
- Multiline JavaScript, Python, Java and React context rules
- Recent Git-history secret scanning
- Normalized severity, evidence, remediation and scoring
- Persistent scan history in a local JSON store
- Approve/dismiss review decisions
- Severity, scanner and security-score charts
- Baseline-versus-rescan comparisons
- JSON and GitHub-compatible SARIF exports
- Optional Semgrep, Gitleaks and OSV-Scanner adapters
- Per-client API rate limiting
- Bounded asynchronous scan queue with live progress and back-pressure
- Clone-disk, total scan-byte and individual file-size limits
- Stable finding fingerprints for accurate comparisons after line changes
- Same-origin write protection, structured request logs and runtime metrics
- Secret-free environments and isolated home directories for external scanner processes
- Atomic finding updates and duplicate-remediation suppression
- Optional Gemini explanations when a key is explicitly configured
- GitHub App or fine-grained token authentication for authorized private repositories
- Draft remediation pull requests after reviewer approval
- Optional Supabase persistence with automatic local fallback
- Static demo fallback when the UI is opened without the Node service
- Responsive review UI and WebMCP finding lookup
- Docker support and automated tests
- Native Vercel Function entry point and deployment configuration
- Commit-pinned, size-limited GitHub archive acquisition for serverless deployments

Chrollo never runs code from a scanned repository. Repository snapshots are stored in a random operating-system temporary directory and removed after each scan. Stale local clone directories are removed when the Node service starts.

## Requirements

- Node.js 20 or newer
- Git available on `PATH`
- Internet access for cloning public repositories

## Run locally

```powershell
npm start
```

Open <http://127.0.0.1:4173>.

For development with automatic restart:

```powershell
npm run dev
```

## Deploy to Vercel

The repository includes `vercel.json` and `api/index.js`; do not set a custom framework preset or output directory in the Vercel dashboard.

1. Create a Supabase project and run [`supabase/schema.sql`](supabase/schema.sql) in its SQL editor.
2. Import this GitHub repository into Vercel.
3. Add the environment variables below for Production and Preview.
4. Enable Fluid Compute in the Vercel project settings and leave the Function duration at 300 seconds.
5. Deploy, then open `/api/health`. A production-ready response reports `runtime: "vercel-function"` and persistence with `configured: true`.

Required for durable operation:

```text
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-server-only-service-role-key
```

Recommended for private repositories and higher GitHub API limits:

```text
GITHUB_TOKEN=your-fine-grained-token
```

Copy the remaining limits from [`.env.vercel.example`](.env.vercel.example). Never add `.env` files or service-role keys to Git. Vercel automatically sets `VERCEL=1`, which makes Chrollo:

- export an HTTP function instead of opening a listening port;
- run scans within the initiating request instead of relying on an in-memory background queue;
- download a commit-pinned GitHub archive instead of invoking a system Git binary;
- use `/tmp` only as disposable working space;
- cap returned findings to stay below the Function response limit;
- disable host-installed executable scanners and Git-history scanning.

If Supabase is not configured, individual scans still work, but history, exports, decisions and rescans are not reliable across Function invocations. `/api/health` reports this state as `degraded`.

For access control, use Vercel Deployment Protection or an identity-aware proxy. `CHROLLO_API_TOKEN` is intended for API-only deployments because exposing a shared bearer token in browser JavaScript would not be secure.

## Optional production scanners

Install Semgrep, Gitleaks and OSV-Scanner on the host, then set:

```text
CHROLLO_EXTERNAL_SCANNERS=true
```

Chrollo runs available tools without executing repository code and merges their results with the built-in scanners. Missing tools are skipped, so the application remains usable during the hackathon.

## Configure integrations

Copy `.env.example` to `.env`. Chrollo loads this file automatically and never serves it to the browser.

For an externally reachable API, set `CHROLLO_API_TOKEN` and have authenticated API clients send it as a bearer token. The built-in browser UI is intended for localhost or for deployment behind an identity-aware reverse proxy.
Chrollo refuses to bind `CHROLLO_HOST` to a non-loopback address unless `CHROLLO_API_TOKEN` is configured. Scan creation has a stricter rate limit than read-only API polling.

### Gemini

Set `GEMINI_API_KEY`. Evidence is sent to Gemini only when a reviewer explicitly clicks **Explain with AI**.

### GitHub App and private repositories

Create and install a GitHub App on the repositories Chrollo may scan. Give it **Contents: read and write** and **Pull requests: read and write**, then configure:

```text
GITHUB_APP_ID=
GITHUB_INSTALLATION_ID=
GITHUB_APP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

For local development, a fine-grained `GITHUB_TOKEN` scoped to selected repositories is also supported. The token is passed to Git per command and is never written into a remote URL.

After a finding is approved, Chrollo can create a draft pull request containing a remediation plan, evidence and the proposed diff. The PR remains draft because applying security changes without repository tests would be unsafe.

### Supabase

Run [`supabase/schema.sql`](supabase/schema.sql) in the Supabase SQL editor, then set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`. Keep the service-role key on the server. If Supabase is unavailable, Chrollo continues using its local JSON store and reports the fallback through `/api/health`.

## Verify

```powershell
npm run check
npm test
```

## API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service and AI configuration status |
| `GET` | `/api/metrics` | Queue, storage, memory and uptime metrics |
| `GET` | `/api/jobs/:id` | Queued scan progress and completed result |
| `GET` | `/api/scans` | Recent scan summaries |
| `POST` | `/api/scans` | Scan `{ "repositoryUrl": "https://github.com/owner/repo" }` |
| `GET` | `/api/scans/:id` | Full normalized scan |
| `GET` | `/api/scans/:id?format=json` | Download a JSON report |
| `GET` | `/api/scans/:id?format=sarif` | Download a SARIF 2.1 report |
| `POST` | `/api/scans/:id/rescan` | Clone and scan the repository again |
| `POST` | `/api/scans/:id/findings/:findingId/decision` | Approve or reject a recommendation |
| `POST` | `/api/scans/:id/findings/:findingId/explain` | Request an optional Gemini explanation |
| `POST` | `/api/scans/:id/findings/:findingId/remediate` | Create an approved draft remediation PR |

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

The built-in scanner is an explainable hackathon implementation, not a replacement for a commercial SAST platform. Chrollo now enforces a bounded queue, repository and scan limits, optional API authentication, same-origin writes and durable storage integration. A public multi-user deployment should still place it behind an identity-aware proxy, isolate each worker at the container or VM level, and install mature tools such as Semgrep, Gitleaks and OSV-Scanner for deeper interprocedural analysis.
