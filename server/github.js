import crypto from "node:crypto";

let cachedInstallationToken = null;

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function createAppJwt() {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!appId || !privateKey) return null;
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({ iat: now - 30, exp: now + 540, iss: appId }));
  const unsigned = `${header}.${payload}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(unsigned), privateKey).toString("base64url");
  return `${unsigned}.${signature}`;
}

export function githubConfigured() {
  return Boolean(process.env.GITHUB_TOKEN || (process.env.GITHUB_APP_ID && process.env.GITHUB_APP_PRIVATE_KEY && process.env.GITHUB_INSTALLATION_ID));
}

export async function githubToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  if (cachedInstallationToken && cachedInstallationToken.expiresAt > Date.now() + 60_000) return cachedInstallationToken.token;
  const jwt = createAppJwt();
  const installationId = process.env.GITHUB_INSTALLATION_ID;
  if (!jwt || !installationId) return null;
  const response = await fetch(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: "POST",
    headers: { authorization: `Bearer ${jwt}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "chrollo-security-review" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`GitHub App authentication failed with HTTP ${response.status}`);
  const payload = await response.json();
  cachedInstallationToken = { token: payload.token, expiresAt: Date.parse(payload.expires_at) };
  return cachedInstallationToken.token;
}

export async function githubRequest(path, options = {}) {
  const token = await githubToken();
  if (!token) throw new Error("GitHub authentication is not configured.");
  const response = await fetch(`https://api.github.com${path}`, {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "chrollo-security-review",
      ...options.headers,
    },
    signal: options.signal || AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(payload?.message || `GitHub request failed with HTTP ${response.status}`);
  return payload;
}

export function remediationDocument(scan, finding) {
  const safeText = (value) => String(value || "").replace(/[<>]/g, (character) => character === "<" ? "&lt;" : "&gt;");
  const codeBlock = (value) => String(value || "").split(/\r?\n/).map((line) => `    ${line}`).join("\n");
  return [
    "# Chrollo remediation plan",
    "",
    `- Scan: ${scan.id}`,
    `- Repository commit: ${scan.repository.commit}`,
    `- Finding: ${finding.id}`,
    `- Severity: ${finding.severity}`,
    `- Location: ${finding.file}:${finding.line}`,
    "",
    "## Finding",
    "",
    safeText(finding.title),
    "",
    safeText(finding.aiExplanation || finding.explanation),
    "",
    "## Evidence",
    "",
    codeBlock(finding.evidence),
    "",
    "## Recommended change",
    "",
    codeBlock((finding.patch || []).join("\n")),
    "",
    "> Review and implement this recommendation before merging. Chrollo intentionally does not execute repository code.",
    "",
  ].join("\n");
}

export async function createRemediationPullRequest(scan, finding) {
  const owner = scan.repository.owner;
  const repository = scan.repository.name;
  const prefix = (process.env.CHROLLO_PR_BRANCH_PREFIX || "chrollo/fix").replace(/[^A-Za-z0-9/_-]/g, "-");
  const branch = `${prefix}-${finding.id.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 48)}-${Date.now().toString(36)}`;
  const repositoryData = await githubRequest(`/repos/${owner}/${repository}`);
  const base = repositoryData.default_branch;
  await githubRequest(`/repos/${owner}/${repository}/git/commits/${scan.repository.commit}`);
  let branchCreated = false;
  try {
    await githubRequest(`/repos/${owner}/${repository}/git/refs`, { method: "POST", body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: scan.repository.commit }) });
    branchCreated = true;
    const planPath = `.chrollo/remediation-${finding.id.replace(/[^A-Za-z0-9_.-]/g, "-")}.md`;
    await githubRequest(`/repos/${owner}/${repository}/contents/${planPath}`, {
      method: "PUT",
      body: JSON.stringify({
        message: `docs(security): plan remediation for ${finding.id}`,
        content: Buffer.from(remediationDocument(scan, finding)).toString("base64"),
        branch,
      }),
    });
    const pull = await githubRequest(`/repos/${owner}/${repository}/pulls`, {
      method: "POST",
      body: JSON.stringify({
        title: `Security remediation: ${finding.title}`,
        head: branch,
        base,
        draft: true,
        body: `Chrollo prepared a reviewable remediation plan for **${finding.id}** at \`${finding.file}:${finding.line}\`.\n\nThe branch starts from the exact scanned commit \`${scan.repository.commit.slice(0, 12)}\`. This draft does not claim the vulnerability is fixed. Implement the recommended change, run tests, and rescan before marking it ready for review.`,
      }),
    });
    return { number: pull.number, url: pull.html_url, branch, base, scannedCommit: scan.repository.commit, draft: pull.draft };
  } catch (error) {
    if (branchCreated) {
      try { await githubRequest(`/repos/${owner}/${repository}/git/refs/heads/${branch}`, { method: "DELETE" }); } catch { /* best-effort cleanup */ }
    }
    throw error;
  }
}
