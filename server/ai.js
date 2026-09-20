export async function explainFinding(finding) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  const model = process.env.GEMINI_MODEL || "gemini-2.0-flash";
  const prompt = [
    "You are a secure-code reviewer. Explain this scanner finding in no more than 100 words.",
    "Do not invent repository context. Include impact and one concrete remediation.",
    JSON.stringify({
      title: finding.title,
      severity: finding.severity,
      rule: finding.rule,
      file: finding.file,
      line: finding.line,
      evidence: finding.evidence,
    }),
  ].join("\n");
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`Gemini request failed with HTTP ${response.status}`);
  const payload = await response.json();
  return payload.candidates?.[0]?.content?.parts?.map((part) => part.text).join("\n").trim() || null;
}
