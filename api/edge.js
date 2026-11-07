export const config = { runtime: "edge" };
// i100119: same bounded probe on Vercel EDGE runtime (different egress class than /api/egress).
const ALLOW = {
  gw: { host: "api-gateway.transak.com", path: "/api/v2/auth/session" },
};
const TOKEN = "b7c1e9f04a2d4c6e8a1b3d5f7091c2e4";
export default async function handler(req) {
  const u = new URL(req.url);
  const q = u.searchParams;
  if (q.get("t") !== TOKEN) return new Response(JSON.stringify({ e: "nf" }), { status: 404 });
  if (q.get("p") === "ident") {
    const r = await fetch("https://api.ipify.org?format=json");
    return new Response(await r.text(), { status: 200, headers: { "content-type": "application/json" } });
  }
  const t = ALLOW[q.get("p")];
  if (!t) return new Response(JSON.stringify({ e: "bad target" }), { status: 400 });
  const headers = {
    "content-type": "application/json",
    "accept": "application/json",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  };
  for (const h of ["x-api-key", "access-token", "origin", "referer"]) {
    const v = q.get("h_" + h);
    if (v) headers[h] = v;
  }
  const body = q.get("b") ? Uint8Array.from(atob(q.get("b")), c => c.charCodeAt(0)) : undefined;
  const r = await fetch(`https://${t.host}${t.path}`, { method: "POST", headers, body });
  const txt = await r.text();
  return new Response(JSON.stringify({ status: r.status, body: txt.slice(0, 4000), h: { deny: r.headers.get("x-deny-reason") } }), { status: 200, headers: { "content-type": "application/json" } });
}
