// Signs a short-lived SSO token for the AI Builder studio (HS256 JWT, tenant id = `iss`).
// Server-side only: BUILDER_SECRET must never reach the browser.
//
// Required Vercel env vars (this project):
//   BUILDER_SECRET      same value as the tenant `secret` in the builder's TENANTS
//   BUILDER_TENANT      tenant id in the builder's TENANTS (letters, digits, dashes)
//   PORTAL_STUDIO_KEY   passphrase that gates the studio (this site has no login of its own)
// Optional: BUILDER_SITE (default "at-world"), TOKEN_TTL seconds (default 3600, max 86400)
const { createHmac, timingSafeEqual } = require("node:crypto");

const ID_RE = /^[a-z0-9-]+$/i;
const b64u = (v) => Buffer.from(v).toString("base64url");

function sign(claims, secret) {
  const data = `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}`;
  return `${data}.${createHmac("sha256", secret).update(data).digest("base64url")}`;
}

function sameString(a, b) {
  const x = createHmac("sha256", "cmp").update(String(a)).digest();
  const y = createHmac("sha256", "cmp").update(String(b)).digest();
  return timingSafeEqual(x, y);
}

module.exports = (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "method_not_allowed" });
  }

  const { BUILDER_SECRET, BUILDER_TENANT, PORTAL_STUDIO_KEY } = process.env;
  if (!BUILDER_SECRET || !BUILDER_TENANT || !PORTAL_STUDIO_KEY || !ID_RE.test(BUILDER_TENANT)) {
    return res.status(500).json({ error: "not_configured" });
  }

  const body = typeof req.body === "string" ? safeParse(req.body) : req.body || {};
  if (typeof body.key !== "string" || !sameString(body.key, PORTAL_STUDIO_KEY)) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const site = process.env.BUILDER_SITE || "at-world";
  if (!ID_RE.test(site)) return res.status(500).json({ error: "not_configured" });

  const ttl = Math.min(Math.max(Number(process.env.TOKEN_TTL) || 3600, 60), 86400);
  const exp = Math.floor(Date.now() / 1000) + ttl;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(sign({ iss: BUILDER_TENANT, sub: "portal-admin", site, exp }, BUILDER_SECRET));
};

function safeParse(s) {
  try {
    return JSON.parse(s) || {};
  } catch {
    return {};
  }
}
