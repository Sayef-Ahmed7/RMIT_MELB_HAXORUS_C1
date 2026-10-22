// Real TideCloak identity, shared by the Tide gateway and the app backend when TIDE_MODE=tidecloak.
//
// - Access tokens are EdDSA JWTs signed by the Tide network's threshold key (no single TideCloak
//   server can mint one). We verify them only against the realm JWK embedded in the adapter config
//   that the bootstrap exports. There is no remote JWKS fetch (Tide pack I-04).
// - Tokens are DPoP-bound (cnf.jkt). A bound token is only accepted with a valid RFC 9449 proof from
//   the same browser key, so a token lifted from a log or proxy cannot be replayed.
//   This is a CommonJS port of the pack's templates/dpop-verify/verifyDpop.ts.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MODE = (process.env.TIDE_MODE || 'sim').toLowerCase();
const DATA_DIR = process.env.TIDECLOAK_DATA_DIR || path.join(__dirname, '..', 'tidecloak', 'data');
const IAT_SKEW_SECONDS = 300;

let adapter = null;
function adapterConfig() {
  if (!adapter) {
    const file = path.join(DATA_DIR, 'tidecloak.json');
    if (!fs.existsSync(file)) throw new Error(`TIDE_MODE=tidecloak but ${file} is missing. Run: npm run tidecloak:bootstrap`);
    adapter = JSON.parse(fs.readFileSync(file, 'utf8'));
  }
  return adapter;
}

const baseUrl = () => String(adapterConfig()['auth-server-url']).replace(/\/$/, '');
const realmUrl = () => `${baseUrl()}/realms/${adapterConfig().realm}`;

let realmKeys = null;
function realmPublicKeys() {
  if (!realmKeys) {
    const jwk = adapterConfig().jwk;
    const keys = jwk && Array.isArray(jwk.keys) ? jwk.keys : [jwk];
    realmKeys = keys.filter(Boolean).map((k) => ({ kid: k.kid, key: crypto.createPublicKey({ key: k, format: 'jwk' }) }));
  }
  return realmKeys;
}

const b64json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

// Verify a TideCloak access token: EdDSA signature by the realm key, issuer, expiry, and that it
// was issued to this dashboard's client.
function verifyAccessToken(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  let header; let claims;
  try { header = b64json(parts[0]); claims = b64json(parts[1]); } catch { return null; }
  if (header.alg !== 'EdDSA') return null;
  const keys = realmPublicKeys().filter((k) => !header.kid || !k.kid || k.kid === header.kid);
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], 'base64url');
  if (!keys.some((k) => { try { return crypto.verify(null, data, k.key, sig); } catch { return false; } })) return null;
  const now = Date.now() / 1000;
  if (claims.iss !== realmUrl()) return null;
  if (!claims.exp || now > claims.exp) return null;
  const client = adapterConfig().resource;
  const aud = [].concat(claims.aud || []);
  if (claims.azp !== client && !aud.includes(client)) return null;
  return claims;
}

// ---------- DPoP (RFC 9449) ----------

const seenJti = new Map();
function claimJti(jti) {
  const now = Date.now();
  for (const [k, exp] of seenJti) if (exp < now) seenJti.delete(k);
  if (seenJti.has(jti)) return false;
  seenJti.set(jti, now + IAT_SKEW_SECONDS * 1000);
  return true;
}

function jwkThumbprint(jwk) {
  const members = jwk.kty === 'EC' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    : jwk.kty === 'OKP' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      : { e: jwk.e, kty: jwk.kty, n: jwk.n };
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

function verifyJws(proof, jwk, alg) {
  const [h, p, s] = proof.split('.');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const data = Buffer.from(`${h}.${p}`);
  const sig = Buffer.from(s, 'base64url');
  if (alg === 'ES256') return crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (alg === 'EdDSA') return crypto.verify(null, data, key, sig);
  return false;
}

// The URL the browser signed into htu: origin + path, no query string.
function requestHtu(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  return `${proto}://${String(host).split(',')[0].trim()}${req.originalUrl.split('?')[0]}`;
}

function verifyDpop(req, accessToken, claims) {
  const jkt = claims.cnf && claims.cnf.jkt;
  if (!jkt) throw new Error('Access token is not sender-constrained (no cnf.jkt)');
  if (!/^DPoP /i.test(req.headers.authorization || '')) throw new Error('Bound token presented without the DPoP scheme');
  const proof = req.headers.dpop;
  if (!proof || proof.split('.').length !== 3) throw new Error('Missing DPoP proof');
  const header = b64json(proof.split('.')[0]);
  if (header.typ !== 'dpop+jwt' || !header.jwk) throw new Error('Malformed DPoP proof header');
  if (!verifyJws(proof, header.jwk, header.alg)) throw new Error('DPoP proof signature invalid');
  if (jwkThumbprint(header.jwk) !== jkt) throw new Error('DPoP key does not match the token binding');
  const payload = b64json(proof.split('.')[1]);
  const ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
  if (payload.ath !== ath) throw new Error('DPoP proof is for a different access token');
  if (String(payload.htm).toUpperCase() !== req.method.toUpperCase()) throw new Error('DPoP htm mismatch');
  if (payload.htu !== requestHtu(req)) throw new Error(`DPoP htu mismatch (${payload.htu})`);
  if (!Number.isFinite(payload.iat) || Math.abs(Date.now() / 1000 - payload.iat) > IAT_SKEW_SECONDS) throw new Error('DPoP proof expired');
  if (!payload.jti || !claimJti(payload.jti)) throw new Error('DPoP proof replayed');
}

// Resolve the caller of an Express request from their TideCloak session. Returns the verified
// claims, or null. Every protected route in tidecloak mode goes through this.
function sessionClaims(req) {
  const m = /^(DPoP|Bearer) (.+)$/i.exec(req.headers.authorization || '');
  if (!m) return null;
  const claims = verifyAccessToken(m[2]);
  if (!claims) return null;
  try {
    verifyDpop(req, m[2], claims);
  } catch (err) {
    console.warn(`[tidecloak] DPoP rejected: ${err.message}`);
    return null;
  }
  return claims;
}

// ---------- Read-only service account (live roles + policy) ----------
// The Tide gateway reads roles and the quorum policy live from TideCloak, rather than trusting what a
// token said ten minutes ago. Its client only has view-users and view-realm: it can read the rules,
// never change them. Changes go through TideCloak change requests signed by an admin quorum.

let readerToken = null;
async function reader(pathname) {
  const a = adapterConfig();
  const base = baseUrl();
  if (!readerToken || readerToken.exp < Date.now() + 5000) {
    const creds = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'policy-reader.json'), 'utf8'));
    const res = await fetch(`${base}/realms/${a.realm}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: creds.clientId, client_secret: creds.secret })
    });
    if (!res.ok) throw new Error(`policy reader login failed (${res.status})`);
    const t = await res.json();
    readerToken = { value: t.access_token, exp: Date.now() + t.expires_in * 1000 };
  }
  const res = await fetch(`${base}/admin/realms/${a.realm}${pathname}`, { headers: { Authorization: `Bearer ${readerToken.value}` } });
  if (!res.ok) throw new Error(`TideCloak read ${pathname} failed (${res.status})`);
  return res.json();
}

module.exports = {
  MODE,
  enabled: MODE === 'tidecloak',
  adapterConfig,
  baseUrl,
  realmUrl,
  verifyAccessToken,
  sessionClaims,
  reader
};
