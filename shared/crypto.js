// Small Ed25519 + JWT helpers shared by every service. No service-specific keys live here.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RUNTIME_DIR = process.env.RUNTIME_DIR || path.join(__dirname, '..', '.runtime');

// Deterministic JSON so the same object always produces the same bytes / digest.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

function digest(value) {
  return crypto.createHash('sha256').update(canonical(value)).digest('hex');
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function generateKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function sign(privateKey, value) {
  return crypto.sign(null, Buffer.from(canonical(value)), privateKey).toString('base64');
}

function verify(publicKey, value, signature) {
  try {
    return crypto.verify(null, Buffer.from(canonical(value)), publicKey, Buffer.from(String(signature), 'base64'));
  } catch {
    return false;
  }
}

function signJwt(privateKey, claims) {
  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }));
  const body = b64url(JSON.stringify(claims));
  const sig = crypto.sign(null, Buffer.from(`${header}.${body}`), privateKey);
  return `${header}.${body}.${b64url(sig)}`;
}

function verifyJwt(publicKey, token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(`${header}.${body}`), publicKey, Buffer.from(sig, 'base64url'));
  } catch {
    return null;
  }
  if (!ok) return null;
  const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (claims.exp && Date.now() / 1000 > claims.exp) return null;
  return claims;
}

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

function cors(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// A public key published by one service and pinned by another (out-of-band, via the filesystem).
function publishPublicKey(name, publicKey) {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });
  fs.writeFileSync(path.join(RUNTIME_DIR, `${name}.pub.pem`), publicKey.export({ type: 'spki', format: 'pem' }));
}

function loadPinnedPublicKey(name) {
  const file = path.join(RUNTIME_DIR, `${name}.pub.pem`);
  if (!fs.existsSync(file)) return null;
  return crypto.createPublicKey(fs.readFileSync(file));
}

module.exports = {
  canonical,
  digest,
  generateKeyPair,
  sign,
  verify,
  signJwt,
  verifyJwt,
  bearer,
  cors,
  publishPublicKey,
  loadPinnedPublicKey,
  RUNTIME_DIR
};
