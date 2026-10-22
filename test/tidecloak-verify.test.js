// Offline checks of the TideCloak token + DPoP verifier (shared/tidecloak.js). A local Ed25519 key
// stands in for the realm's Tide key, and an ES256 key for the browser's DPoP key, exactly as
// @tidecloak/js produces them.
const { test, before } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REALM = 'http://localhost:8080/realms/water-treatment';
const CLIENT = 'water-treatment-dashboard';
const realmKey = crypto.generateKeyPairSync('ed25519');
const dpopKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const dpopJwk = dpopKey.publicKey.export({ format: 'jwk' });
let tc;

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jkt = (j) => crypto.createHash('sha256').update(JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y })).digest('base64url');

function accessToken(overrides = {}, key = realmKey.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: REALM, azp: CLIENT, preferred_username: 'priya', exp: now + 600, iat: now, cnf: { jkt: jkt(dpopJwk) }, ...overrides };
  const head = b64({ alg: 'EdDSA', typ: 'JWT' });
  const body = b64(claims);
  return `${head}.${body}.${crypto.sign(null, Buffer.from(`${head}.${body}`), key).toString('base64url')}`;
}

function proof(token, { htm = 'POST', htu = 'http://localhost:5000/authorize', key = dpopKey.privateKey, jwk = dpopJwk, jti } = {}) {
  const head = b64({ alg: 'ES256', typ: 'dpop+jwt', jwk });
  const body = b64({
    jti: jti || crypto.randomUUID(), htm, htu, iat: Math.floor(Date.now() / 1000),
    ath: crypto.createHash('sha256').update(token).digest('base64url')
  });
  const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), { key, dsaEncoding: 'ieee-p1363' });
  return `${head}.${body}.${sig.toString('base64url')}`;
}

const req = (token, dpop, { scheme = 'DPoP', method = 'POST' } = {}) => ({
  method, originalUrl: '/authorize', protocol: 'http',
  headers: { host: 'localhost:5000', authorization: `${scheme} ${token}`, ...(dpop ? { dpop } : {}) }
});

before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wtd-tc-'));
  const jwk = { ...realmKey.publicKey.export({ format: 'jwk' }), kid: 'realm', alg: 'EdDSA', use: 'sig' };
  fs.writeFileSync(path.join(dir, 'tidecloak.json'), JSON.stringify({
    realm: 'water-treatment', 'auth-server-url': 'http://localhost:8080', resource: CLIENT, jwk: { keys: [jwk] }
  }));
  process.env.TIDECLOAK_DATA_DIR = dir;
  process.env.TIDE_MODE = 'tidecloak';
  tc = require('../shared/tidecloak');
});

test('a realm-signed, DPoP-bound token with a fresh proof is accepted', () => {
  const t = accessToken();
  assert.equal(tc.sessionClaims(req(t, proof(t))).preferred_username, 'priya');
});

test('forged, foreign-client and expired tokens are refused', () => {
  const forged = accessToken({}, crypto.generateKeyPairSync('ed25519').privateKey);
  assert.equal(tc.sessionClaims(req(forged, proof(forged))), null);
  const other = accessToken({ azp: 'some-other-app' });
  assert.equal(tc.sessionClaims(req(other, proof(other))), null);
  const old = accessToken({ exp: Math.floor(Date.now() / 1000) - 5 });
  assert.equal(tc.sessionClaims(req(old, proof(old))), null);
});

test('a stolen bound token cannot be replayed without the browser key', () => {
  const t = accessToken();
  assert.equal(tc.sessionClaims(req(t, null, { scheme: 'Bearer' })), null, 'replayed as a plain Bearer');
  const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const wrongKey = proof(t, { key: attacker.privateKey, jwk: attacker.publicKey.export({ format: 'jwk' }) });
  assert.equal(tc.sessionClaims(req(t, wrongKey)), null, 'proof from a different key');
  const p = proof(t);
  assert.ok(tc.sessionClaims(req(t, p)));
  assert.equal(tc.sessionClaims(req(t, p)), null, 'same proof twice (jti replay)');
  assert.equal(tc.sessionClaims(req(t, proof(t, { htu: 'http://localhost:5000/reject' }))), null, 'proof for another endpoint');
});
