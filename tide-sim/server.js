// Tide gateway: the quorum policy and the command-authority signer, with identity from TideCloak.
//
// TIDE_MODE=tidecloak (the demo):
//   - identity: real TideCloak. Callers present their own DPoP-bound TideCloak access token, signed by
//     the Tide network's threshold key, which no single server can mint.
//   - roles + policy: read live from TideCloak through a read-only service account. They can only be
//     changed by a TideCloak change request approved by a quorum of admins in their own Tide enclaves.
//     This gateway has no admin endpoints at all in this mode.
//   - authority signing: still local (Fallback B). Once the quorum is met it signs the exact command
//     with an Ed25519 key the PLC pins. In full Tide this signature would come from the ORK network
//     under a Forseti policy; see README "TideCloak integration status".
//
// TIDE_MODE=sim (npm test, offline): the same API, with a local IdP and admin quorum standing in for
// TideCloak, because a headless test cannot complete a Tide enclave login.
//
// The app backend never sees the authority private key. The PLC pins the authority *public* key.
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const {
  digest, generateKeyPair, sign, signJwt, verifyJwt, bearer, cors, publishPublicKey
} = require('../shared/crypto');
const { PLANT_ID, PARAMETERS, scoreRequest, requiresEngineer } = require('../shared/plant');
const { PERSONAS } = require('../shared/personas');
const tc = require('../shared/tidecloak');

const PORT = Number(process.env.TIDE_PORT || 5000);
const AUTH_TTL_SECONDS = 300;

const idpKeys = generateKeyPair();
const authorityKeys = generateKeyPair();
publishPublicKey('tide-idp', idpKeys.publicKey);
publishPublicKey('tide-authority', authorityKeys.publicKey);

const ledger = new Map(); // requestDigest -> { request, endorsements, rejectedBy, issued }
const events = [];

function log(kind, message, details = {}) {
  events.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), source: 'tide', kind, message, details });
  if (events.length > 300) events.pop();
  console.log(`[tide] ${kind.toUpperCase()} ${message}`);
}

const displayName = (id) => (PERSONAS.find((p) => p.username === id) || { name: id }).name;

// ---------- Directory: who is calling, what roles they hold, what the policy is ----------

// Simulated TideCloak. Passwords are deliberately weak: the attacker panel "steals" them.
function simDirectory() {
  const users = Object.fromEntries(PERSONAS.map((p) => [p.username, { ...p, password: 'demo', roles: [...p.roles] }]));
  const policy = { version: 1, engineerApprovals: 1, adminQuorum: 2 };
  return {
    users,
    policyState: policy,
    async caller(req) {
      const claims = verifyJwt(idpKeys.publicKey, bearer(req));
      return claims && users[claims.sub] ? claims.sub : null;
    },
    async roles(id) { return users[id] ? [...users[id].roles] : []; },
    async policy() { return policy; },
    async list() {
      return Object.values(users).map((u) => ({ id: u.username, name: u.name, title: u.title, roles: [...u.roles] }));
    }
  };
}

// Real TideCloak. Roles are read live (2s cache), never trusted from a token that may be minutes old.
function tidecloakDirectory() {
  const cache = new Map();
  async function cached(key, load) {
    const hit = cache.get(key);
    if (hit && hit.at > Date.now() - 2000) return hit.value;
    const value = await load();
    cache.set(key, { at: Date.now(), value });
    return value;
  }
  async function userRoles(id) {
    return cached(`roles:${id}`, async () => {
      const [u] = await tc.reader(`/users?username=${encodeURIComponent(id)}&exact=true`);
      if (!u) return [];
      const roles = await tc.reader(`/users/${u.id}/role-mappings/realm/composite`);
      return roles.map((r) => r.name).filter((n) => ['operator', 'engineer', 'admin'].includes(n));
    });
  }
  return {
    async caller(req) {
      const claims = tc.sessionClaims(req);
      return claims ? claims.preferred_username : null;
    },
    roles: userRoles,
    async policy() {
      return cached('policy', async () => {
        const realm = await tc.reader('');
        const attrs = realm.attributes || {};
        const n = Number(attrs['wtd.engineerApprovals']);
        return {
          version: attrs['wtd.policyVersion'] || 'tidecloak',
          engineerApprovals: Number.isInteger(n) ? n : 1,
          // TideCloak sets the admin quorum itself: 70% of realm admins, enforced by the Tide network.
          adminQuorum: null,
          source: 'tidecloak'
        };
      });
    },
    async list() {
      const out = [];
      for (const p of PERSONAS) out.push({ id: p.username, name: p.name, title: p.title, roles: await userRoles(p.username) });
      return out;
    }
  };
}

const directory = tc.enabled ? tidecloakDirectory() : simDirectory();
const hasRole = async (id, role) => (await directory.roles(id)).includes(role);

const app = express();
app.use(cors);
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true, service: 'tide-gateway', mode: tc.MODE }));

app.get('/keys', (req, res) => res.json({
  idp: idpKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  authority: authorityKeys.publicKey.export({ type: 'spki', format: 'pem' })
}));

app.post('/login', (req, res) => {
  if (tc.enabled) return res.status(410).json({ error: 'Passwords are not accepted here. Sign in with TideCloak.' });
  const { username, password, device } = req.body || {};
  const u = directory.users[username];
  if (!u || u.password !== password) {
    log('blocked', `Failed login for "${username}"`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt(idpKeys.privateKey, {
    iss: 'tide-sim', sub: username, name: u.name, roles: u.roles, device: device || 'control-room-console',
    iat: now, exp: now + 8 * 3600
  });
  log('info', `${u.name} signed in${device && device !== 'control-room-console' ? ` from ${device}` : ''}`);
  res.json({ token, user: { id: username, name: u.name, title: u.title, roles: [...u.roles] } });
});

app.get('/policy', async (req, res) => {
  try {
    res.json({ mode: tc.MODE, policy: await directory.policy(), users: await directory.list() });
  } catch (err) {
    res.status(502).json({ error: `Policy unavailable: ${err.message}` });
  }
});

// ---------- Command authorization (the quorum) ----------

function validateRequest(r) {
  if (!r || typeof r !== 'object') return 'Missing request';
  for (const k of ['id', 'plant', 'parameter', 'requestedBy', 'nonce', 'createdAt']) {
    if (!r[k]) return `Request is missing "${k}"`;
  }
  if (r.plant !== PLANT_ID) return 'Unknown plant';
  if (!PARAMETERS[r.parameter]) return 'Unknown parameter';
  return null;
}

async function quorumStatus(entry) {
  const policy = await directory.policy();
  const risk = scoreRequest(entry.request);
  const operatorOk = entry.endorsements.some((e) => e.role === 'operator' && e.sub === entry.request.requestedBy);
  const engineers = new Set(entry.endorsements.filter((e) => e.role === 'engineer').map((e) => e.sub));
  const engineersNeeded = requiresEngineer(risk.level) ? policy.engineerApprovals : 0;
  return {
    risk: risk.level,
    operatorOk,
    engineers: engineers.size,
    engineersNeeded,
    policyVersion: policy.version,
    satisfied: operatorOk && engineers.size >= engineersNeeded
  };
}

// Called by each human from their own browser with their own Tide session.
// The operator calls it to request; an engineer calls it to approve.
app.post('/authorize', async (req, res) => {
  const who = await directory.caller(req);
  if (!who) return res.status(401).json({ error: 'No valid Tide session' });
  const request = req.body && req.body.request;
  const invalid = validateRequest(request);
  if (invalid) return res.status(400).json({ error: invalid });

  const d = digest(request);
  if (!ledger.has(d)) ledger.set(d, { request, endorsements: [], rejectedBy: null, issued: false });
  const entry = ledger.get(d);
  const label = `${PARAMETERS[request.parameter].label} → ${request.value}`;

  if (entry.rejectedBy) {
    log('blocked', `Refused to authorise ${label}: rejected by ${displayName(entry.rejectedBy)}`);
    return res.status(409).json({ error: `Rejected by ${displayName(entry.rejectedBy)}`, status: 'rejected' });
  }
  if (entry.issued) return res.status(409).json({ error: 'Already authorised once; authorizations are single-use' });

  if (who === request.requestedBy) {
    if (!(await hasRole(who, 'operator'))) {
      log('blocked', `${displayName(who)} tried to request ${label} without the Operator role`);
      return res.status(403).json({ error: 'Requester must hold the Operator role' });
    }
    if (!entry.endorsements.some((e) => e.sub === who)) entry.endorsements.push({ sub: who, role: 'operator', at: new Date().toISOString() });
  } else if (await hasRole(who, 'engineer')) {
    if (!entry.endorsements.some((e) => e.role === 'operator')) {
      return res.status(409).json({ error: 'No operator has requested this command' });
    }
    if (!entry.endorsements.some((e) => e.sub === who)) entry.endorsements.push({ sub: who, role: 'engineer', at: new Date().toISOString() });
    log('ok', `${displayName(who)} (Engineer) approved ${label}`);
  } else {
    log('blocked', `${displayName(who)} has no role that can endorse ${label}`);
    return res.status(403).json({ error: 'Only the requesting operator or an independent engineer can endorse' });
  }

  const q = await quorumStatus(entry);
  if (!q.satisfied) {
    log('warn', `${label}: risk ${q.risk.toUpperCase()}, waiting for ${q.engineersNeeded - q.engineers} engineer approval(s)`);
    return res.status(202).json({ status: 'pending', ...q });
  }

  const now = Date.now();
  const payload = {
    type: 'plc-command',
    plant: PLANT_ID,
    requestDigest: d,
    request,
    risk: q.risk,
    approvers: entry.endorsements.map((e) => ({ sub: e.sub, role: e.role })),
    policyVersion: q.policyVersion,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + AUTH_TTL_SECONDS * 1000).toISOString()
  };
  entry.issued = true;
  log('ok', `Quorum met for ${label}: authority signature issued (${payload.approvers.map((a) => displayName(a.sub)).join(' + ')})`);
  res.json({ status: 'authorized', ...q, authorization: { payload, signature: sign(authorityKeys.privateKey, payload) } });
});

app.post('/reject', async (req, res) => {
  const who = await directory.caller(req);
  if (!who) return res.status(401).json({ error: 'No valid Tide session' });
  if (!(await hasRole(who, 'engineer'))) return res.status(403).json({ error: 'Only engineers can reject' });
  const request = req.body && req.body.request;
  const invalid = validateRequest(request);
  if (invalid) return res.status(400).json({ error: invalid });
  const d = digest(request);
  if (!ledger.has(d)) ledger.set(d, { request, endorsements: [], rejectedBy: null, issued: false });
  const entry = ledger.get(d);
  if (entry.issued) return res.status(409).json({ error: 'Already authorised' });
  entry.rejectedBy = who;
  log('blocked', `${displayName(who)} (Engineer) rejected ${PARAMETERS[request.parameter].label} → ${request.value}. It can never be authorised.`);
  res.json({ status: 'rejected' });
});

// Lets the dashboard put TideCloak governance outcomes in the shared audit feed. Display only: the
// caller must be a signed-in admin, and nothing here changes roles or policy.
app.post('/audit', async (req, res) => {
  const who = await directory.caller(req);
  if (!who || !(await hasRole(who, 'admin'))) return res.status(403).json({ error: 'Admin session required' });
  const { kind, message } = req.body || {};
  if (!['ok', 'warn', 'blocked', 'info'].includes(kind) || typeof message !== 'string') return res.status(400).json({ error: 'Bad event' });
  log(kind, `TideCloak: ${message.slice(0, 200)}`, { reportedBy: who });
  res.json({ ok: true });
});

// ---------- Governance: no single admin can change roles or policy ----------
// This gateway never applies a role or policy change on one admin's say-so. With real TideCloak it
// has no write path at all; governance lives in TideCloak's change requests (see app/public/app.js).

function singleAdminBlocked(what) {
  return async (req, res) => {
    const who = await directory.caller(req);
    const name = who ? displayName(who) : 'Unauthenticated caller';
    const quorum = (await directory.policy()).adminQuorum || 'a quorum of';
    log('blocked', `${name} tried to ${what} directly. Single-admin changes are disabled.`);
    res.status(403).json({
      error: `Single-admin changes are disabled. Create a change request; it needs ${quorum} distinct admins.`
    });
  };
}
app.post('/admin/roles', singleAdminBlocked('change a role assignment'));
app.post('/admin/policy', singleAdminBlocked('change the quorum policy'));

if (!tc.enabled) require('./change-requests')(app, { directory, log });
else app.all('/admin/change-requests*', (req, res) => res.status(410).json({ error: 'Change requests live in TideCloak' }));

app.get('/events', (req, res) => res.json(events));

app.listen(PORT, () => {
  log('info', tc.enabled
    ? 'Tide gateway online with TideCloak identity. Authority key published for PLC pinning.'
    : 'Tide network simulator online. Authority key published for PLC pinning.');
  console.log(`[tide] listening on http://localhost:${PORT} (${tc.MODE} mode)`);
});
