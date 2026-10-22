// tide-sim: a local stand-in for TideCloak + the Tide network.
//
// It plays the parts the real system gives you:
//   - identity provider: issues signed session tokens (TideCloak login)
//   - policy enforcement: decides whether the approvals on a specific command satisfy the quorum
//   - authority signing: only when the policy is met, signs the exact command with the authority key
//     (in real Tide this key is split across ORK nodes and never exists in one place)
//   - governance: role and policy changes need a quorum of admins (TideCloak change requests)
//
// The app backend never sees the authority private key. The PLC pins the authority *public* key.
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const {
  digest, generateKeyPair, sign, signJwt, verifyJwt, bearer, cors, publishPublicKey
} = require('../shared/crypto');
const { PLANT_ID, PARAMETERS, scoreRequest, requiresEngineer } = require('../shared/plant');

const PORT = Number(process.env.TIDE_PORT || 5000);
const AUTH_TTL_SECONDS = 300;

const idpKeys = generateKeyPair();
const authorityKeys = generateKeyPair();
publishPublicKey('tide-idp', idpKeys.publicKey);
publishPublicKey('tide-authority', authorityKeys.publicKey);

// Synthetic users. Passwords are deliberately weak: the attacker panel "steals" them.
const users = {
  sam: { name: 'Sam', title: 'Operator (on shift)', password: 'demo', roles: ['operator'] },
  priya: { name: 'Priya', title: 'Process engineer', password: 'demo', roles: ['engineer'] },
  alex: { name: 'Alex', title: 'Process engineer', password: 'demo', roles: ['engineer'] },
  morgan: { name: 'Morgan', title: 'IT administrator', password: 'demo', roles: ['admin'] },
  jordan: { name: 'Jordan', title: 'IT administrator', password: 'demo', roles: ['admin'] },
  casey: { name: 'Casey', title: 'IT administrator', password: 'demo', roles: ['admin'] }
};

const policy = { version: 1, engineerApprovals: 1, adminQuorum: 2 };
const ledger = new Map(); // requestDigest -> { request, endorsements, rejectedBy, issued }
const changeRequests = [];
const events = [];

function log(kind, message, details = {}) {
  events.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), source: 'tide', kind, message, details });
  if (events.length > 300) events.pop();
  console.log(`[tide] ${kind.toUpperCase()} ${message}`);
}

function publicUser(id) {
  const u = users[id];
  return { id, name: u.name, title: u.title, roles: [...u.roles] };
}

function hasRole(id, role) {
  return !!users[id] && users[id].roles.includes(role);
}

// Resolve the caller from their Tide session token. Roles are read live, never trusted from the token.
function caller(req) {
  const claims = verifyJwt(idpKeys.publicKey, bearer(req));
  if (!claims || !users[claims.sub]) return null;
  return claims.sub;
}

const app = express();
app.use(cors);
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true, service: 'tide-sim' }));

app.get('/keys', (req, res) => res.json({
  idp: idpKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  authority: authorityKeys.publicKey.export({ type: 'spki', format: 'pem' })
}));

app.post('/login', (req, res) => {
  const { username, password, device } = req.body || {};
  const u = users[username];
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
  res.json({ token, user: publicUser(username) });
});

app.get('/policy', (req, res) => res.json({
  policy,
  users: Object.keys(users).map(publicUser)
}));

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

function quorumStatus(entry) {
  const risk = scoreRequest(entry.request);
  const operatorOk = entry.endorsements.some((e) => e.role === 'operator' && e.sub === entry.request.requestedBy);
  const engineers = new Set(entry.endorsements.filter((e) => e.role === 'engineer').map((e) => e.sub));
  const engineersNeeded = requiresEngineer(risk.level) ? policy.engineerApprovals : 0;
  return {
    risk: risk.level,
    operatorOk,
    engineers: engineers.size,
    engineersNeeded,
    satisfied: operatorOk && engineers.size >= engineersNeeded
  };
}

// Called by each human from their own browser with their own Tide session.
// The operator calls it to request; an engineer calls it to approve.
app.post('/authorize', (req, res) => {
  const who = caller(req);
  if (!who) return res.status(401).json({ error: 'No valid Tide session' });
  const request = req.body && req.body.request;
  const invalid = validateRequest(request);
  if (invalid) return res.status(400).json({ error: invalid });

  const d = digest(request);
  if (!ledger.has(d)) ledger.set(d, { request, endorsements: [], rejectedBy: null, issued: false });
  const entry = ledger.get(d);
  const label = `${PARAMETERS[request.parameter].label} → ${request.value}`;

  if (entry.rejectedBy) {
    log('blocked', `Refused to authorise ${label}: rejected by ${users[entry.rejectedBy].name}`);
    return res.status(409).json({ error: `Rejected by ${users[entry.rejectedBy].name}`, status: 'rejected' });
  }
  if (entry.issued) return res.status(409).json({ error: 'Already authorised once; authorizations are single-use' });

  if (who === request.requestedBy) {
    if (!hasRole(who, 'operator')) {
      log('blocked', `${users[who].name} tried to request ${label} without the Operator role`);
      return res.status(403).json({ error: 'Requester must hold the Operator role' });
    }
    if (!entry.endorsements.some((e) => e.sub === who)) entry.endorsements.push({ sub: who, role: 'operator', at: new Date().toISOString() });
  } else if (hasRole(who, 'engineer')) {
    if (!entry.endorsements.some((e) => e.role === 'operator')) {
      return res.status(409).json({ error: 'No operator has requested this command' });
    }
    if (!entry.endorsements.some((e) => e.sub === who)) entry.endorsements.push({ sub: who, role: 'engineer', at: new Date().toISOString() });
    log('ok', `${users[who].name} (Engineer) approved ${label}`);
  } else {
    log('blocked', `${users[who].name} has no role that can endorse ${label}`);
    return res.status(403).json({ error: 'Only the requesting operator or an independent engineer can endorse' });
  }

  const q = quorumStatus(entry);
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
    policyVersion: policy.version,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + AUTH_TTL_SECONDS * 1000).toISOString()
  };
  entry.issued = true;
  log('ok', `Quorum met for ${label}: authority signature issued (${payload.approvers.map((a) => users[a.sub].name).join(' + ')})`);
  res.json({ status: 'authorized', ...q, authorization: { payload, signature: sign(authorityKeys.privateKey, payload) } });
});

app.post('/reject', (req, res) => {
  const who = caller(req);
  if (!who) return res.status(401).json({ error: 'No valid Tide session' });
  if (!hasRole(who, 'engineer')) return res.status(403).json({ error: 'Only engineers can reject' });
  const request = req.body && req.body.request;
  const invalid = validateRequest(request);
  if (invalid) return res.status(400).json({ error: invalid });
  const d = digest(request);
  if (!ledger.has(d)) ledger.set(d, { request, endorsements: [], rejectedBy: null, issued: false });
  const entry = ledger.get(d);
  if (entry.issued) return res.status(409).json({ error: 'Already authorised' });
  entry.rejectedBy = who;
  log('blocked', `${users[who].name} (Engineer) rejected ${PARAMETERS[request.parameter].label} → ${request.value}. It can never be authorised.`);
  res.json({ status: 'rejected' });
});

// ---------- Governance: no single admin can change roles or policy ----------

function singleAdminBlocked(what) {
  return (req, res) => {
    const who = caller(req);
    const name = who ? users[who].name : 'Unauthenticated caller';
    log('blocked', `${name} tried to ${what} directly. Single-admin changes are disabled.`);
    res.status(403).json({
      error: `Single-admin changes are disabled. Create a change request; it needs ${policy.adminQuorum} distinct admins.`
    });
  };
}
app.post('/admin/roles', singleAdminBlocked('change a role assignment'));
app.post('/admin/policy', singleAdminBlocked('change the quorum policy'));

function describeChange(c) {
  if (c.type === 'grant-role') return `Grant ${c.role} role to ${users[c.target] ? users[c.target].name : c.target}`;
  if (c.type === 'revoke-role') return `Revoke ${c.role} role from ${users[c.target] ? users[c.target].name : c.target}`;
  if (c.type === 'set-policy') {
    const label = { engineerApprovals: 'engineer approvals required', adminQuorum: 'admin quorum' }[c.key] || c.key;
    return `Set ${label} to ${c.value}`;
  }
  return 'Unknown change';
}

function validateChange(c) {
  if (c.type === 'grant-role' || c.type === 'revoke-role') {
    if (!users[c.target]) return 'Unknown user';
    if (!['operator', 'engineer', 'admin'].includes(c.role)) return 'Unknown role';
    return null;
  }
  if (c.type === 'set-policy') {
    if (!['engineerApprovals', 'adminQuorum'].includes(c.key)) return 'Unknown policy key';
    const v = Number(c.value);
    if (!Number.isInteger(v) || v < 0 || v > 3) return 'Policy value must be an integer 0–3';
    return null;
  }
  return 'Unknown change type';
}

function applyChange(c) {
  if (c.type === 'grant-role' && !users[c.target].roles.includes(c.role)) users[c.target].roles.push(c.role);
  if (c.type === 'revoke-role') users[c.target].roles = users[c.target].roles.filter((r) => r !== c.role);
  if (c.type === 'set-policy') {
    policy[c.key] = Number(c.value);
    policy.version += 1;
  }
}

app.get('/admin/change-requests', (req, res) => res.json({ changeRequests, policy }));

app.post('/admin/change-requests', (req, res) => {
  const who = caller(req);
  if (!who || !hasRole(who, 'admin')) return res.status(403).json({ error: 'Admin session required' });
  const { type, target, role, key, value } = req.body || {};
  const change = { type, target, role, key, value };
  const invalid = validateChange(change);
  if (invalid) return res.status(400).json({ error: invalid });
  const cr = {
    id: `cr-${changeRequests.length + 1}`,
    ...change,
    description: describeChange(change),
    createdBy: who,
    createdAt: new Date().toISOString(),
    approvals: [who],
    rejectedBy: null,
    status: 'pending',
    quorum: policy.adminQuorum
  };
  changeRequests.unshift(cr);
  log('warn', `${users[who].name} opened change request "${cr.description}". Needs ${cr.quorum} admins; has 1.`);
  maybeApply(cr);
  res.status(cr.status === 'applied' ? 200 : 202).json(cr);
});

function maybeApply(cr) {
  if (cr.status === 'pending' && cr.approvals.length >= cr.quorum) {
    applyChange(cr);
    cr.status = 'applied';
    log('ok', `Change request "${cr.description}" applied with approvals from ${cr.approvals.map((a) => users[a].name).join(' + ')}`);
  }
}

app.post('/admin/change-requests/:id/approve', (req, res) => {
  const who = caller(req);
  if (!who || !hasRole(who, 'admin')) return res.status(403).json({ error: 'Admin session required' });
  const cr = changeRequests.find((c) => c.id === req.params.id);
  if (!cr) return res.status(404).json({ error: 'Not found' });
  if (cr.status !== 'pending') return res.status(409).json({ error: `Change request is ${cr.status}` });
  if (cr.approvals.includes(who)) {
    log('blocked', `${users[who].name} tried to approve their own change request "${cr.description}" a second time`);
    return res.status(409).json({ error: `${users[who].name} has already approved. A different admin must approve.` });
  }
  cr.approvals.push(who);
  maybeApply(cr);
  res.json(cr);
});

app.post('/admin/change-requests/:id/reject', (req, res) => {
  const who = caller(req);
  if (!who || !hasRole(who, 'admin')) return res.status(403).json({ error: 'Admin session required' });
  const cr = changeRequests.find((c) => c.id === req.params.id);
  if (!cr) return res.status(404).json({ error: 'Not found' });
  if (cr.status !== 'pending') return res.status(409).json({ error: `Change request is ${cr.status}` });
  cr.status = 'rejected';
  cr.rejectedBy = who;
  log('blocked', `${users[who].name} rejected change request "${cr.description}"`);
  res.json(cr);
});

app.get('/events', (req, res) => res.json(events));

app.listen(PORT, () => {
  log('info', 'Tide network simulator online. Authority key published for PLC pinning.');
  console.log(`[tide] listening on http://localhost:${PORT}`);
});
