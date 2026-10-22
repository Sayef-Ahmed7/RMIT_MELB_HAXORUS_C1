// Mock PLC (the plant controller). It trusts exactly one thing: the Tide authority public key,
// pinned at commissioning time. It does not trust the app backend, any session, or any admin.
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { digest, verify, cors, loadPinnedPublicKey } = require('../shared/crypto');
const { PLANT_ID, PLANT_NAME, PARAMETERS, scoreRequest, requiresEngineer, initialSetpoints } = require('../shared/plant');

const PORT = Number(process.env.PLC_PORT || 4000);

let authorityKey = loadPinnedPublicKey('tide-authority');
const setpoints = initialSetpoints();
const usedDigests = new Set();
const events = [];

function log(kind, message, details = {}) {
  events.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), source: 'plc', kind, message, details });
  if (events.length > 300) events.pop();
  console.log(`[plc]  ${kind.toUpperCase()} ${message}`);
}

function reject(res, reason, details) {
  log('blocked', `REJECTED: ${reason}`, details);
  return res.status(403).json({ accepted: false, error: `REJECTED: ${reason}` });
}

const app = express();
app.use(cors);
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true, service: 'plc', pinnedAuthority: !!authorityKey }));
app.get('/state', (req, res) => res.json({ plant: PLANT_ID, name: PLANT_NAME, setpoints }));
app.get('/events', (req, res) => res.json(events));

app.post('/command', (req, res) => {
  if (!authorityKey) authorityKey = loadPinnedPublicKey('tide-authority');
  const body = req.body || {};
  const auth = body.authorization;
  const attempted = body.parameter ? `${body.parameter} → ${body.value}` : 'command';

  if (!auth || !auth.payload || !auth.signature) {
    return reject(res, `no valid quorum authorization (${attempted})`, { via: body.via || 'direct' });
  }
  if (!authorityKey) return reject(res, 'no Tide authority key pinned');
  if (!verify(authorityKey, auth.payload, auth.signature)) {
    return reject(res, `signature is not from the Tide authority (${attempted})`, { via: body.via || 'direct' });
  }

  const p = auth.payload;
  const r = p.request || {};
  const label = `${PARAMETERS[r.parameter] ? PARAMETERS[r.parameter].label : r.parameter} → ${r.value}`;

  if (p.type !== 'plc-command' || p.plant !== PLANT_ID) return reject(res, 'authorization is for a different plant or purpose');
  if (Date.parse(p.expiresAt) < Date.now()) return reject(res, `authorization expired (${label})`);
  if (p.requestDigest !== digest(r)) return reject(res, 'authorization does not match the command it carries');
  if (usedDigests.has(p.requestDigest)) return reject(res, `replayed authorization (${label})`);

  // Firmware floor, independent of the Tide policy: dangerous commands always need an engineer
  // who is not the requester.
  const risk = scoreRequest(r);
  if (risk.error) return reject(res, risk.error);
  const independentEngineer = (p.approvers || []).some((a) => a.role === 'engineer' && a.sub !== r.requestedBy);
  if (requiresEngineer(risk.level) && !independentEngineer) {
    return reject(res, `${risk.level}-risk command without an independent engineer (${label})`);
  }

  usedDigests.add(p.requestDigest);
  const def = PARAMETERS[r.parameter];
  const before = setpoints[r.parameter];
  setpoints[r.parameter] = def.kind === 'number' ? Number(r.value) : r.value;
  log('ok', `EXECUTED ${label} (was ${before}). Authorised by ${p.approvers.map((a) => `${a.sub}:${a.role}`).join(' + ')}`);
  res.json({ accepted: true, parameter: r.parameter, before, after: setpoints[r.parameter], setpoints });
});

app.listen(PORT, () => {
  log('info', authorityKey ? 'PLC online. Tide authority key pinned.' : 'PLC online. WARNING: no authority key pinned yet.');
  console.log(`[plc]  listening on http://localhost:${PORT}`);
});
