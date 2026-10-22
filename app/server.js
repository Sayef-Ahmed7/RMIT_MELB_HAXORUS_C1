// App backend: serves the dashboard, stores requests, relays authorizations to the PLC.
// It holds NO key that can authorise a plant command. It can verify who a user is (Tide IdP public
// key), but authority only comes from Tide's quorum signature, which the PLC checks itself.
require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { digest, generateKeyPair, sign, verifyJwt, bearer, loadPinnedPublicKey } = require('../shared/crypto');
const { PLANT_ID, PLANT_NAME, PARAMETERS, scoreRequest, requiresEngineer } = require('../shared/plant');
const { PERSONAS } = require('../shared/personas');
const tc = require('../shared/tidecloak');

const PORT = Number(process.env.APP_PORT || 3000);
const TIDE_URL = process.env.TIDE_PUBLIC_URL || `http://localhost:${process.env.TIDE_PORT || 5000}`;
const PLC_URL = process.env.PLC_PUBLIC_URL || `http://localhost:${process.env.PLC_PORT || 4000}`;
const PLC_INTERNAL_URL = process.env.PLC_INTERNAL_URL || PLC_URL;

const requests = [];
const events = [];

function log(kind, message, details = {}) {
  events.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), source: 'app', kind, message, details });
  if (events.length > 300) events.pop();
  console.log(`[app]  ${kind.toUpperCase()} ${message}`);
}

// Who is calling. Identity only: nothing here grants authority over the plant.
let idpKey = null;
function sessionUser(req) {
  if (tc.enabled) {
    const claims = tc.sessionClaims(req);
    if (!claims) return null;
    const persona = PERSONAS.find((p) => p.username === claims.preferred_username);
    // The device label is self-reported and only shown to reviewers, so it comes from the request.
    const device = String((req.body && req.body.device) || 'control-room-console').slice(0, 60);
    return { sub: claims.preferred_username, name: persona ? persona.name : claims.preferred_username, device };
  }
  if (!idpKey) idpKey = loadPinnedPublicKey('tide-idp');
  return idpKey ? verifyJwt(idpKey, bearer(req)) : null;
}

// ---------- Optional: Claude writes the plain-English risk explanation ----------
// The AI only advises. The risk level comes from the deterministic scorer, and the scorer runs
// again inside the Tide policy and the PLC, so nothing the AI says can lower the bar.
let anthropic = null;
if (process.env.ANTHROPIC_API_KEY) {
  const Anthropic = require('@anthropic-ai/sdk');
  anthropic = new Anthropic();
}

async function aiExplanation(record) {
  if (!anthropic) return;
  const p = PARAMETERS[record.request.parameter];
  try {
    const response = await anthropic.beta.messages.create({
      model: process.env.CLAUDE_MODEL || 'claude-opus-5-5',
      max_tokens: 1024,
      output_config: { effort: 'low' },
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      system: 'You are the anomaly advisor for a drinking-water treatment plant control room. In at most two short sentences, explain to an engineer why a requested setpoint change is or is not dangerous. Plain English, no preamble.',
      messages: [{
        role: 'user',
        content: JSON.stringify({
          parameter: p.label,
          unit: p.unit,
          normalValue: p.normal,
          safeRange: p.safe,
          requestedValue: record.request.value,
          ruleBasedRisk: record.risk.level,
          ruleFindings: record.risk.reasons
        })
      }]
    });
    if (response.stop_reason === 'refusal') return;
    const text = response.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ').trim();
    if (text) {
      record.risk.explanation = text;
      record.risk.explainedBy = 'claude';
    }
  } catch (err) {
    console.warn(`[app]  Claude explanation unavailable, using template: ${err.message}`);
  }
}

const app = express();
app.use(express.json());

// The DPoP relay page the Tide enclave loads during login, served byte-exact by the SDK with the
// CSP it requires. Never serve a hand-edited copy: the enclave integrity-checks it.
if (tc.enabled) {
  const { resolveDpopAuthRequest, expectationsFromConfig } = require('@tidecloak/js/dpop-server');
  const { issuer, client } = expectationsFromConfig(tc.adapterConfig());
  app.use('/tide_dpop', (req, res, next) => {
    const r = resolveDpopAuthRequest({ pathname: req.originalUrl.split('?')[0], expectedIssuer: issuer, expectedClient: client, method: req.method });
    if (!r) return next();
    res.status(r.status).set(r.headers).send(r.body);
  });
}
app.use(express.static(path.join(__dirname, 'public')));

// Public adapter config for the browser SDK: realm URL, client id, the realm's public JWK and
// signed client origins. No secrets.
app.get('/api/tidecloak.json', (req, res) => {
  if (!tc.enabled) return res.status(404).json({ error: 'TIDE_MODE is not tidecloak' });
  res.json(tc.adapterConfig());
});

app.get('/api/config', (req, res) => res.json({
  tideMode: tc.MODE,
  tidecloak: tc.enabled ? { url: tc.baseUrl(), realm: tc.adapterConfig().realm } : null,
  tideUrl: TIDE_URL,
  plcUrl: PLC_URL,
  plant: { id: PLANT_ID, name: PLANT_NAME },
  parameters: PARAMETERS,
  ai: anthropic ? 'claude' : 'rules'
}));

app.get('/api/requests', (req, res) => res.json(requests));
app.get('/api/events', (req, res) => res.json(events));

app.post('/api/requests', (req, res) => {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in first' });
  const { parameter, value, reason } = req.body || {};
  const def = PARAMETERS[parameter];
  if (!def) return res.status(400).json({ error: 'Unknown parameter' });
  const normalisedValue = def.kind === 'number' ? Number(value) : value;

  const request = {
    id: `req-${requests.length + 1}`,
    plant: PLANT_ID,
    parameter,
    value: normalisedValue,
    reason: String(reason || '').slice(0, 200),
    requestedBy: user.sub,
    context: { device: user.device || 'control-room-console' },
    createdAt: new Date().toISOString(),
    nonce: crypto.randomBytes(8).toString('hex')
  };
  const risk = scoreRequest(request);
  if (risk.error) return res.status(400).json({ error: risk.error });

  const record = {
    request,
    requesterName: user.name,
    risk: { ...risk, explainedBy: 'rules' },
    status: requiresEngineer(risk.level) ? 'pending-approval' : 'awaiting-signature',
    history: []
  };
  requests.unshift(record);
  log(risk.level === 'low' ? 'info' : 'warn',
    `${user.name} requested ${def.label} → ${normalisedValue}. AI risk: ${risk.level.toUpperCase()}`);
  aiExplanation(record);
  res.status(201).json(record);
});

// Relay a Tide-signed authorization to the PLC. The backend cannot create one; it can only pass it on.
app.post('/api/requests/:id/execute', async (req, res) => {
  const record = requests.find((r) => r.request.id === req.params.id);
  if (!record) return res.status(404).json({ error: 'Not found' });
  try {
    const plcRes = await fetch(`${PLC_INTERNAL_URL}/command`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authorization: req.body && req.body.authorization, via: 'app-backend' })
    });
    const result = await plcRes.json();
    // A refused relay doesn't change the request: it stays pending for the real approvers.
    if (result.accepted) {
      record.status = 'executed';
      record.plcResult = result;
    } else {
      record.lastPlcRejection = result.error;
    }
    res.status(plcRes.status).json(result);
  } catch (err) {
    res.status(502).json({ error: `PLC unreachable: ${err.message}` });
  }
});

app.post('/api/requests/:id/reject', (req, res) => {
  const user = sessionUser(req);
  const record = requests.find((r) => r.request.id === req.params.id);
  if (!user || !record) return res.status(404).json({ error: 'Not found' });
  record.status = 'rejected';
  record.rejectedBy = user.name;
  res.json(record);
});

app.post('/api/requests/:id/status', (req, res) => {
  const record = requests.find((r) => r.request.id === req.params.id);
  if (!record) return res.status(404).json({ error: 'Not found' });
  const { status, approvals } = req.body || {};
  if (['pending-approval', 'blocked'].includes(status)) record.status = status;
  if (Array.isArray(approvals)) record.approvals = approvals;
  res.json(record);
});

// ---------- Attack: the backend itself is compromised ----------
// A malicious admin with root on this server tries to push a command straight to the PLC.
// The best it can do is sign with a key it controls, or send "approved: true". Both fail.
app.post('/api/demo/compromised-backend', async (req, res) => {
  const { parameter = 'naoh_ppm', value = 11100 } = req.body || {};
  const rogue = generateKeyPair();
  const request = {
    id: 'req-forged', plant: PLANT_ID, parameter, value, reason: 'forged by backend',
    requestedBy: 'sam', context: { device: 'control-room-console' },
    createdAt: new Date().toISOString(), nonce: crypto.randomBytes(8).toString('hex')
  };
  const payload = {
    type: 'plc-command', plant: PLANT_ID, requestDigest: digest(request), request,
    risk: 'low', approvers: [{ sub: 'sam', role: 'operator' }, { sub: 'priya', role: 'engineer' }],
    policyVersion: 1, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString()
  };
  log('warn', `COMPROMISED BACKEND: forging an "approved" ${PARAMETERS[parameter].label} → ${value} command`);
  const attempts = [
    { label: 'Backend says approved = true', body: { parameter, value, approved: true, via: 'compromised-backend' } },
    { label: 'Backend signs with its own key', body: { parameter, value, authorization: { payload, signature: sign(rogue.privateKey, payload) }, via: 'compromised-backend' } }
  ];
  const results = [];
  for (const a of attempts) {
    const r = await fetch(`${PLC_INTERNAL_URL}/command`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(a.body)
    });
    results.push({ attempt: a.label, status: r.status, ...(await r.json()) });
  }
  res.json(results);
});

app.listen(PORT, () => {
  log('info', `Dashboard online. AI explanations: ${anthropic ? 'Claude' : 'rule templates'}.`);
  console.log(`[app]  dashboard on http://localhost:${PORT}`);
});
