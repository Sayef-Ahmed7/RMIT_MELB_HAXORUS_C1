// End-to-end: boots all three services and walks the demo script, including every attack.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

const ports = { APP_PORT: '3901', PLC_PORT: '4901', TIDE_PORT: '5901' };
const APP = `http://localhost:${ports.APP_PORT}`;
const PLC = `http://localhost:${ports.PLC_PORT}`;
const TIDE = `http://localhost:${ports.TIDE_PORT}`;
let proc;

async function json(url, { method = 'GET', token, body } = {}) {
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: res.status, body: await res.json() };
}

async function login(username, device) {
  return (await json(`${TIDE}/login`, { method: 'POST', body: { username, password: 'demo', device } })).body.token;
}

// The operator's browser: create the request in the app, then endorse it with Tide.
async function operatorRequest(token, parameter, value) {
  const created = await json(`${APP}/api/requests`, { method: 'POST', token, body: { parameter, value, reason: 'test' } });
  const tide = await json(`${TIDE}/authorize`, { method: 'POST', token, body: { request: created.body.request } });
  return { record: created.body, tide };
}

before(async () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), 'wtd-'));
  proc = spawn(process.execPath, [path.join(__dirname, '..', 'start.js')], {
    env: { ...process.env, ...ports, RUNTIME_DIR: runtime, ANTHROPIC_API_KEY: '', TIDE_MODE: 'sim' },
    stdio: 'ignore'
  });
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${APP}/api/config`)).ok && (await fetch(`${PLC}/health`)).ok) return;
    } catch { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('services did not start');
});

after(() => proc && proc.kill());

test('routine change executes with the operator alone', async () => {
  const sam = await login('sam');
  const { record, tide } = await operatorRequest(sam, 'chlorine_mgL', 1.2);
  assert.equal(record.risk.level, 'low');
  assert.equal(tide.body.status, 'authorized');
  const exec = await json(`${APP}/api/requests/${record.request.id}/execute`, { method: 'POST', body: { authorization: tide.body.authorization } });
  assert.equal(exec.body.accepted, true);
  assert.equal((await json(`${PLC}/state`)).body.setpoints.chlorine_mgL, 1.2);
});

test('stolen operator login cannot push NaOH to 11,100 ppm; engineer rejects', async () => {
  const stolen = await login('sam', 'unknown-laptop (VPN, 03:12)');
  const { record, tide } = await operatorRequest(stolen, 'naoh_ppm', 11100);
  assert.equal(record.risk.level, 'high');
  assert.equal(tide.body.status, 'pending');
  assert.equal(tide.body.authorization, undefined);

  // Attacker relays the pending (unsigned) request anyway
  const exec = await json(`${APP}/api/requests/${record.request.id}/execute`, { method: 'POST', body: {} });
  assert.equal(exec.body.accepted, false);

  const priya = await login('priya');
  assert.equal((await json(`${TIDE}/reject`, { method: 'POST', token: priya, body: { request: record.request } })).body.status, 'rejected');
  const again = await json(`${TIDE}/authorize`, { method: 'POST', token: priya, body: { request: record.request } });
  assert.equal(again.status, 409);
  assert.equal((await json(`${PLC}/state`)).body.setpoints.naoh_ppm, 100);
});

test('operator cannot self-approve; an independent engineer can', async () => {
  const sam = await login('sam');
  const { record, tide } = await operatorRequest(sam, 'naoh_ppm', 150);
  assert.equal(record.risk.level, 'medium');
  assert.equal(tide.body.status, 'pending');
  const alex = await login('alex');
  const approved = await json(`${TIDE}/authorize`, { method: 'POST', token: alex, body: { request: record.request } });
  assert.equal(approved.body.status, 'authorized');
  const exec = await json(`${APP}/api/requests/${record.request.id}/execute`, { method: 'POST', body: { authorization: approved.body.authorization } });
  assert.equal(exec.body.accepted, true);
  // Replay is refused
  const replay = await json(`${PLC}/command`, { method: 'POST', body: { authorization: approved.body.authorization } });
  assert.equal(replay.status, 403);
});

test('direct PLC call and tampered authorization are rejected', async () => {
  assert.equal((await json(`${PLC}/command`, { method: 'POST', body: { parameter: 'naoh_ppm', value: 11100 } })).status, 403);

  const sam = await login('sam');
  const { tide } = await operatorRequest(sam, 'chlorine_mgL', 1.1);
  const tampered = JSON.parse(JSON.stringify(tide.body.authorization));
  tampered.payload.request.value = 40;
  assert.equal((await json(`${PLC}/command`, { method: 'POST', body: { authorization: tampered } })).status, 403);
});

test('compromised backend cannot forge an authorization', async () => {
  const r = await json(`${APP}/api/demo/compromised-backend`, { method: 'POST', body: { parameter: 'naoh_ppm', value: 11100 } });
  assert.ok(r.body.every((a) => a.accepted === false && a.status === 403));
  assert.equal((await json(`${PLC}/state`)).body.setpoints.naoh_ppm, 150);
});

test('stolen admin cannot grant roles or lower the quorum alone', async () => {
  const morgan = await login('morgan');
  assert.equal((await json(`${TIDE}/admin/roles`, { method: 'POST', token: morgan, body: { target: 'sam', role: 'engineer' } })).status, 403);

  const cr = await json(`${TIDE}/admin/change-requests`, { method: 'POST', token: morgan, body: { type: 'set-policy', key: 'engineerApprovals', value: 0 } });
  assert.equal(cr.body.status, 'pending');
  const self = await json(`${TIDE}/admin/change-requests/${cr.body.id}/approve`, { method: 'POST', token: morgan });
  assert.equal(self.status, 409);
  assert.equal((await json(`${TIDE}/policy`)).body.policy.engineerApprovals, 1);

  const jordan = await login('jordan');
  assert.equal((await json(`${TIDE}/admin/change-requests/${cr.body.id}/reject`, { method: 'POST', token: jordan })).body.status, 'rejected');
});

test('two admins together can change roles (governance still works)', async () => {
  const morgan = await login('morgan');
  const jordan = await login('jordan');
  const cr = await json(`${TIDE}/admin/change-requests`, { method: 'POST', token: morgan, body: { type: 'grant-role', target: 'alex', role: 'operator' } });
  const ok = await json(`${TIDE}/admin/change-requests/${cr.body.id}/approve`, { method: 'POST', token: jordan });
  assert.equal(ok.body.status, 'applied');
});
