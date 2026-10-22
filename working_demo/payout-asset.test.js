const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');

function waitForServer(port, timeoutMs = 15000) {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const req = http.get({ host: '127.0.0.1', port, path: '/api/session' }, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', () => {
        if (Date.now() - startedAt > timeoutMs) {
          reject(new Error('Server did not start in time'));
          return;
        }
        setTimeout(check, 200);
      });
    };
    check();
  });
}

async function apiRequest({ port, method, path, body, cookie }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: text,
          json: text ? JSON.parse(text) : null
        });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function parseSessionCookie(headers) {
  const value = Array.isArray(headers['set-cookie']) ? headers['set-cookie'][0] : headers['set-cookie'];
  if (!value) return '';
  return value.split(';')[0];
}

test('exam vault keeps ciphertext only until 2-of-3 custodians approve the paper', async () => {
  const serverProcess = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: '4021',
      TIDE_AUTH_MODE: 'mock'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await waitForServer(4021);

    const adminLogin = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/login',
      body: { userId: 'exam-admin' }
    });
    const adminCookie = parseSessionCookie(adminLogin.headers);

    const setterLogin = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/login',
      body: { userId: 'paper-setter' }
    });
    const setterCookie = parseSessionCookie(setterLogin.headers);

    const uploadPaper = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/papers',
      body: {
        title: 'Advanced Calculus Final',
        subject: 'Mathematics',
        examDate: '2026-12-12',
        content: 'The final exam contains three extended proof questions.'
      },
      cookie: setterCookie
    });
    assert.equal(uploadPaper.statusCode, 201);
    const paperId = uploadPaper.json.paper.id;

    const databaseView = await apiRequest({
      port: 4021,
      method: 'GET',
      path: '/api/database',
      cookie: adminCookie
    });
    assert.equal(databaseView.statusCode, 200);
    const databasePaper = databaseView.json.papers.find((paper) => paper.id === paperId);
    assert.ok(databasePaper);
    assert.ok(databasePaper.ciphertext);
    assert.equal(databasePaper.plaintext, undefined);

    const adminRequest = await apiRequest({
      port: 4021,
      method: 'POST',
      path: `/api/papers/${paperId}/open-request`,
      body: { requesterId: 'exam-admin' },
      cookie: adminCookie
    });
    assert.equal(adminRequest.statusCode, 201);
    assert.equal(adminRequest.json.request.status, 'Pending');

    const custodianOneLogin = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/login',
      body: { userId: 'custodian-1' }
    });
    const custodianOneCookie = parseSessionCookie(custodianOneLogin.headers);

    const custodianTwoLogin = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/login',
      body: { userId: 'custodian-2' }
    });
    const custodianTwoCookie = parseSessionCookie(custodianTwoLogin.headers);

    const firstApproval = await apiRequest({
      port: 4021,
      method: 'POST',
      path: `/api/papers/${paperId}/approve`,
      body: { userId: 'custodian-1' },
      cookie: custodianOneCookie
    });
    assert.equal(firstApproval.statusCode, 200);

    const secondApproval = await apiRequest({
      port: 4021,
      method: 'POST',
      path: `/api/papers/${paperId}/approve`,
      body: { userId: 'custodian-2' },
      cookie: custodianTwoCookie
    });
    assert.equal(secondApproval.statusCode, 200);

    const openedPaper = await apiRequest({
      port: 4021,
      method: 'GET',
      path: `/api/papers/${paperId}`,
      cookie: adminCookie
    });
    assert.equal(openedPaper.statusCode, 200);
    assert.equal(openedPaper.json.paper.status, 'Opened');
    assert.match(openedPaper.json.paper.content, /three extended proof questions/i);

    const blockedAdminCustodianChange = await apiRequest({
      port: 4021,
      method: 'POST',
      path: '/api/admin/custodians',
      body: {
        initiatorId: 'exam-admin',
        confirmers: ['custodian-1'],
        newCustodians: ['exam-admin', 'custodian-2', 'custodian-3']
      },
      cookie: adminCookie
    });
    assert.equal(blockedAdminCustodianChange.statusCode, 400);
    assert.match(blockedAdminCustodianChange.body, /requires 2 custodians|admin cannot add themselves/i);
  } finally {
    serverProcess.kill('SIGTERM');
  }
});
