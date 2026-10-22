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

      req.on('error', (err) => {
        if (Date.now() - startedAt > timeoutMs) {
          reject(err);
          return;
        }
        setTimeout(check, 200);
      });
    };

    check();
  });
}

function startFakeIssuer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === '/.well-known/openid-configuration') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          issuer: `http://127.0.0.1:${server.address().port}`,
          authorization_endpoint: `http://127.0.0.1:${server.address().port}/authorize`,
          token_endpoint: `http://127.0.0.1:${server.address().port}/token`,
          jwks_uri: `http://127.0.0.1:${server.address().port}/keys`
        }));
        return;
      }

      res.writeHead(404);
      res.end('not found');
    });

    server.listen(0, '127.0.0.1', () => resolve({
      server,
      url: `http://127.0.0.1:${server.address().port}`
    }));
  });
}

test('default auth mode is TideCloak and mock login is rejected', async () => {
  const issuer = await startFakeIssuer();
  const serverProcess = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: '4010',
      TIDE_AUTH_MODE: 'oidc',
      TIDE_ISSUER: issuer.url,
      TIDE_CLIENT_ID: 'demo-client',
      TIDE_CLIENT_SECRET: 'demo-secret',
      TIDE_REDIRECT_URI: 'http://127.0.0.1:4010/auth/callback'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await waitForServer(4010);

    const loginResponse = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: 4010,
        path: '/auth/login',
        method: 'GET'
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ statusCode: res.statusCode, location: res.headers.location, body: Buffer.concat(chunks).toString() }));
      });
      req.on('error', reject);
      req.end();
    });

    assert.equal(loginResponse.statusCode, 302);
    assert.match(loginResponse.location || '', /\/auth\/tide/);

    const tideRedirect = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: 4010,
        path: '/auth/tide',
        method: 'GET'
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ statusCode: res.statusCode, location: res.headers.location, body: Buffer.concat(chunks).toString() }));
      });
      req.on('error', reject);
      req.end();
    });

    assert.equal(tideRedirect.statusCode, 302);
    assert.match(tideRedirect.location || '', /authorize/);

    const mockLoginResponse = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: 4010,
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      req.on('error', reject);
      req.write(JSON.stringify({ userId: 'exam-admin' }));
      req.end();
    });

    assert.equal(mockLoginResponse.statusCode, 400);
    assert.match(mockLoginResponse.body, /OIDC mode uses the provider login flow/i);
  } finally {
    serverProcess.kill('SIGTERM');
    issuer.server.close();
  }
});
