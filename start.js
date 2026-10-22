// Starts the three services as separate processes, the way they would be deployed:
// tide-sim first (so the PLC can pin its authority key), then the PLC, then the dashboard.
require('dotenv').config();
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { RUNTIME_DIR } = require('./shared/crypto');

const TIDE_PORT = process.env.TIDE_PORT || 5000;
const children = [];

function run(name, script) {
  const child = spawn(process.execPath, [path.join(__dirname, script)], { stdio: 'inherit', env: process.env });
  child.on('exit', (code) => {
    console.log(`[start] ${name} exited (${code})`);
    shutdown();
  });
  children.push(child);
}

function shutdown() {
  for (const c of children) if (!c.killed) c.kill();
  process.exit();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

async function waitForTide() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://localhost:${TIDE_PORT}/health`);
      if (r.ok && fs.existsSync(path.join(RUNTIME_DIR, 'tide-authority.pub.pem'))) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('tide-sim did not start');
}

// TIDE_MODE=tidecloak needs the realm the bootstrap creates. Say so plainly rather than crash later.
async function checkTidecloak() {
  const tc = require('./shared/tidecloak');
  if (!tc.enabled) return console.log('[start] TIDE_MODE=sim: local TideCloak simulator (set TIDE_MODE=tidecloak for the real thing)');
  try {
    tc.adapterConfig();
    const r = await fetch(`${tc.realmUrl()}/.well-known/openid-configuration`);
    if (!r.ok) throw new Error(`realm answered ${r.status}`);
    console.log(`[start] TIDE_MODE=tidecloak: identity and governance from ${tc.realmUrl()}`);
  } catch (err) {
    console.error(`[start] TideCloak is not ready: ${err.message}\n        Start it with: npm run tidecloak:bootstrap  (or run with TIDE_MODE=sim)`);
    process.exit(1);
  }
}

(async () => {
  await checkTidecloak();
  fs.rmSync(RUNTIME_DIR, { recursive: true, force: true });
  run('tide-sim', 'tide-sim/server.js');
  await waitForTide();
  run('plc', 'plc/server.js');
  run('app', 'app/server.js');
})();
