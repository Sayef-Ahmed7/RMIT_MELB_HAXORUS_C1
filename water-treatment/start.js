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

(async () => {
  fs.rmSync(RUNTIME_DIR, { recursive: true, force: true });
  run('tide-sim', 'tide-sim/server.js');
  await waitForTide();
  run('plc', 'plc/server.js');
  run('app', 'app/server.js');
})();
