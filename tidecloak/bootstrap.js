// Bootstraps a local TideCloak (Docker) for the dashboard. A Node port of the Tide pack's
// bootstrap-tidecloak.sh, so it runs on Windows without jq/sudo. Safe to re-run: every phase
// checks what already exists and resumes from there.
//
//   npm run tidecloak:bootstrap
//
// Order matters (Tide pack, canon/iga-change-requests-api.md): every governed write happens while the
// realm is still in FirstAdmin mode, and tide-realm-admin is granted LAST. Committing that grant flips
// the realm to MultiAdmin, after which every role or policy change needs an enclave-signed admin quorum.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { PERSONAS } = require('../shared/personas');

const TC = process.env.TIDECLOAK_URL || 'http://localhost:8080';
const REALM = process.env.TIDECLOAK_REALM || 'water-treatment';
const CLIENT = process.env.TIDECLOAK_CLIENT || 'water-treatment-dashboard';
const READER = 'wtd-policy-reader';
const CONTAINER = process.env.TIDECLOAK_CONTAINER || 'tidecloak-wtd';
const IMAGE = 'tideorg/tidecloak-dev:latest';
const OUT_DIR = path.join(__dirname, 'data');
const SKIP = ['DISABLE_IGA', 'DELETE_REALM', 'OFFBOARD_REALM'];

const ADMIN_USER = process.env.KC_BOOTSTRAP_ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.KC_BOOTSTRAP_ADMIN_PASSWORD;
const EMAIL = process.env.TIDE_LICENSE_EMAIL;

function fail(msg, code = 1) {
  console.error(`\nERROR: ${msg}`);
  process.exit(code);
}

// The master-admin password and the licence answers come from the person who owns the deployment,
// via the gitignored .env. Nothing here has a default (Tide pack AP-41, AP-90).
if (!ADMIN_PASS) fail('KC_BOOTSTRAP_ADMIN_PASSWORD is not set in .env');
if (!EMAIL || !/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(EMAIL) || /@(example|test|localhost)/i.test(EMAIL)
  || process.env.TIDE_TERMS_ACCEPTED !== 'yes') {
  fail('TIDE_LICENSE_EMAIL and TIDE_TERMS_ACCEPTED=yes must be set in .env by the realm owner, who must\n'
    + '       read and accept https://tide.org/legal themselves. Nothing was created.', 2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (msg) => console.log(`==> ${msg}`);

// Master-admin tokens live ~60s, so mint one per call.
async function token() {
  const res = await fetch(`${TC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: ADMIN_USER, password: ADMIN_PASS })
  });
  if (!res.ok) fail(`master admin login failed (${res.status})`);
  return (await res.json()).access_token;
}

async function kc(method, p, { json, form } = {}) {
  const headers = { Authorization: `Bearer ${await token()}` };
  let body;
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  if (form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form); }
  const res = await fetch(`${TC}${p}`, { method, headers, body });
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch { /* plain text */ }
  return { status: res.status, ok: res.ok, data };
}
const admin = (p) => `/admin/realms/${REALM}${p}`;

// FirstAdmin mode: authorize every pending change request, then commit the ready ones, in passes
// so dependent requests (a user before its role grant) become ready.
async function drain(label) {
  for (let pass = 0; pass < 6; pass++) {
    const pending = (await kc('GET', admin('/iga/change-requests?status=PENDING'))).data;
    const list = Array.isArray(pending) ? pending.filter((c) => !SKIP.includes(c.actionType)) : [];
    if (!list.length) break;
    for (const c of list) await kc('POST', admin(`/iga/change-requests/${c.id}/authorize`), { json: {} });
    const ready = (await kc('GET', admin('/iga/change-requests?status=PENDING'))).data
      .filter((c) => !SKIP.includes(c.actionType) && c.readyToCommit);
    if (!ready.length) break;
    for (const c of ready) await kc('POST', admin(`/iga/change-requests/${c.id}/commit`));
  }
  const left = (await kc('GET', admin('/iga/change-requests?status=PENDING'))).data;
  const n = Array.isArray(left) ? left.filter((c) => !SKIP.includes(c.actionType)).length : 0;
  console.log(`    drained (${label}); ${n} still pending`);
  return n;
}

async function findUser(username) {
  const r = await kc('GET', admin(`/users?username=${encodeURIComponent(username)}&exact=true&briefRepresentation=false`));
  return Array.isArray(r.data) ? r.data[0] : null;
}

async function clientUuid(clientId) {
  const r = await kc('GET', admin(`/clients?clientId=${encodeURIComponent(clientId)}`));
  return r.data[0] && r.data[0].id;
}

// ---------- Phases ----------

async function startContainer() {
  try {
    const up = await fetch(`${TC}/realms/master`);
    if (up.ok) return step(`TideCloak already answering on ${TC}`);
  } catch { /* not running */ }
  // The realm lives inside the container (dev image, H2). Restart an existing one rather than
  // recreating it: a realm cannot be rebuilt without re-linking every Tide account.
  let exists = false;
  try { exists = execSync(`docker ps -a --filter name=^${CONTAINER}$ --format {{.Names}}`).toString().trim() === CONTAINER; } catch { /* no docker */ }
  if (exists) {
    step(`Starting existing container ${CONTAINER}`);
    execSync(`docker start ${CONTAINER}`, { stdio: 'inherit' });
  } else {
    step(`Creating TideCloak container ${CONTAINER} (${IMAGE})`);
    // The password reaches docker through the environment, never on the command line.
    execSync(`docker run -d --name ${CONTAINER} -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD ${IMAGE}`,
      { stdio: 'inherit', env: { ...process.env, KC_BOOTSTRAP_ADMIN_USERNAME: ADMIN_USER, KC_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASS } });
  }
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${TC}/realms/master`)).ok) return step('TideCloak is ready'); } catch { /* booting */ }
    await sleep(3000);
  }
  fail(`TideCloak did not start. Check: docker logs ${CONTAINER}`);
}

async function createRealm() {
  if ((await kc('GET', admin(''))).ok) return step(`Realm ${REALM} exists`);
  step(`Creating realm ${REALM}`);
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'realm.json'), 'utf8'));
  const r = await kc('POST', '/admin/realms', { json: realm });
  if (!r.ok) fail(`realm import failed (${r.status}): ${JSON.stringify(r.data).slice(0, 400)}`);

  // Tide asserts only a vuid, so never show Keycloak's "Update Account Information" page. Must run
  // before IGA is on, after which a realm-config write becomes a change request.
  const ex = (await kc('GET', admin('/authentication/flows/first%20broker%20login/executions'))).data;
  const review = ex.find((e) => e.providerId === 'idp-review-profile');
  const cfg = { alias: 'review profile config', config: { 'update.profile.on.first.login': 'off' } };
  if (review && review.authenticationConfig) await kc('PUT', admin(`/authentication/config/${review.authenticationConfig}`), { json: cfg });
  else if (review) await kc('POST', admin(`/authentication/executions/${review.id}/config`), { json: cfg });
}

async function setUpTide() {
  const realm = (await kc('GET', admin(''))).data;
  if (realm.attributes && String(realm.attributes.isIGAEnabled).toLowerCase() === 'true') return step('Tide licence + IGA already enabled');
  step(`Licensing the realm to ${EMAIL} (Tide T&Cs accepted by the realm owner)`);
  const setup = await kc('POST', admin('/vendorResources/setUpTideRealm'), { form: { email: EMAIL, isRagnarokEnabled: 'true' } });
  const body = typeof setup.data === 'string' ? setup.data : JSON.stringify(setup.data);
  if (!setup.ok || /NEED_PAYMENT/.test(body)) {
    // A failed setup leaves a half-made vendor key behind, so retrying in place fails differently.
    // The realm has no IGA yet, so deleting it is a plain delete; the next run starts fresh.
    await kc('DELETE', admin(''));
    fail(`setUpTideRealm failed (${setup.status}): ${body.slice(0, 300)}\n`
      + `       The realm was removed so a re-run starts clean. Cause is in: docker logs ${CONTAINER} (look for [Midgard])`);
  }

  step('Stamping iga.attestor=tide (cryptographic governance, not Tideless)');
  const rep = (await kc('GET', admin(''))).data;
  rep.attributes = { ...(rep.attributes || {}), 'iga.attestor': 'tide' };
  await kc('PUT', admin(''), { json: rep });

  step('Enabling IGA (toggle-iga is a flip: called exactly once)');
  const iga = await kc('POST', admin('/tide-admin/toggle-iga'), { form: { isIGAEnabled: 'true' } });
  const out = JSON.stringify(iga.data);
  if (!/"enabled":true/.test(out)) fail(`toggle-iga did not report enabled=true: ${out.slice(0, 400)}`);
  if (/warning/i.test(out)) console.log(`    toggle-iga warning: ${String(iga.data.warning || '').slice(0, 300)}`);
  await sleep(2000);
  await drain('clients, roles, adopt');
}

async function createUsers() {
  for (const p of PERSONAS) {
    if (await findUser(p.username)) continue;
    step(`Creating user ${p.username} (${p.title})`);
    await kc('POST', admin('/users'), {
      json: { username: p.username, firstName: p.name, lastName: p.title, enabled: true, attributes: { tideInvitable: ['true'] } }
    });
  }
  await sleep(1500);
  await drain('users');

  for (const p of PERSONAS) {
    const u = await findUser(p.username);
    if (!u) fail(`user ${p.username} not queryable after drain`);
    const have = (await kc('GET', admin(`/users/${u.id}/role-mappings/realm`))).data.map((r) => r.name);
    const missing = p.roles.filter((r) => !have.includes(r));
    if (!missing.length) continue;
    const reps = [];
    for (const name of missing) reps.push((await kc('GET', admin(`/roles/${name}`))).data);
    step(`Granting ${missing.join(', ')} to ${p.username}`);
    await kc('POST', admin(`/users/${u.id}/role-mappings/realm`), { json: reps });
  }
  await sleep(1500);
  await drain('app roles');
}

async function linkAccounts() {
  const links = [];
  for (const p of PERSONAS) {
    const u = await findUser(p.username);
    if (u.attributes && u.attributes.tideUserKey && u.attributes.tideUserKey[0]) continue;
    const r = await kc('POST', admin(`/tideAdminResources/get-required-action-link?userId=${u.id}&lifespan=43200`), { json: ['link-tide-account-action'] });
    links.push({ p, link: typeof r.data === 'string' ? r.data : JSON.stringify(r.data) });
  }
  if (!links.length) return step('All personas have linked Tide accounts');

  const file = path.join(OUT_DIR, 'invite-links.txt');
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(file, links.map(({ p, link }) => `${p.username}\t${link}`).join('\n') + '\n');
  console.log('\n============================================================');
  console.log('Create one Tide account per persona. Open each link (a private window per link is');
  console.log('easiest) and sign up. Use a memorable username like wtd-sam. Valid for 12 hours.');
  console.log(`(Also saved to ${file})\n`);
  for (const { p, link } of links) console.log(`  ${p.username.padEnd(7)} ${link}`);
  console.log('============================================================\n');

  const waiting = new Set(links.map(({ p }) => p.username));
  while (waiting.size) {
    for (const name of [...waiting]) {
      const u = await findUser(name);
      if (u.attributes && u.attributes.tideUserKey && u.attributes.tideUserKey[0]) {
        waiting.delete(name);
        console.log(`    linked: ${name} (${waiting.size} to go)`);
      }
    }
    if (waiting.size) await sleep(5000);
  }
  await sleep(2000);
  await drain('account links');
}

async function signIdpSettings() {
  step('Pointing CustomAdminUIDomain at the realm console and signing IdP settings');
  const inst = (await kc('GET', admin('/identity-provider/instances/tide'))).data;
  inst.config = { ...inst.config, CustomAdminUIDomain: `${TC}/realms/${REALM}/tide-console/` };
  await kc('PUT', admin('/identity-provider/instances/tide'), { json: inst });
  const s = await kc('POST', admin('/vendorResources/sign-idp-settings'));
  if (!s.ok) fail(`sign-idp-settings failed (${s.status}): ${JSON.stringify(s.data).slice(0, 300)}`);
}

async function grantRealmAdmins() {
  const rm = await clientUuid('realm-management');
  const role = (await kc('GET', admin(`/clients/${rm}/roles/tide-realm-admin`))).data;
  if (!role || role.error) fail(`tide-realm-admin not found: ${JSON.stringify(role)}`);
  const admins = PERSONAS.filter((p) => p.roles.includes('admin'));
  const todo = [];
  for (const p of admins) {
    const u = await findUser(p.username);
    const have = (await kc('GET', admin(`/users/${u.id}/role-mappings/clients/${rm}`))).data;
    if (!have.some((r) => r.name === 'tide-realm-admin')) todo.push({ p, u });
  }
  if (!todo.length) return step('tide-realm-admin already held by all admins');
  step(`Granting tide-realm-admin to ${todo.map(({ p }) => p.username).join(', ')} (flips the realm to MultiAdmin)`);
  for (const { u } of todo) await kc('POST', admin(`/users/${u.id}/role-mappings/clients/${rm}`), { json: [role] });
  await sleep(2000);
  const left = await drain('admin grants');
  if (left) {
    console.log('\n    Some admin grants need an enclave approval now that the realm is MultiAdmin.');
    console.log(`    Approve them as an existing admin in the dashboard (?as=morgan) or ${TC}/admin/${REALM}/console/`);
  }
}

async function exportConfig() {
  step('Exporting adapter config and the policy reader secret');
  const uuid = await clientUuid(CLIENT);
  const adapter = (await kc('GET', admin(`/vendorResources/get-installations-provider?clientId=${uuid}&providerId=keycloak-oidc-keycloak-json`))).data;
  if (!adapter || !adapter.jwk) fail(`adapter JSON has no jwk (is IGA enabled?): ${JSON.stringify(adapter).slice(0, 300)}`);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, 'tidecloak.json'), JSON.stringify(adapter, null, 2));
  const reader = await clientUuid(READER);
  const secret = (await kc('GET', admin(`/clients/${reader}/client-secret`))).data.value;
  fs.writeFileSync(path.join(OUT_DIR, 'policy-reader.json'), JSON.stringify({ clientId: READER, secret }, null, 2));
}

// One bootstrap at a time: two runs creating and deleting the same realm would trip over each other.
function takeLock() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const lock = path.join(OUT_DIR, 'bootstrap.lock');
  try {
    fs.writeFileSync(lock, String(process.pid), { flag: 'wx' });
  } catch {
    const pid = Number(fs.readFileSync(lock, 'utf8'));
    let alive = false;
    try { process.kill(pid, 0); alive = true; } catch { /* stale lock */ }
    if (alive) fail(`another bootstrap is already running (pid ${pid})`);
    fs.writeFileSync(lock, String(process.pid));
  }
  process.on('exit', () => { try { fs.unlinkSync(lock); } catch { /* gone */ } });
}

(async () => {
  takeLock();
  console.log(`Licence email: ${EMAIL} · Terms (https://tide.org/legal): accepted by the realm owner`);
  await startContainer();
  await createRealm();
  await setUpTide();
  await createUsers();
  await linkAccounts();
  await signIdpSettings();
  await grantRealmAdmins();
  await exportConfig();
  console.log(`\nDone. Realm ${REALM} on ${TC}. Adapter config in tidecloak/data/. Run: npm start`);
})().catch((err) => fail(err.stack || err.message));
