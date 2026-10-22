// Dashboard client. Each persona talks to the Tide simulator with their *own* session, straight from
// the browser. The app backend only stores requests and relays the Tide-signed result to the PLC.

const PERSONAS = [
  { key: 'sam', user: 'sam', label: 'Sam', sub: 'Operator', view: 'operator' },
  { key: 'priya', user: 'priya', label: 'Priya', sub: 'Engineer', view: 'engineer' },
  { key: 'alex', user: 'alex', label: 'Alex', sub: 'Engineer', view: 'engineer' },
  { key: 'morgan', user: 'morgan', label: 'Morgan', sub: 'Admin', view: 'admin' },
  { key: 'jordan', user: 'jordan', label: 'Jordan', sub: 'Admin', view: 'admin' },
  { key: 'attacker', user: null, label: 'Attacker', sub: 'Stolen creds', view: 'attacker' }
];
const ATTACKER_DEVICE = 'unknown-laptop (VPN exit, 03:12)';

const state = {
  config: null,
  persona: null,
  tokens: {},
  requests: [],
  setpoints: {},
  events: [],
  policy: null,
  users: [],
  changeRequests: [],
  seenEvents: new Set(),
  firstLoad: true,
  previewing: false
};

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (v) => (typeof v === 'number' ? v.toLocaleString('en-AU') : v);

// ---------- TideCloak session (TIDE_MODE=tidecloak) ----------
// One browser profile holds one person's TideCloak session, as on a real control-room console.
// Calls go out through secureFetch, which attaches that session's DPoP-bound token and a fresh proof.
// Nothing in this page ever holds a password.
const SESSION = 'tidecloak-session';
const tideSession = { iam: null, user: null };
const isTidecloak = () => state.config && state.config.tideMode === 'tidecloak';

async function initTideSession() {
  const { IAMService } = await import('/vendor/tidecloak.js');
  const adapter = (await api('/api/tidecloak.json')).data;
  // Return to this exact view (?as=...) after the Tide enclave login.
  await IAMService.initIAM({ ...adapter, useDPoP: { mode: 'strict', alg: 'ES256' }, redirectUri: location.href.split('#')[0] });
  tideSession.iam = IAMService;
  tideSession.user = IAMService.isLoggedIn() ? IAMService.getValueFromToken('preferred_username') : null;
  IAMService.on('authRefreshError', () => { tideSession.user = null; renderSession(); });
}

async function http(url, { method = 'GET', token, body } = {}) {
  const init = {
    method,
    headers: { 'Content-Type': 'application/json', ...(token && token !== SESSION ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  };
  const res = token === SESSION ? await tideSession.iam.secureFetch(url, init) : await fetch(url, init);
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  return { status: res.status, ok: res.ok, data, headers: res.headers };
}

const tide = (path, opts) => http(`${state.config.tideUrl}${path}`, opts);
const plc = (path, opts) => http(`${state.config.plcUrl}${path}`, opts);
const api = (path, opts) => http(path, opts);
const realmAdmin = (path, opts) => http(`${state.config.tidecloak.url}/admin/realms/${state.config.tidecloak.realm}${path}`, { token: SESSION, ...opts });

// Sim mode: log in with the synthetic password ("demo"; the attacker simply has it).
// TideCloak mode: use this window's own Tide session, which must belong to that person.
async function tokenFor(user, device) {
  if (isTidecloak()) {
    if (!tideSession.user) throw new Error('Sign in with Tide first (top right).');
    if (tideSession.user !== user) {
      throw new Error(`This window is signed in as ${nameOf(tideSession.user)}. Open ?as=${user} in ${nameOf(user)}'s own browser profile.`);
    }
    return SESSION;
  }
  const key = `${user}|${device || ''}`;
  if (!state.tokens[key]) {
    const r = await tide('/login', { method: 'POST', body: { username: user, password: 'demo', device } });
    if (!r.ok) throw new Error(r.data.error || 'Login failed');
    state.tokens[key] = r.data.token;
  }
  return state.tokens[key];
}

// ---------- Core flows ----------

async function submitRequest(token, parameter, value, reason, device) {
  const created = await api('/api/requests', { method: 'POST', token, body: { parameter, value, reason, device } });
  if (!created.ok) throw new Error(created.data.error);
  const record = created.data;
  const t = await tide('/authorize', { method: 'POST', token, body: { request: record.request } });
  if (t.data.status === 'authorized') {
    const exec = await api(`/api/requests/${record.request.id}/execute`, { method: 'POST', body: { authorization: t.data.authorization } });
    return { record, tide: t, exec };
  }
  await api(`/api/requests/${record.request.id}/status`, { method: 'POST', body: { status: t.ok ? 'pending-approval' : 'blocked' } });
  return { record, tide: t };
}

async function approve(record) {
  let token;
  try { token = await tokenFor(state.persona.user); } catch (err) { flash('blocked', err.message); return refresh(); }
  const t = await tide('/authorize', { method: 'POST', token, body: { request: record.request } });
  if (t.data.status === 'authorized') {
    await api(`/api/requests/${record.request.id}/execute`, { method: 'POST', body: { authorization: t.data.authorization } });
  } else if (!t.ok) {
    flash('blocked', t.data.error);
  }
  refresh();
}

async function reject(record) {
  let token;
  try { token = await tokenFor(state.persona.user); } catch (err) { flash('blocked', err.message); return refresh(); }
  const t = await tide('/reject', { method: 'POST', token, body: { request: record.request } });
  if (t.ok) await api(`/api/requests/${record.request.id}/reject`, { method: 'POST', token });
  refresh();
}

// ---------- Governance through TideCloak change requests (TIDE_MODE=tidecloak) ----------
// The browser files and approves change requests directly against TideCloak with the admin's own
// DPoP-bound session, never through a server: TideCloak credits an approval to whoever makes the
// call, and each admin counts once. In MultiAdmin mode every approval is signed in that admin's
// Tide enclave, so a stolen session without the admin's Tide key cannot approve at all.

const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const bytesToB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));

async function tcUserId(username) {
  const r = await realmAdmin(`/users?username=${encodeURIComponent(username)}&exact=true`);
  if (!r.ok || !r.data[0]) throw new Error(`TideCloak user lookup failed for ${username} (${r.status})`);
  return r.data[0].id;
}

// A governed admin write. With IGA on, TideCloak does not apply it: it answers 202 and holds it
// as a change request until enough admins sign.
async function tcPropose({ type, role, target, key, value }) {
  if (type === 'set-policy') {
    if (key !== 'engineerApprovals') throw new Error('TideCloak sets the admin quorum itself: 70% of realm admins.');
    const realm = await realmAdmin('');
    if (!realm.ok) throw new Error(`TideCloak realm read failed (${realm.status})`);
    const attributes = { ...(realm.data.attributes || {}), 'wtd.engineerApprovals': String(value) };
    return realmAdmin('', { method: 'PUT', body: { ...realm.data, attributes } });
  }
  const id = await tcUserId(target);
  const rep = await realmAdmin(`/roles/${encodeURIComponent(role)}`);
  if (!rep.ok) throw new Error(`TideCloak role lookup failed (${rep.status})`);
  return realmAdmin(`/users/${id}/role-mappings/realm`, { method: type === 'grant-role' ? 'POST' : 'DELETE', body: [rep.data] });
}

// Approve = sign. First call returns what to sign; the admin signs it in their Tide enclave; the
// second call submits the signature. TideCloak commits once its threshold of admins have signed.
async function tcApprove(id) {
  const first = await realmAdmin(`/iga/change-requests/${id}/approve`, { method: 'POST', body: {} });
  if (!first.ok || first.data.mode !== 'needs-approval') return first;
  const [signed] = await tideSession.iam.getTideCloakClient()
    .requestTideOperatorApproval([{ id, request: b64ToBytes(first.data.requestModel) }]);
  if (!signed || signed.status !== 'approved') {
    return { ok: false, status: 0, data: { error: `Not signed in the Tide enclave (${signed ? signed.status : 'closed'})` } };
  }
  return realmAdmin(`/iga/change-requests/${id}/approve`, { method: 'POST', body: { requestModel: bytesToB64(signed.request) } });
}

const tcDeny = (id) => realmAdmin(`/iga/change-requests/${id}/deny`, { method: 'POST', body: { reason: `Rejected by ${nameOf(tideSession.user)}` } });

// Put a governance outcome in the shared audit feed (display only).
const audit = (kind, message) => tide('/audit', { method: 'POST', token: SESSION, body: { kind, message } }).catch(() => {});

function describeCr(c) {
  const rows = JSON.stringify(c.rows || '');
  const role = ['operator', 'engineer', 'admin', 'tide-realm-admin'].find((r) => rows.includes(`"${r}"`));
  const user = PERSONAS.find((p) => p.user && (rows.includes(`"${p.user}"`) || String(c.entityId || '').includes(p.user)));
  if (c.actionType === 'GRANT_ROLES') return `Grant ${role || 'role'} to ${user ? user.label : 'user'}`;
  if (c.actionType === 'REVOKE_ROLES') return `Revoke ${role || 'role'} from ${user ? user.label : 'user'}`;
  if (/REALM/.test(c.actionType) && rows.includes('wtd.engineerApprovals')) {
    const m = /wtd\.engineerApprovals\\?"\s*[:,]\s*\\?"?(\d)/.exec(rows);
    return `Set engineer approvals required${m ? ` to ${m[1]}` : ''}`;
  }
  return `${c.actionType} ${c.entityType || ''}`.trim();
}

// TideCloak change request → the shape the admin panel renders.
function normalizeCr(c) {
  const approvals = (c.authorizers || []).map((a) => a.username);
  return {
    id: c.id,
    description: describeCr(c),
    createdBy: c.requestedBy,
    status: { PENDING: 'pending', APPROVED: 'applied', DENIED: 'rejected', CANCELLED: 'rejected' }[c.status] || c.status,
    approvals,
    // Count from authorizationCount; if absent fall back to readyToCommit, never to zero.
    count: c.authorizationCount ?? (c.readyToCommit ? c.threshold : approvals.length),
    quorum: c.threshold,
    rejectedBy: c.status === 'DENIED' ? c.resolvedBy : null
  };
}

const GOVERNED = ['GRANT_ROLES', 'REVOKE_ROLES', 'SET_REALM_ATTRIBUTE', 'SET_REALM_CONFIG'];
let lastCrFetch = 0;
async function fetchTidecloakCrs() {
  if (!tideSession.user || Date.now() - lastCrFetch < 3000) return state.changeRequests;
  lastCrFetch = Date.now();
  const r = await realmAdmin('/iga/change-requests');
  if (!r.ok || !Array.isArray(r.data)) return state.changeRequests;
  return r.data.filter((c) => GOVERNED.includes(c.actionType))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 12).map(normalizeCr);
}

// ---------- Rendering: header, plant, gauges ----------

function nameOf(id) {
  const p = PERSONAS.find((x) => x.user === id);
  if (p) return p.label;
  const u = state.users.find((x) => x.id === id);
  return u ? u.name : id;
}

function renderSession() {
  const el = $('#session');
  if (!isTidecloak()) { el.innerHTML = ''; return; }
  el.innerHTML = tideSession.user
    ? `<span class="pill ok" title="TideCloak session in this browser profile">Tide: ${esc(nameOf(tideSession.user))}</span> <button class="btn ghost small" id="btn-logout">Sign out</button>`
    : '<button class="btn primary small" id="btn-login">Sign in with Tide</button>';
  if ($('#btn-login')) $('#btn-login').onclick = () => tideSession.iam.doLogin();
  if ($('#btn-logout')) $('#btn-logout').onclick = () => tideSession.iam.doLogout();
}

function renderPersonas() {
  $('#personas').innerHTML = PERSONAS.map((p) => `
    <button class="persona ${p.key === 'attacker' ? 'attacker' : ''} ${state.persona && state.persona.key === p.key ? 'active' : ''}" data-key="${p.key}">
      <span>${p.label}</span><small>${p.sub}</small>
    </button>`).join('');
  document.querySelectorAll('.persona').forEach((b) => b.addEventListener('click', () => selectPersona(b.dataset.key)));
}

function selectPersona(key) {
  state.persona = PERSONAS.find((p) => p.key === key) || PERSONAS[0];
  try { localStorage.setItem('persona', state.persona.key); } catch { /* ignore */ }
  renderPersonas();
  renderPanel();
  refreshLists();
}

function isUnsafe(sp) {
  const P = state.config.parameters;
  return Object.entries(P).some(([k, p]) => {
    const v = sp[k];
    if (p.kind === 'number') return v < p.safe[0] || v > p.safe[1];
    return v === p.danger;
  });
}

function renderPlant() {
  const sp = state.previewing ? { ...state.setpoints, ...state.previewing } : state.setpoints;
  const unsafe = isUnsafe(sp);
  const svg = $('#schematic');
  svg.classList.toggle('unsafe', unsafe);
  svg.classList.toggle('bypass-on', sp.bypass_valve === 'open');
  $('#filter-unit').classList.toggle('filter-off', sp.filter === 'offline');
  $('#flow-filter-out').style.opacity = sp.filter === 'offline' ? 0.15 : 1;
  $('#dose-label').textContent = `NaOH ${fmt(sp.naoh_ppm)} ppm`;
  $('#filter-label').textContent = sp.filter;
  $('#clear-label').textContent = `pH ${sp.ph} · Cl ${sp.chlorine_mgL}`;

  const status = $('#water-status');
  if (state.previewing) {
    status.className = 'pill bad';
    status.textContent = 'PREVIEW: what would reach town (not applied)';
  } else {
    status.className = `pill ${unsafe ? 'bad' : 'ok'}`;
    status.textContent = unsafe ? 'UNSAFE water to town' : 'Water safe';
  }

  const P = state.config.parameters;
  $('#gauges').innerHTML = Object.entries(P).map(([k, p]) => {
    const v = sp[k];
    let bad; let pct;
    if (p.kind === 'number') {
      bad = v < p.safe[0] || v > p.safe[1];
      pct = Math.min(100, (v / (p.safe[1] * 1.25)) * 100);
    } else {
      bad = v === p.danger;
      pct = 100;
    }
    return `<div class="gauge ${bad ? 'bad' : ''}">
      <div class="label">${esc(p.label)}</div>
      <div class="value">${esc(fmt(v))}<small>${esc(p.unit)}</small></div>
      <div class="range">${p.kind === 'number' ? `normal ${p.normal} · safe ${p.safe[0]}–${p.safe[1]}` : `normal: ${p.normal}`}</div>
      <div class="bar"><span style="width:${pct}%"></span></div>
    </div>`;
  }).join('');

  const pending = state.requests.find((r) => r.status === 'pending-approval' && r.risk.level === 'high');
  const preview = $('#preview');
  if (pending) {
    const p = P[pending.request.parameter];
    preview.classList.remove('hidden');
    preview.innerHTML = `<strong>Held by quorum:</strong> ${esc(pending.requesterName)} requested ${esc(p.label)} → <strong>${esc(fmt(pending.request.value))} ${esc(p.unit)}</strong>.
      It has <strong>not</strong> been executed. ${esc(pending.risk.explanation)}
      <div class="row" style="margin-top:8px"><button class="btn bad" id="btn-preview">Show what would have reached town</button></div>`;
    $('#btn-preview').onclick = () => {
      state.previewing = { [pending.request.parameter]: pending.request.value };
      renderPlant();
      setTimeout(() => { state.previewing = false; renderPlant(); }, 4000);
    };
  } else {
    preview.classList.add('hidden');
  }
}

// ---------- Request cards ----------

const STATUS = {
  'awaiting-signature': ['muted', 'Signing…'],
  'pending-approval': ['warn', 'Awaiting independent engineer'],
  executed: ['ok', 'Executed on PLC'],
  rejected: ['bad', 'Rejected'],
  'plc-rejected': ['bad', 'PLC refused'],
  blocked: ['bad', 'Blocked by Tide policy']
};

function requestCard(r, { actions = false } = {}) {
  const p = state.config.parameters[r.request.parameter];
  const before = r.plcResult && r.plcResult.before !== undefined ? r.plcResult.before : state.setpoints[r.request.parameter];
  const [cls, text] = STATUS[r.status] || ['muted', r.status];
  const device = r.request.context && r.request.context.device;
  return `<div class="req">
    <div class="top">
      <span class="meta">${esc(r.request.id)} · ${esc(r.requesterName)} · ${new Date(r.request.createdAt).toLocaleTimeString()}${device && device !== 'control-room-console' ? ` · <span style="color:var(--warn)">${esc(device)}</span>` : ''}</span>
      <span class="pill ${cls}">${text}${r.rejectedBy ? ` by ${esc(r.rejectedBy)}` : ''}</span>
    </div>
    <div class="change">${esc(p.label)}: ${esc(fmt(before))}<span class="arrow">→</span>${esc(fmt(r.request.value))} ${esc(p.unit)}</div>
    ${r.request.reason ? `<div class="meta">Reason: “${esc(r.request.reason)}”</div>` : ''}
    <div class="ai ${r.risk.level}">
      <strong>AI risk: ${r.risk.level.toUpperCase()}</strong>: ${esc(r.risk.explanation)}
      <small>${r.risk.reasons.map(esc).join(' · ')} · ${r.risk.explainedBy === 'claude' ? 'explained by Claude' : 'rule-based check'} · advisory only</small>
    </div>
    ${actions && r.status === 'pending-approval' ? `<div class="row">
      <button class="btn ok" data-approve="${esc(r.request.id)}">Approve as me</button>
      <button class="btn bad" data-reject="${esc(r.request.id)}">Reject</button>
    </div>` : ''}
  </div>`;
}

function bindCardActions(root) {
  root.querySelectorAll('[data-approve]').forEach((b) => b.addEventListener('click', () => {
    b.disabled = true;
    approve(state.requests.find((r) => r.request.id === b.dataset.approve));
  }));
  root.querySelectorAll('[data-reject]').forEach((b) => b.addEventListener('click', () => {
    b.disabled = true;
    reject(state.requests.find((r) => r.request.id === b.dataset.reject));
  }));
}

// ---------- Persona panels ----------

function renderPanel() {
  const v = state.persona.view;
  const panel = $('#panel');
  if (v === 'operator') panel.innerHTML = operatorPanel();
  if (v === 'engineer') panel.innerHTML = engineerPanel();
  if (v === 'admin') panel.innerHTML = adminPanel();
  if (v === 'attacker') panel.innerHTML = attackerPanel();
  if (v === 'operator') bindOperator();
  if (v === 'admin') bindAdmin();
  if (v === 'attacker') bindAttacker();
}

function operatorPanel() {
  const P = state.config.parameters;
  return `<div class="card-head"><h2>Request a setpoint change: Sam (Operator, on shift)</h2></div>
  <p class="panel-intro">Routine changes are signed off by the Tide authority signer on Sam's request alone. Anything unusual is held until an independent engineer adds their approval. The AI check can escalate a request, but it can never approve one.</p>
  <div class="grid-2">
    <form class="form" id="op-form">
      <label>Parameter
        <select name="parameter" id="op-param">${Object.entries(P).map(([k, p]) => `<option value="${k}">${esc(p.label)}</option>`).join('')}</select>
      </label>
      <label>New value <span id="op-value-wrap"></span></label>
      <label>Reason <input name="reason" placeholder="e.g. raw water turbidity up after rain" value="Routine adjustment"></label>
      <div class="row">
        <button class="btn primary" type="submit">Submit request</button>
        <button class="btn ghost" type="button" data-preset="chlorine_mgL:1.2">Preset: chlorine → 1.2</button>
        <button class="btn ghost" type="button" data-preset="naoh_ppm:160">Preset: NaOH → 160</button>
      </div>
      <div id="op-result"></div>
    </form>
    <div><h3 style="margin-bottom:8px">Sam's recent requests</h3><div id="my-requests"></div></div>
  </div>`;
}

function renderValueInput(parameter, value) {
  const p = state.config.parameters[parameter];
  $('#op-value-wrap').innerHTML = p.kind === 'number'
    ? `<input name="value" type="number" step="any" value="${value ?? state.setpoints[parameter] ?? p.normal}">`
    : `<select name="value">${p.options.map((o) => `<option ${o === (value ?? state.setpoints[parameter]) ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
}

function bindOperator() {
  const sel = $('#op-param');
  renderValueInput(sel.value);
  sel.addEventListener('change', () => renderValueInput(sel.value));
  document.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => {
    const [k, v] = b.dataset.preset.split(':');
    sel.value = k;
    renderValueInput(k, v);
  }));
  $('#op-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const out = $('#op-result');
    out.innerHTML = '<p class="panel-intro">Submitting…</p>';
    try {
      const token = await tokenFor('sam');
      const r = await submitRequest(token, f.get('parameter'), f.get('value'), f.get('reason'));
      if (r.exec && r.exec.data.accepted) out.innerHTML = '<p class="pill ok">Executed: Tide signed it on the operator\'s request alone (low risk)</p>';
      else if (r.tide.data.status === 'pending') out.innerHTML = '<p class="pill warn">Held: needs an independent engineer\'s approval</p>';
      else out.innerHTML = `<p class="pill bad">${esc(r.tide.data.error || (r.exec && r.exec.data.error) || 'Refused')}</p>`;
    } catch (err) {
      out.innerHTML = `<p class="pill bad">${esc(err.message)}</p>`;
    }
    refresh();
  });
}

function engineerPanel() {
  return `<div class="card-head"><h2>Approvals inbox: ${esc(state.persona.label)} (Engineer)</h2></div>
  <p class="panel-intro">Approving adds <em>your</em> approval to this exact command, through your own TideCloak session. The app server cannot add it for you. You cannot approve your own request.</p>
  <div class="grid-2">
    <div><h3 style="margin-bottom:8px">Waiting for you</h3><div id="inbox"></div></div>
    <div><h3 style="margin-bottom:8px">Recent decisions</h3><div id="decided"></div></div>
  </div>`;
}

function adminPanel() {
  return `<div class="card-head"><h2>Governance: ${esc(state.persona.label)} (IT admin)</h2></div>
  <p class="panel-intro">Admins manage accounts but hold no plant authority. Any change to roles or the quorum policy is a change request that needs <strong id="adm-quorum">2</strong> different admins. No single admin, and no stolen admin login, can weaken the rules.</p>
  <div class="grid-2">
    <div>
      <h3 style="margin-bottom:8px">Current policy and roles</h3>
      <div id="policy"></div>
      <h3 style="margin:14px 0 8px">Propose a change</h3>
      <form class="form" id="cr-form">
        <label>Change
          <select name="kind">
            <option value="grant-role|engineer">Grant Engineer role</option>
            <option value="grant-role|operator">Grant Operator role</option>
            <option value="revoke-role|engineer">Revoke Engineer role</option>
            <option value="set-policy|engineerApprovals">Set engineer approvals required</option>
            <option value="set-policy|adminQuorum">Set admin quorum</option>
          </select>
        </label>
        <label>User (for role changes)
          <select name="target">${state.users.map((u) => `<option value="${u.id}">${esc(u.name)}</option>`).join('')}</select>
        </label>
        <label>Value (for policy changes) <input name="value" type="number" min="0" max="3" value="1"></label>
        <button class="btn primary" type="submit">Open change request</button>
        <div id="cr-result"></div>
      </form>
    </div>
    <div><h3 style="margin-bottom:8px">Change requests</h3><div id="crs"></div></div>
  </div>`;
}

function bindAdmin() {
  $('#cr-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const [type, x] = f.get('kind').split('|');
    const body = type === 'set-policy' ? { type, key: x, value: Number(f.get('value')) } : { type, role: x, target: f.get('target') };
    try {
      const token = await tokenFor(state.persona.user);
      if (isTidecloak()) {
        const r = await tcPropose(body);
        $('#cr-result').innerHTML = r.status === 202
          ? '<p class="pill warn">Held by TideCloak as a change request: it needs other admins to sign</p>'
          : `<p class="pill bad">${r.ok ? `Applied immediately (HTTP ${r.status}). IGA is not governing this realm!` : esc(r.data.errorMessage || r.data.error || `HTTP ${r.status}`)}</p>`;
        if (r.status === 202) audit('warn', `${nameOf(tideSession.user)} opened a change request. It needs a quorum of admins.`);
        lastCrFetch = 0;
      } else {
        const r = await tide('/admin/change-requests', { method: 'POST', token, body });
        $('#cr-result').innerHTML = r.ok
          ? `<p class="pill ${r.data.status === 'applied' ? 'ok' : 'warn'}">${r.data.status === 'applied' ? 'Applied' : `Pending: needs ${r.data.quorum - r.data.approvals.length} more admin(s)`}</p>`
          : `<p class="pill bad">${esc(r.data.error)}</p>`;
      }
    } catch (err) {
      $('#cr-result').innerHTML = `<p class="pill bad">${esc(err.message)}</p>`;
    }
    refresh();
  });
}

function attackerPanel() {
  const intro = isTidecloak()
    ? `The attacker has taken over a signed-in console: this window's TideCloak session (<b>${esc(tideSession.user ? nameOf(tideSession.user) : 'none')}</b>), plus root on the app server. Run ① from Sam's window and ③ from Morgan's. On an ordinary system, any one of those would be enough.`
    : 'The attacker has Sam\'s operator password and Morgan\'s admin password, and root on the app server. On an ordinary system, any one of those would be enough.';
  return `<div class="card-head"><h2>Attacker console</h2><span class="pill bad">${isTidecloak() ? 'Hijacked session' : 'Stolen credentials loaded'}</span></div>
  <p class="panel-intro">${intro}</p>

  <div class="attack">
    <h3>① Stolen operator login → NaOH to 11,100 ppm <span class="pill muted">Oldsmar 2021</span></h3>
    <p>Log in as Sam from an unknown laptop and push lye to 111× normal, then try to self-approve and force it through.</p>
    <button class="btn bad" id="atk-1">Launch</button>
    <ul class="steps" id="log-1"></ul>
  </div>

  <div class="attack">
    <h3>② Bypass the app: talk to the PLC directly <span class="pill muted">Ukraine 2015</span></h3>
    <p>Skip every approval and send the command straight to the controller, then have the compromised app server forge an "approved" authorization.</p>
    <div class="row"><button class="btn bad" id="atk-2a">Call PLC directly</button><button class="btn bad" id="atk-2b">Compromised backend forges approval</button></div>
    <ul class="steps" id="log-2"></ul>
  </div>

  <div class="attack">
    <h3>③ Stolen admin login → make myself Engineer, lower the quorum <span class="pill muted">Post Rock 2019</span></h3>
    <p>Use Morgan's admin account to grant Sam the Engineer role (so Sam can approve Sam), and set "engineer approvals required" to 0.</p>
    <button class="btn bad" id="atk-3">Launch</button>
    <ul class="steps" id="log-3"></ul>
  </div>`;
}

function step(list, tag, text) {
  const labels = { blocked: 'BLOCKED', ok: 'OK', wait: 'HELD', info: '…' };
  $(list).insertAdjacentHTML('beforeend', `<li><span class="tag ${tag}">${labels[tag]}</span><span>${text}</span></li>`);
}

function bindAttacker() {
  $('#atk-1').onclick = async (e) => {
    e.target.disabled = true;
    $('#log-1').innerHTML = '';
    let token;
    try { token = await tokenFor('sam', ATTACKER_DEVICE); } catch (err) {
      step('#log-1', 'info', esc(err.message));
      e.target.disabled = false;
      return;
    }
    step('#log-1', 'ok', isTidecloak()
      ? 'Using <b>Sam</b>\'s live TideCloak session from a hijacked laptop. A login is identity, not authority.'
      : 'Signed in to TideCloak as <b>Sam</b> with the stolen password. A login is identity, not authority.');
    const r = await submitRequest(token, 'naoh_ppm', 11100, 'pH correction', ATTACKER_DEVICE);
    step('#log-1', 'info', `AI check: <b>${r.record.risk.level.toUpperCase()}</b>. ${esc(r.record.risk.explanation)}`);
    step('#log-1', r.tide.data.status === 'authorized' ? 'ok' : 'wait',
      `The Tide authority signer withheld its signature: needs ${r.tide.data.engineersNeeded} independent engineer approval(s), has ${r.tide.data.engineers}.`);
    const self = await tide('/authorize', { method: 'POST', token, body: { request: r.record.request } });
    step('#log-1', self.data.status === 'authorized' ? 'ok' : 'blocked', 'Tried to approve it again as Sam: the requester\'s own approval never counts as the engineer\'s.');
    const force = await api(`/api/requests/${r.record.request.id}/execute`, { method: 'POST', body: { authorization: null } });
    step('#log-1', force.data.accepted ? 'ok' : 'blocked', `Forced the unsigned command to the PLC: ${esc(force.data.error || 'accepted')}`);
    step('#log-1', 'info', 'Switch to <b>Priya</b>: the request is waiting in her inbox.');
    e.target.disabled = false;
    refresh();
  };

  $('#atk-2a').onclick = async () => {
    const r = await plc('/command', { method: 'POST', body: { parameter: 'naoh_ppm', value: 11100, via: 'attacker-direct' } });
    step('#log-2', r.data.accepted ? 'ok' : 'blocked', `POST ${esc(state.config.plcUrl)}/command {naoh_ppm: 11100}: ${esc(r.data.error || 'accepted')}`);
    refresh();
  };
  $('#atk-2b').onclick = async () => {
    const r = await api('/api/demo/compromised-backend', { method: 'POST', body: { parameter: 'naoh_ppm', value: 11100 } });
    for (const a of r.data) step('#log-2', a.accepted ? 'ok' : 'blocked', `${esc(a.attempt)}: ${esc(a.error || 'accepted')}`);
    step('#log-2', 'info', 'The server has no key that the PLC trusts. Only the Tide authority signer can sign, and only when the quorum is met.');
    refresh();
  };

  $('#atk-3').onclick = async (e) => {
    e.target.disabled = true;
    $('#log-3').innerHTML = '';
    let token;
    try { token = await tokenFor('morgan', ATTACKER_DEVICE); } catch (err) {
      step('#log-3', 'info', esc(err.message));
      e.target.disabled = false;
      return;
    }
    if (isTidecloak()) {
      await attackAdminTidecloak(token);
      e.target.disabled = false;
      return refresh();
    }
    step('#log-3', 'ok', 'Signed in to TideCloak as <b>Morgan (admin)</b> with the stolen password.');
    const direct = await tide('/admin/roles', { method: 'POST', token, body: { target: 'sam', role: 'engineer' } });
    step('#log-3', direct.ok ? 'ok' : 'blocked', `Directly granted Sam the Engineer role: ${esc(direct.data.error || 'done')}`);
    const cr1 = await tide('/admin/change-requests', { method: 'POST', token, body: { type: 'grant-role', target: 'sam', role: 'engineer' } });
    step('#log-3', cr1.data.status === 'applied' ? 'ok' : 'wait', `Opened change request "${esc(cr1.data.description)}": needs ${cr1.data.quorum} admins, has ${cr1.data.approvals.length}.`);
    const again = await tide(`/admin/change-requests/${cr1.data.id}/approve`, { method: 'POST', token });
    step('#log-3', again.ok ? 'ok' : 'blocked', `Approved it a second time as Morgan: ${esc(again.data.error || again.data.status)}`);
    const cr2 = await tide('/admin/change-requests', { method: 'POST', token, body: { type: 'set-policy', key: 'engineerApprovals', value: 0 } });
    step('#log-3', cr2.data.status === 'applied' ? 'ok' : 'wait', `Opened change request "${esc(cr2.data.description)}": stuck pending; no second admin will sign.`);
    step('#log-3', 'info', 'Switch to <b>Jordan</b> to see both requests and reject them.');
    e.target.disabled = false;
    refresh();
  };
}

// Attack ③ against real TideCloak, using Morgan's hijacked admin session. Even if the attacker also
// has Morgan's Tide account and signs in the enclave, that is one signature of the quorum.
async function attackAdminTidecloak(token) {
  step('#log-3', 'ok', 'Using <b>Morgan (admin)</b>\'s live TideCloak session.');
  const direct = await tide('/admin/roles', { method: 'POST', token, body: { target: 'sam', role: 'engineer' } });
  step('#log-3', direct.ok ? 'ok' : 'blocked', `Asked the Tide gateway to grant Sam the Engineer role: ${esc(direct.data.error || 'done')}`);

  const grant = await tcPropose({ type: 'grant-role', target: 'sam', role: 'engineer' });
  step('#log-3', grant.status === 202 ? 'wait' : grant.ok ? 'ok' : 'blocked', grant.status === 202
    ? 'Granted Sam the Engineer role straight in the TideCloak admin API: TideCloak <b>did not apply it</b>. It is now a change request.'
    : `TideCloak admin API: ${esc(grant.ok ? `applied (HTTP ${grant.status})` : grant.data.errorMessage || grant.data.error || `HTTP ${grant.status}`)}`);

  lastCrFetch = 0;
  const crs = await fetchTidecloakCrs();
  const cr = crs.find((c) => c.status === 'pending' && /Grant engineer to Sam/i.test(c.description));
  if (cr) {
    step('#log-3', 'info', 'Signing it as Morgan in the Tide enclave (the attacker has Morgan\'s Tide account too)…');
    const signed = await tcApprove(cr.id);
    const n = signed.data && (signed.data.authCount ?? signed.data.authorizationCount);
    step('#log-3', signed.ok && !signed.data.committed ? 'wait' : signed.ok ? 'ok' : 'blocked', signed.ok
      ? `Morgan's signature counted: ${n ?? '?'}/${signed.data.threshold ?? cr.quorum}. ${signed.data.committed ? 'Committed!' : 'Still pending.'}`
      : `Morgan's approval: ${esc(signed.data.error || signed.data.errorMessage || `HTTP ${signed.status}`)}`);
    const again = await tcApprove(cr.id);
    step('#log-3', again.ok && again.data.committed ? 'ok' : 'blocked',
      `Signed again as Morgan: ${again.ok ? `still ${again.data.authCount ?? n ?? '?'}/${again.data.threshold ?? cr.quorum}. Each admin counts once.` : esc(again.data.error || again.data.errorMessage || `HTTP ${again.status}`)}`);
  }

  const policy = await tcPropose({ type: 'set-policy', key: 'engineerApprovals', value: 0 });
  step('#log-3', policy.status === 202 ? 'wait' : policy.ok ? 'ok' : 'blocked', policy.status === 202
    ? 'Set "engineer approvals required" to 0 in TideCloak: held as a change request. No second admin will sign.'
    : `Policy change: ${esc(policy.ok ? `applied (HTTP ${policy.status})` : policy.data.errorMessage || policy.data.error || `HTTP ${policy.status}`)}`);
  audit('blocked', 'Morgan\'s admin session tried to grant Sam the Engineer role and lower the quorum: both held for a second admin.');
  step('#log-3', 'info', 'Switch to <b>Jordan</b> (own browser profile) to see both requests and reject them.');
}

// ---------- Live lists ----------

function refreshLists() {
  const v = state.persona.view;
  if (v === 'operator' && $('#my-requests')) {
    const mine = state.requests.filter((r) => r.request.requestedBy === 'sam').slice(0, 6);
    $('#my-requests').innerHTML = mine.length ? mine.map((r) => requestCard(r)).join('') : '<div class="empty">No requests yet</div>';
  }
  if (v === 'engineer' && $('#inbox')) {
    const pending = state.requests.filter((r) => r.status === 'pending-approval');
    const decided = state.requests.filter((r) => ['executed', 'rejected', 'plc-rejected'].includes(r.status)).slice(0, 5);
    $('#inbox').innerHTML = pending.length ? pending.map((r) => requestCard(r, { actions: true })).join('') : '<div class="empty">Nothing waiting. Normal work flows without you.</div>';
    $('#decided').innerHTML = decided.length ? decided.map((r) => requestCard(r)).join('') : '<div class="empty">No decisions yet</div>';
    bindCardActions($('#inbox'));
  }
  if (v === 'admin' && $('#crs')) {
    const live = state.changeRequests.find((c) => c.quorum);
    const quorum = state.policy.adminQuorum || (live ? live.quorum : '70% of');
    $('#adm-quorum').textContent = quorum;
    $('#policy').innerHTML = `<table class="simple">
      <tr><th>Engineer approvals for non-routine commands</th><td><b>${state.policy.engineerApprovals}</b></td></tr>
      <tr><th>Admins needed for any governance change</th><td><b>${esc(quorum)}</b>${isTidecloak() ? ' (enforced by TideCloak)' : ''}</td></tr>
      <tr><th>Policy source</th><td>${isTidecloak() ? 'TideCloak realm, read live' : `v${state.policy.version}`}</td></tr>
    </table>
    <table class="simple" style="margin-top:10px"><tr><th>User</th><th>Roles</th></tr>
      ${state.users.map((u) => `<tr><td>${esc(u.name)}</td><td>${u.roles.map(esc).join(', ')}</td></tr>`).join('')}
    </table>`;
    const me = state.persona.user;
    $('#crs').innerHTML = state.changeRequests.length ? state.changeRequests.map((c) => {
      const cls = c.status === 'applied' ? 'ok' : c.status === 'rejected' ? 'bad' : 'warn';
      const name = (id) => (state.users.find((u) => u.id === id) || { name: id }).name;
      return `<div class="req">
        <div class="top"><span class="meta">${esc(String(c.id).slice(0, 8))} · opened by ${esc(name(c.createdBy))}</span><span class="pill ${cls}">${c.status}${c.status === 'pending' ? ` ${c.count ?? c.approvals.length}/${c.quorum}` : ''}</span></div>
        <div class="change">${esc(c.description)}</div>
        <div class="meta">${isTidecloak() ? 'Signed by' : 'Approved by'}: ${c.approvals.map(name).map(esc).join(', ') || 'nobody yet'}${c.rejectedBy ? ` · rejected by ${esc(name(c.rejectedBy))}` : ''}</div>
        ${c.status === 'pending' ? `<div class="row" style="margin-top:8px">
          <button class="btn ok" data-cr-approve="${c.id}" ${c.approvals.includes(me) ? 'disabled title="You already approved"' : ''}>Approve</button>
          <button class="btn bad" data-cr-reject="${c.id}">Reject</button></div>` : ''}
      </div>`;
    }).join('') : '<div class="empty">No change requests</div>';
    document.querySelectorAll('[data-cr-approve]').forEach((b) => b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        const token = await tokenFor(me);
        const cr = state.changeRequests.find((c) => c.id === b.dataset.crApprove);
        const r = isTidecloak() ? await tcApprove(cr.id) : await tide(`/admin/change-requests/${cr.id}/approve`, { method: 'POST', token });
        if (!r.ok) flash('blocked', r.data.error || r.data.errorMessage || r.data.message || `HTTP ${r.status}`);
        else if (isTidecloak()) {
          audit(r.data.committed ? 'ok' : 'warn', `${nameOf(me)} signed "${cr.description}" in their Tide enclave: ${r.data.authCount ?? '?'}/${r.data.threshold ?? cr.quorum}${r.data.committed ? ', committed' : ''}`);
        }
      } catch (err) { flash('blocked', err.message); }
      lastCrFetch = 0;
      refresh();
    }));
    document.querySelectorAll('[data-cr-reject]').forEach((b) => b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        const token = await tokenFor(me);
        const cr = state.changeRequests.find((c) => c.id === b.dataset.crReject);
        if (isTidecloak()) {
          const r = await tcDeny(cr.id);
          if (r.ok) audit('blocked', `${nameOf(me)} rejected change request "${cr.description}"`);
        } else {
          await tide(`/admin/change-requests/${cr.id}/reject`, { method: 'POST', token });
        }
      } catch (err) { flash('blocked', err.message); }
      lastCrFetch = 0;
      refresh();
    }));
  }
}

// ---------- Audit feed + alerts ----------

function renderEvents() {
  const list = state.events.slice(0, 120);
  $('#events').innerHTML = list.map((e) => `<li class="${e.kind} ${state.seenEvents.has(e.id) ? '' : 'fresh'}">
    <span class="chip ${e.source}">${e.source.toUpperCase()}</span> ${esc(e.message)}
    <span class="when">${new Date(e.at).toLocaleTimeString()}</span></li>`).join('');

  const fresh = list.filter((e) => !state.seenEvents.has(e.id));
  list.forEach((e) => state.seenEvents.add(e.id));
  if (state.firstLoad) { state.firstLoad = false; return; }
  const blocked = fresh.find((e) => e.kind === 'blocked' && e.source !== 'app');
  const executed = fresh.find((e) => e.source === 'plc' && e.kind === 'ok');
  if (blocked) flash('blocked', `ATTACK BLOCKED: ${blocked.message}`);
  else if (executed) flash('ok', executed.message);
}

let alertTimer;
function flash(kind, message) {
  const el = $('#alert');
  el.className = `alert ${kind}`;
  el.textContent = `${kind === 'blocked' ? '⛔ ' : kind === 'ok' ? '✓ ' : ''}${message}`;
  clearTimeout(alertTimer);
  alertTimer = setTimeout(() => el.classList.add('hidden'), 3800);
}

// ---------- Polling ----------

async function refresh() {
  try {
    const adminView = state.persona && state.persona.view === 'admin';
    const [reqs, st, appEv, plcEv, tideEv, pol, crs] = await Promise.all([
      api('/api/requests'), plc('/state'), api('/api/events'), plc('/events'), tide('/events'), tide('/policy'),
      isTidecloak() ? (adminView ? fetchTidecloakCrs() : state.changeRequests) : tide('/admin/change-requests').then((r) => r.data.changeRequests)
    ]);
    state.requests = reqs.data;
    state.setpoints = st.data.setpoints;
    state.events = [...appEv.data, ...plcEv.data, ...tideEv.data].sort((a, b) => b.at.localeCompare(a.at));
    if (pol.ok) {
      state.policy = pol.data.policy;
      state.users = pol.data.users;
    }
    state.changeRequests = crs || [];
    renderPlant();
    renderEvents();
    refreshLists();
  } catch (err) {
    console.warn('refresh failed', err);
  }
}

(async function init() {
  state.config = (await api('/api/config')).data;
  $('#plant-name').textContent = state.config.plant.name;
  if (isTidecloak()) {
    try { await initTideSession(); } catch (err) { flash('blocked', `TideCloak unavailable: ${err.message}`); }
    renderSession();
  }
  await refresh();
  // ?as=priya opens a persona directly, so each person can have their own tab (sim) or browser
  // profile (TideCloak). With TideCloak the default view is whoever this window is signed in as.
  let saved = new URLSearchParams(location.search).get('as');
  if (!saved && tideSession.user && PERSONAS.some((p) => p.user === tideSession.user)) saved = tideSession.user;
  try { saved = saved || localStorage.getItem('persona'); } catch { /* ignore */ }
  selectPersona(saved || 'sam');
  setInterval(refresh, 1500);
})();
