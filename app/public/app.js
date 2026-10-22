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

async function http(url, { method = 'GET', token, body } = {}) {
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  return { status: res.status, ok: res.ok, data };
}

const tide = (path, opts) => http(`${state.config.tideUrl}${path}`, opts);
const plc = (path, opts) => http(`${state.config.plcUrl}${path}`, opts);
const api = (path, opts) => http(path, opts);

// TideCloak login. In the demo every synthetic password is "demo"; the attacker simply has it.
async function tokenFor(user, device) {
  const key = `${user}|${device || ''}`;
  if (!state.tokens[key]) {
    const r = await tide('/login', { method: 'POST', body: { username: user, password: 'demo', device } });
    if (!r.ok) throw new Error(r.data.error || 'Login failed');
    state.tokens[key] = r.data.token;
  }
  return state.tokens[key];
}

// ---------- Core flows ----------

async function submitRequest(token, parameter, value, reason) {
  const created = await api('/api/requests', { method: 'POST', token, body: { parameter, value, reason } });
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
  const token = await tokenFor(state.persona.user);
  const t = await tide('/authorize', { method: 'POST', token, body: { request: record.request } });
  if (t.data.status === 'authorized') {
    await api(`/api/requests/${record.request.id}/execute`, { method: 'POST', body: { authorization: t.data.authorization } });
  } else if (!t.ok) {
    flash('blocked', t.data.error);
  }
  refresh();
}

async function reject(record) {
  const token = await tokenFor(state.persona.user);
  const t = await tide('/reject', { method: 'POST', token, body: { request: record.request } });
  if (t.ok) await api(`/api/requests/${record.request.id}/reject`, { method: 'POST', token });
  refresh();
}

// ---------- Rendering: header, plant, gauges ----------

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
      <button class="btn ok" data-approve="${esc(r.request.id)}">Approve with my Tide key</button>
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
  <p class="panel-intro">Routine changes are signed off by the Tide network on Sam's request alone. Anything unusual is held until an independent engineer adds their approval. The AI check can escalate a request, but it can never approve one.</p>
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
  <p class="panel-intro">Approving adds <em>your</em> share of authority for this exact command, through your own TideCloak session. The app server never holds it. You cannot approve your own request.</p>
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
    const token = await tokenFor(state.persona.user);
    const r = await tide('/admin/change-requests', { method: 'POST', token, body });
    $('#cr-result').innerHTML = r.ok
      ? `<p class="pill ${r.data.status === 'applied' ? 'ok' : 'warn'}">${r.data.status === 'applied' ? 'Applied' : `Pending: needs ${r.data.quorum - r.data.approvals.length} more admin(s)`}</p>`
      : `<p class="pill bad">${esc(r.data.error)}</p>`;
    refresh();
  });
}

function attackerPanel() {
  return `<div class="card-head"><h2>Attacker console</h2><span class="pill bad">Stolen credentials loaded</span></div>
  <p class="panel-intro">The attacker has Sam's operator password and Morgan's admin password, and root on the app server. On an ordinary system, any one of those would be enough.</p>

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
    const token = await tokenFor('sam', ATTACKER_DEVICE);
    step('#log-1', 'ok', 'Signed in to TideCloak as <b>Sam</b> with the stolen password. A login is identity, not authority.');
    const r = await submitRequest(token, 'naoh_ppm', 11100, 'pH correction');
    step('#log-1', 'info', `AI check: <b>${r.record.risk.level.toUpperCase()}</b>. ${esc(r.record.risk.explanation)}`);
    step('#log-1', r.tide.data.status === 'authorized' ? 'ok' : 'wait',
      `Tide network withheld the authority signature: needs ${r.tide.data.engineersNeeded} independent engineer approval(s), has ${r.tide.data.engineers}.`);
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
    step('#log-2', 'info', 'The server has no key that the PLC trusts. Only the Tide network can sign, and only when the quorum is met.');
    refresh();
  };

  $('#atk-3').onclick = async (e) => {
    e.target.disabled = true;
    $('#log-3').innerHTML = '';
    const token = await tokenFor('morgan', ATTACKER_DEVICE);
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
    $('#adm-quorum').textContent = state.policy.adminQuorum;
    $('#policy').innerHTML = `<table class="simple">
      <tr><th>Engineer approvals for non-routine commands</th><td><b>${state.policy.engineerApprovals}</b></td></tr>
      <tr><th>Admins needed for any governance change</th><td><b>${state.policy.adminQuorum}</b></td></tr>
      <tr><th>Policy version</th><td>${state.policy.version}</td></tr>
    </table>
    <table class="simple" style="margin-top:10px"><tr><th>User</th><th>Roles</th></tr>
      ${state.users.map((u) => `<tr><td>${esc(u.name)}</td><td>${u.roles.map(esc).join(', ')}</td></tr>`).join('')}
    </table>`;
    const me = state.persona.user;
    $('#crs').innerHTML = state.changeRequests.length ? state.changeRequests.map((c) => {
      const cls = c.status === 'applied' ? 'ok' : c.status === 'rejected' ? 'bad' : 'warn';
      const name = (id) => (state.users.find((u) => u.id === id) || { name: id }).name;
      return `<div class="req">
        <div class="top"><span class="meta">${esc(c.id)} · opened by ${esc(name(c.createdBy))}</span><span class="pill ${cls}">${c.status}${c.status === 'pending' ? ` ${c.approvals.length}/${c.quorum}` : ''}</span></div>
        <div class="change">${esc(c.description)}</div>
        <div class="meta">Approved by: ${c.approvals.map(name).map(esc).join(', ')}${c.rejectedBy ? ` · rejected by ${esc(name(c.rejectedBy))}` : ''}</div>
        ${c.status === 'pending' ? `<div class="row" style="margin-top:8px">
          <button class="btn ok" data-cr-approve="${c.id}" ${c.approvals.includes(me) ? 'disabled title="You already approved"' : ''}>Approve</button>
          <button class="btn bad" data-cr-reject="${c.id}">Reject</button></div>` : ''}
      </div>`;
    }).join('') : '<div class="empty">No change requests</div>';
    document.querySelectorAll('[data-cr-approve]').forEach((b) => b.addEventListener('click', async () => {
      const r = await tide(`/admin/change-requests/${b.dataset.crApprove}/approve`, { method: 'POST', token: await tokenFor(me) });
      if (!r.ok) flash('blocked', r.data.error);
      refresh();
    }));
    document.querySelectorAll('[data-cr-reject]').forEach((b) => b.addEventListener('click', async () => {
      await tide(`/admin/change-requests/${b.dataset.crReject}/reject`, { method: 'POST', token: await tokenFor(me) });
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
    const [reqs, st, appEv, plcEv, tideEv, pol, crs] = await Promise.all([
      api('/api/requests'), plc('/state'), api('/api/events'), plc('/events'), tide('/events'), tide('/policy'), tide('/admin/change-requests')
    ]);
    state.requests = reqs.data;
    state.setpoints = st.data.setpoints;
    state.events = [...appEv.data, ...plcEv.data, ...tideEv.data].sort((a, b) => b.at.localeCompare(a.at));
    state.policy = pol.data.policy;
    state.users = pol.data.users;
    state.changeRequests = crs.data.changeRequests;
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
  await refresh();
  // ?as=priya opens a persona directly, so each person can have their own tab.
  let saved = new URLSearchParams(location.search).get('as');
  try { saved = saved || localStorage.getItem('persona'); } catch { /* ignore */ }
  selectPersona(saved || 'sam');
  setInterval(refresh, 1500);
})();
