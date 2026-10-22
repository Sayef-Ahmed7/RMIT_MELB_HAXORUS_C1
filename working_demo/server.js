const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');
const dotenv = require('dotenv');
const openidClient = require('openid-client');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_MODE = (process.env.TIDE_AUTH_MODE || 'oidc').toLowerCase();
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'vault.json');

const syntheticUsers = {
  'exam-admin': { id: 'exam-admin', name: 'Exam Admin', roles: ['exam-admin'] },
  'paper-setter': { id: 'paper-setter', name: 'Paper Setter', roles: ['paper-setter'] },
  'custodian-1': { id: 'custodian-1', name: 'Custodian 1', roles: ['custodian'] },
  'custodian-2': { id: 'custodian-2', name: 'Custodian 2', roles: ['custodian'] },
  'custodian-3': { id: 'custodian-3', name: 'Custodian 3', roles: ['custodian'] }
};

const state = {
  custodians: ['custodian-1', 'custodian-2', 'custodian-3'],
  papers: [],
  notifications: [],
  auditLog: []
};

function getSessionUser(req) {
  if (req.session && req.session.user) return req.session.user;
  return null;
}

function normalizeRoles(roles) {
  const list = Array.isArray(roles) ? roles : [];
  return list.map(String);
}

function hasRole(user, roleName) {
  if (!user) return false;
  const roles = normalizeRoles(Array.isArray(user.roles) ? user.roles : (user.role ? [user.role] : []));
  return roles.includes(roleName);
}

function isExamAdmin(user) {
  return !!user && (user.id === 'exam-admin' || hasRole(user, 'exam-admin'));
}

function isCustodian(user) {
  return !!user && state.custodians.includes(user.id);
}

function resolveUserPayload(rawUser) {
  if (!rawUser) return null;
  const roles = Array.isArray(rawUser.roles)
    ? rawUser.roles
    : (rawUser.role ? [rawUser.role] : []);

  return {
    id: rawUser.id || rawUser.sub || rawUser.username || rawUser.email,
    name: rawUser.name || rawUser.preferred_username || rawUser.email || rawUser.id,
    roles: normalizeRoles(roles),
    email: rawUser.email || null,
    source: rawUser.source || 'synthetic'
  };
}

function getPaperKey() {
  return crypto.createHash('sha256').update(process.env.PAPER_VAULT_KEY || 'exam-paper-vault-demo-key').digest();
}

function doEncrypt(value) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', getPaperKey(), iv);
  const payload = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, payload]).toString('base64');
}

function doDecrypt(value) {
  const raw = Buffer.from(value, 'base64');
  const iv = raw.subarray(0, 16);
  const tag = raw.subarray(16, 32);
  const encrypted = raw.subarray(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', getPaperKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function addAudit(event, actorId, details = {}) {
  state.auditLog.unshift({
    id: `evt-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    event,
    actorId,
    at: new Date().toISOString(),
    details
  });
}

function persistVault() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify({
    custodians: state.custodians,
    papers: state.papers,
    notifications: state.notifications,
    auditLog: state.auditLog
  }, null, 2));
}

function seedPapers() {
  const samplePapers = [
    {
      title: 'Advanced Calculus Final',
      subject: 'Mathematics',
      examDate: '2026-12-12',
      content: 'The final paper includes three extended proof questions and one derivation challenge.'
    },
    {
      title: 'Biology Practical',
      subject: 'Biology',
      examDate: '2026-11-18',
      content: 'Students must identify labelled cells from specimen slides and explain the observed stages.'
    },
    {
      title: 'Literature Essay',
      subject: 'English',
      examDate: '2026-10-30',
      content: 'Write a comparative essay on irony and narrative voice in the two set texts.'
    }
  ];

  return samplePapers.map((paper, index) => ({
    id: `paper-${index + 1}`,
    title: paper.title,
    subject: paper.subject,
    examDate: paper.examDate,
    createdAt: new Date().toISOString(),
    status: 'Sealed',
    ciphertext: doEncrypt(paper.content),
    requests: [],
    approvals: [],
    rejections: [],
    openedAt: null,
    openedBy: null,
    openedFor: null
  }));
}

function loadVault() {
  if (!fs.existsSync(DATA_FILE)) {
    state.custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
    state.papers = seedPapers();
    state.notifications = [];
    state.auditLog = [];
    persistVault();
    return;
  }

  try {
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    state.custodians = Array.isArray(raw.custodians) && raw.custodians.length ? raw.custodians : ['custodian-1', 'custodian-2', 'custodian-3'];
    state.papers = Array.isArray(raw.papers) && raw.papers.length ? raw.papers : seedPapers();
    state.notifications = Array.isArray(raw.notifications) ? raw.notifications : [];
    state.auditLog = Array.isArray(raw.auditLog) ? raw.auditLog : [];
  } catch (error) {
    console.warn('Falling back to a fresh vault state', error.message);
    state.custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
    state.papers = seedPapers();
    state.notifications = [];
    state.auditLog = [];
    persistVault();
  }
}

function getPaperById(id) {
  return state.papers.find((paper) => paper.id === String(id));
}

function buildPaperResponse(paper) {
  const safePaper = {
    id: paper.id,
    title: paper.title,
    subject: paper.subject,
    examDate: paper.examDate,
    createdAt: paper.createdAt,
    status: paper.status,
    approvals: paper.approvals || [],
    requests: paper.requests || [],
    openedAt: paper.openedAt,
    openedBy: paper.openedBy,
    ciphertext: paper.ciphertext,
    isOpen: paper.status === 'Opened'
  };

  if (paper.status === 'Opened') {
    safePaper.content = doDecrypt(paper.ciphertext);
  }

  return safePaper;
}

function createOpenRequestNotification(paper, requesterId) {
  const requesterName = syntheticUsers[requesterId]?.name || requesterId;
  const recipients = [...state.custodians, 'exam-admin'];

  recipients.forEach((recipientId) => {
    state.notifications.unshift({
      id: `notif-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
      recipientId,
      paperId: paper.id,
      paperTitle: paper.title,
      requesterId,
      requesterName,
      createdAt: new Date().toISOString(),
      type: 'open-request',
      status: 'pending',
      action: 'pending'
    });
  });
}

function recordDecision(paperId, actorId, decision) {
  const paper = getPaperById(paperId);
  if (!paper) return { statusCode: 404, payload: { error: 'Paper not found' } };

  if (!syntheticUsers[actorId]) {
    return { statusCode: 400, payload: { error: 'Unknown actor' } };
  }

  if (!state.custodians.includes(actorId)) {
    return { statusCode: 403, payload: { error: 'Only custodians may approve or reject a paper opening.' } };
  }

  if (paper.status === 'Opened') {
    return { statusCode: 409, payload: { error: 'This paper is already opened.' } };
  }

  const request = (paper.requests || []).slice(-1)[0];
  if (!request) {
    return { statusCode: 400, payload: { error: 'No open request exists for this paper.' } };
  }

  if (decision === 'approve') {
    if ((request.approvals || []).includes(actorId)) {
      return { statusCode: 409, payload: { error: 'This custodian has already approved this request.' } };
    }

    request.approvals = [...new Set([...(request.approvals || []), actorId])];
    paper.approvals = [...new Set([...(paper.approvals || []), actorId])];
    addAudit('paper_approved', actorId, { paperId: paper.id, paperTitle: paper.title, requestId: request.id });

    if (request.approvals.length >= 2) {
      paper.status = 'Opened';
      paper.openedAt = new Date().toISOString();
      paper.openedBy = actorId;
      paper.openedFor = request.requesterId;
      addAudit('paper_opened', actorId, { paperId: paper.id, paperTitle: paper.title, approvals: request.approvals });
    }

    persistVault();
    return { statusCode: 200, payload: { paper: buildPaperResponse(paper), request, status: paper.status } };
  }

  if (decision === 'reject') {
    if ((request.rejections || []).includes(actorId)) {
      return { statusCode: 409, payload: { error: 'This custodian has already rejected this request.' } };
    }

    request.rejections = [...new Set([...(request.rejections || []), actorId])];
    paper.rejections = [...new Set([...(paper.rejections || []), actorId])];
    addAudit('paper_rejected', actorId, { paperId: paper.id, paperTitle: paper.title, requestId: request.id });
    persistVault();
    return { statusCode: 200, payload: { paper: buildPaperResponse(paper), request, status: 'Rejected' } };
  }

  return { statusCode: 400, payload: { error: 'Decision must be either approve or reject.' } };
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'exam-paper-vault-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: false }
  })
);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/session', (req, res) => {
  const user = getSessionUser(req);
  res.json({
    authMode: AUTH_MODE,
    currentUser: user,
    users: Object.values(syntheticUsers),
    custodians: state.custodians,
    policy: {
      name: 'Exam paper decryption quorum',
      quorumRequired: 2,
      custodians: state.custodians,
      rule: 'At least 2 of 3 custodians must approve before any paper decrypts.'
    }
  });
});

app.get('/auth/login', (req, res) => {
  if (AUTH_MODE === 'oidc') {
    return res.redirect('/auth/tide');
  }

  return res.redirect('/');
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.post('/api/login', (req, res) => {
  const { userId } = req.body || {};

  if (AUTH_MODE === 'oidc') {
    return res.status(400).json({ error: 'OIDC mode uses the provider login flow.' });
  }

  const user = syntheticUsers[userId];
  if (!user) {
    return res.status(400).json({ error: 'Unknown user' });
  }

  req.session.user = resolveUserPayload({ ...user, source: 'synthetic' });
  return res.json({
    currentUser: req.session.user,
    policy: {
      quorumRequired: 2,
      custodians: state.custodians,
      rule: 'At least 2 of 3 custodians must approve before any paper decrypts.'
    }
  });
});

app.get('/api/database', (req, res) => {
  const papers = state.papers.map((paper) => ({
    id: paper.id,
    title: paper.title,
    subject: paper.subject,
    examDate: paper.examDate,
    status: paper.status,
    ciphertext: paper.ciphertext,
    approvals: paper.approvals || [],
    createdAt: paper.createdAt
  }));

  res.json({ papers });
});

app.get('/api/papers', (req, res) => {
  res.json({
    papers: state.papers.map((paper) => ({
      id: paper.id,
      title: paper.title,
      subject: paper.subject,
      examDate: paper.examDate,
      status: paper.status,
      approvals: paper.approvals || [],
      requests: paper.requests || [],
      openedAt: paper.openedAt,
      openedBy: paper.openedBy,
      ciphertext: paper.ciphertext
    }))
  });
});

app.post('/api/papers', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first to upload a paper.' });
  }

  if (!isExamAdmin(currentUser) && !hasRole(currentUser, 'paper-setter')) {
    return res.status(403).json({ error: 'Only the paper setter or exam admin can upload a paper.' });
  }

  const { title, subject, examDate, content } = req.body || {};
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required.' });
  }

  const paper = {
    id: `paper-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    title,
    subject: subject || 'General',
    examDate: examDate || new Date().toISOString().slice(0, 10),
    createdAt: new Date().toISOString(),
    status: 'Sealed',
    ciphertext: doEncrypt(content),
    approvals: [],
    rejections: [],
    requests: [],
    openedAt: null,
    openedBy: null,
    openedFor: null
  };

  state.papers.unshift(paper);
  addAudit('paper_uploaded', currentUser.id, { paperId: paper.id, title });
  persistVault();

  return res.status(201).json({ paper: buildPaperResponse(paper) });
});

app.post('/api/papers/:paperId/open-request', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const paper = getPaperById(req.params.paperId);
  if (!paper) {
    return res.status(404).json({ error: 'Paper not found' });
  }

  if (paper.status === 'Opened') {
    return res.status(409).json({ error: 'This paper is already open.' });
  }

  const requesterId = (req.body && req.body.requesterId) || currentUser.id;
  const request = {
    id: `req-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
    paperId: paper.id,
    requesterId,
    requestedAt: new Date().toISOString(),
    status: 'Pending',
    approvals: [],
    rejections: []
  };

  paper.requests = [...(paper.requests || []), request];
  addAudit('open_request_created', requesterId, { paperId: paper.id, requestId: request.id });
  createOpenRequestNotification(paper, requesterId);
  persistVault();

  return res.status(201).json({ request, paper: buildPaperResponse(paper) });
});

app.post('/api/papers/:paperId/approve', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const actorId = (req.body && req.body.userId) || currentUser.id;
  const result = recordDecision(req.params.paperId, actorId, 'approve');
  if (result.statusCode !== 200) {
    return res.status(result.statusCode).json(result.payload);
  }

  return res.json(result.payload);
});

app.post('/api/papers/:paperId/reject', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const actorId = (req.body && req.body.userId) || currentUser.id;
  const result = recordDecision(req.params.paperId, actorId, 'reject');
  if (result.statusCode !== 200) {
    return res.status(result.statusCode).json(result.payload);
  }

  return res.json(result.payload);
});

app.post('/api/notifications/:notificationId/decision', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const notification = state.notifications.find((item) => item.id === req.params.notificationId);
  if (!notification) {
    return res.status(404).json({ error: 'Notification not found.' });
  }

  const decision = (req.body && req.body.decision) || 'approve';
  const result = recordDecision(notification.paperId, currentUser.id, decision);
  if (result.statusCode !== 200) {
    return res.status(result.statusCode).json(result.payload);
  }

  notification.status = 'resolved';
  notification.action = decision;
  persistVault();
  return res.json(result.payload);
});

app.get('/api/notifications', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const notifications = state.notifications.filter((entry) => {
    if (entry.recipientId === currentUser.id) return true;
    if (isExamAdmin(currentUser) && entry.recipientId === 'exam-admin') return true;
    return false;
  });

  return res.json({ notifications });
});

app.get('/api/papers/:paperId', (req, res) => {
  const paper = getPaperById(req.params.paperId);
  if (!paper) {
    return res.status(404).json({ error: 'Paper not found' });
  }

  const currentUser = getSessionUser(req);
  if (paper.status === 'Opened') {
    return res.json({ paper: buildPaperResponse(paper) });
  }

  return res.json({
    paper: {
      id: paper.id,
      title: paper.title,
      subject: paper.subject,
      examDate: paper.examDate,
      status: 'Sealed',
      approvals: paper.approvals || [],
      requests: paper.requests || [],
      ciphertext: paper.ciphertext,
      message: 'This paper is sealed. It can be opened only after 2 of 3 custodians approve.'
    }
  });
});

app.post('/api/admin/custodians', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in as the exam admin.' });
  }

  if (!isExamAdmin(currentUser)) {
    return res.status(403).json({ error: 'Only the exam admin can change the custodian roster.' });
  }

  const { confirmers, newCustodians } = req.body || {};
  const validConfirmers = Array.isArray(confirmers) ? [...new Set(confirmers)] : [];

  if (!validConfirmers || validConfirmers.length < 2) {
    return res.status(400).json({ error: 'Custodian roster changes require 2 custodians to confirm.' });
  }

  if (!validConfirmers.every((id) => state.custodians.includes(id))) {
    return res.status(400).json({ error: 'Only active custodians may confirm a roster change.' });
  }

  const nextCustodians = Array.isArray(newCustodians) ? [...new Set(newCustodians.filter(Boolean))] : [];
  if (nextCustodians.length !== 3) {
    return res.status(400).json({ error: 'A valid custodian list contains exactly 3 custodians.' });
  }

  if (nextCustodians.includes(currentUser.id)) {
    return res.status(400).json({ error: 'Admin cannot add themselves as a custodian.' });
  }

  state.custodians = nextCustodians;
  addAudit('custodian_roster_changed', currentUser.id, { newCustodians: nextCustodians, confirmers: validConfirmers });
  persistVault();

  return res.json({
    success: true,
    message: 'Custodian roster updated by quorum.',
    custodians: state.custodians
  });
});

app.post('/api/reset-demo', (req, res) => {
  state.custodians = ['custodian-1', 'custodian-2', 'custodian-3'];
  state.papers = seedPapers();
  state.notifications = [];
  state.auditLog = [];
  addAudit('demo_reset', 'system', { message: 'Synthetic exam vault reset to seed data.' });
  persistVault();
  return res.json({
    success: true,
    message: 'Demo reset complete. 3 synthetic papers and 5 users were re-seeded.',
    custodians: state.custodians,
    papers: state.papers.map((paper) => ({ id: paper.id, title: paper.title, status: paper.status }))
  });
});

async function configureOidc() {
  if (AUTH_MODE !== 'oidc') return;

  const issuerUrl = process.env.TIDE_ISSUER;
  const clientId = process.env.TIDE_CLIENT_ID;
  const clientSecret = process.env.TIDE_CLIENT_SECRET;
  const redirectUri = process.env.TIDE_REDIRECT_URI || 'http://localhost:3000/auth/callback';

  if (!issuerUrl || !clientId || !clientSecret) {
    throw new Error('OIDC mode is enabled but TIDE_ISSUER, TIDE_CLIENT_ID, and TIDE_CLIENT_SECRET must be configured.');
  }

  const config = await openidClient.discovery(new URL(issuerUrl), clientId, undefined, undefined, {
    execute: [openidClient.allowInsecureRequests]
  });

  app.get('/auth/tide', (req, res) => {
    const params = {
      redirect_uri: redirectUri,
      scope: 'openid profile email roles',
      state: openidClient.randomState(),
      response_type: 'code'
    };
    const redirectUrl = openidClient.buildAuthorizationUrl(config, params);
    res.redirect(redirectUrl.href);
  });

  app.get('/auth/callback', async (req, res) => {
    try {
      const currentUrl = new URL(req.originalUrl, redirectUri);
      const tokenSet = await openidClient.authorizationCodeGrant(config, currentUrl, {
        expectedState: req.query.state,
        pkceCodeVerifier: undefined
      });
      const claims = tokenSet.claims();
      const principal = resolveUserPayload({
        id: claims.sub,
        name: claims.name || claims.preferred_username || claims.email || claims.sub,
        email: claims.email || null,
        roles: claims.roles || claims.realm_access?.roles || claims.resource_access?.account?.roles || [],
        source: 'oidc'
      });

      req.session.user = principal;
      return res.redirect('/');
    } catch (error) {
      console.error('OIDC callback failed:', error);
      return res.status(500).json({ error: 'OIDC login failed.' });
    }
  });
}

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async function start() {
  try {
    loadVault();
    await configureOidc();
    app.listen(PORT, () => {
      console.log(`Exam Paper Vault is listening on http://localhost:${PORT}`);
      console.log(`Auth mode: ${AUTH_MODE}`);
    });
  } catch (error) {
    console.error('Startup failed:', error);
    process.exit(1);
  }
})();

