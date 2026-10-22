const express = require('express');
const path = require('path');
const session = require('express-session');
const dotenv = require('dotenv');
const { Issuer, Strategy } = require('openid-client');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_MODE = (process.env.TIDE_AUTH_MODE || 'mock').toLowerCase();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'expense-demo-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: false }
  })
);
app.use(express.static(path.join(__dirname, 'public')));

const syntheticUsers = {
  alice: { id: 'alice', name: 'Alice Johnson', roles: ['employee'] },
  bob: { id: 'bob', name: 'Bob Chan', roles: ['employee'] },
  charlie: { id: 'charlie', name: 'Charlie Reed', roles: ['employee'] },
  maya: { id: 'maya', name: 'Maya Patel', roles: ['manager'] },
  owen: { id: 'owen', name: 'Owen Brooks', roles: ['manager'] },
  sara: { id: 'sara', name: 'Sara Lewis', roles: ['manager'] },
  nora: { id: 'nora', name: 'Nora James', roles: ['admin'] },
  imran: { id: 'imran', name: 'Imran Ali', roles: ['admin'] }
};

const approverConfig = {
  threshold: 1000,
  approvalsRequired: 2,
  managers: ['maya', 'owen', 'sara'],
  adminPolicyApprovalsRequired: 2,
  adminApprovers: ['nora', 'imran']
};

function getSessionUser(req) {
  if (req.session && req.session.user) return req.session.user;
  return null;
}

function normalizeRoles(roles) {
  return Array.isArray(roles) ? roles.map(String) : [];
}

function hasRole(user, roleName) {
  if (!user) return false;
  const roles = normalizeRoles(Array.isArray(user.roles) ? user.roles : (user.role ? [user.role] : []));
  return roles.includes(roleName);
}

function canApprove(user) {
  return user && ((Array.isArray(user.roles) && user.roles.includes('manager')) || user.role === 'manager');
}

function canAdmin(user) {
  return user && ((Array.isArray(user.roles) && user.roles.includes('admin')) || user.role === 'admin');
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

function ensurePolicyShape(policy) {
  return {
    threshold: policy.threshold || approverConfig.threshold,
    approvalsRequired: policy.approvalsRequired || approverConfig.approvalsRequired,
    managerList: policy.managerList || approverConfig.managers,
    adminApprovers: policy.adminApprovers || approverConfig.adminApprovers,
    restriction: 'No single admin can approve or change approver assignments alone.'
  };
}

const expenses = [
  makeExpense({ employeeId: 'alice', amount: 850, description: 'Client travel - 2 nights' }),
  makeExpense({ employeeId: 'bob', amount: 1500, description: 'Laptop replacement' }),
  makeExpense({ employeeId: 'charlie', amount: 2200, description: 'Conference and booth materials' }),
  makeExpense({ employeeId: 'alice', amount: 220, description: 'Team lunch' })
];

function makeExpense({ employeeId, amount, description }) {
  const id = Date.now() + Math.floor(Math.random() * 1000);
  return {
    id,
    employeeId,
    amount: Number(amount),
    description,
    createdAt: new Date().toISOString(),
    status: 'Pending',
    approvals: [],
    approverHistory: []
  };
}

function distinctApprovals(list) {
  return [...new Set(list)];
}

function refreshExpenseStatus(expense) {
  const uniqueApprovalIds = distinctApprovals(expense.approvals);
  expense.approvals = uniqueApprovalIds;

  if (expense.amount > approverConfig.threshold) {
    expense.status = uniqueApprovalIds.length >= approverConfig.approvalsRequired ? 'Approved' : 'Pending';
  } else {
    expense.status = 'Approved';
  }
}

function ensureManager(userId) {
  return approverConfig.managers.includes(userId);
}

function ensureAdmin(userId) {
  return approverConfig.adminApprovers.includes(userId);
}

app.get('/api/session', (req, res) => {
  const user = getSessionUser(req);
  res.json({
    authMode: AUTH_MODE,
    currentUser: user,
    users: Object.values(syntheticUsers),
    policy: ensurePolicyShape({
      threshold: approverConfig.threshold,
      approvalsRequired: approverConfig.approvalsRequired,
      managerList: approverConfig.managers,
      adminApprovers: approverConfig.adminApprovers
    })
  });
});

app.get('/auth/login', (req, res) => {
  if (AUTH_MODE === 'oidc') {
    return res.redirect('/auth/tide');
  }

  res.redirect('/api/session');
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.post('/api/login', (req, res) => {
  const { userId } = req.body;

  if (AUTH_MODE === 'oidc') {
    return res.status(400).json({ error: 'OIDC mode uses the provider login flow.' });
  }

  const user = syntheticUsers[userId];
  if (!user) {
    return res.status(400).json({ error: 'Unknown user' });
  }

  const normalized = resolveUserPayload({ ...user, roles: user.roles, source: 'synthetic' });
  req.session.user = normalized;

  return res.json({
    currentUser: normalized,
    policy: ensurePolicyShape({
      threshold: approverConfig.threshold,
      approvalsRequired: approverConfig.approvalsRequired,
      managerList: approverConfig.managers,
      adminApprovers: approverConfig.adminApprovers
    })
  });
});

app.get('/api/expenses', (req, res) => {
  for (const expense of expenses) {
    refreshExpenseStatus(expense);
  }
  res.json({ expenses });
});

app.post('/api/expenses', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser || !currentUser.id) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const { amount, description } = req.body;
  const employeeId = req.body.employeeId || currentUser.id;

  if (!syntheticUsers[employeeId] && AUTH_MODE === 'mock') {
    return res.status(400).json({ error: 'Employee not found' });
  }

  if (!amount || Number(amount) <= 0) {
    return res.status(400).json({ error: 'Amount must be greater than zero' });
  }

  const newExpense = makeExpense({
    employeeId,
    amount,
    description: description || 'General expense'
  });

  expenses.unshift(newExpense);
  refreshExpenseStatus(newExpense);

  return res.status(201).json({ expense: newExpense });
});

app.post('/api/expenses/:id/approve', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in to approve.' });
  }

  const expense = expenses.find((item) => item.id === Number(req.params.id));
  if (!expense) {
    return res.status(404).json({ error: 'Expense not found' });
  }

  if (!canApprove(currentUser)) {
    return res.status(403).json({ error: 'Only managers can approve expenses.' });
  }

  const userId = currentUser.id;
  if (expense.approvals.includes(userId)) {
    return res.status(409).json({ error: 'This manager has already approved this expense.' });
  }

  if (!ensureManager(userId)) {
    return res.status(403).json({ error: 'This user is not in the active manager list.' });
  }

  expense.approvals.push(userId);
  expense.approverHistory.push({ userId, approvedAt: new Date().toISOString() });
  refreshExpenseStatus(expense);

  return res.json({ expense });
});

app.post('/api/admin/change-approvers', (req, res) => {
  const currentUser = getSessionUser(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'Please sign in as an admin.' });
  }

  if (!canAdmin(currentUser)) {
    return res.status(403).json({ error: 'Only admin users may change approver assignments.' });
  }

  const { confirmers, newManagers } = req.body;
  const validConfirmers = Array.isArray(confirmers) ? [...new Set(confirmers)] : [];
  if (validConfirmers.length < approverConfig.adminPolicyApprovalsRequired) {
    return res.status(400).json({
      error: `A change in approvers requires ${approverConfig.adminPolicyApprovalsRequired} different admins.`
    });
  }

  if (!validConfirmers.every((id) => ensureAdmin(id))) {
    return res.status(400).json({ error: 'All policy confirmers must be approved admins.' });
  }

  const nextManagers = [...new Set((newManagers || []).filter(Boolean))];
  if (nextManagers.length < 2) {
    return res.status(400).json({ error: 'At least two managers are required.' });
  }

  approverConfig.managers = nextManagers;

  return res.json({
    success: true,
    message: 'Approver list updated by admin quorum.',
    managers: approverConfig.managers
  });
});

async function configureOidc() {
  if (AUTH_MODE !== 'oidc') return;

  const issuerUrl = process.env.TIDE_ISSUER;
  const clientId = process.env.TIDE_CLIENT_ID;
  const clientSecret = process.env.TIDE_CLIENT_SECRET;
  const redirectUri = process.env.TIDE_REDIRECT_URI || 'http://localhost:3000/auth/callback';

  if (!issuerUrl || !clientId || !clientSecret) {
    console.warn('OIDC mode is enabled without TIDE_ISSUER, TIDE_CLIENT_ID, or TIDE_CLIENT_SECRET. Falling back to mock auth.');
    return;
  }

  const issuer = await Issuer.discover(issuerUrl);
  const client = new issuer.Client({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [redirectUri],
    response_types: ['code']
  });

  app.get('/auth/tide', (req, res) => {
    const params = {
      scope: 'openid profile email roles',
      redirect_uri: redirectUri,
      state: 'expense-demo'
    };
    const redirectUrl = client.authorizationUrl(params);
    res.redirect(redirectUrl);
  });

  app.get('/auth/callback', async (req, res) => {
    try {
      const params = client.callbackParams(req);
      const tokenSet = await client.callback(redirectUri, params, { state: params.state });
      const idTokenClaims = tokenSet.claims();
      const principal = resolveUserPayload({
        id: idTokenClaims.sub,
        name: idTokenClaims.name || idTokenClaims.preferred_username || idTokenClaims.email || idTokenClaims.sub,
        email: idTokenClaims.email || null,
        roles: idTokenClaims.roles || idTokenClaims.realm_access?.roles || idTokenClaims.resource_access?.account?.roles || [],
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
    await configureOidc();
    app.listen(PORT, () => {
      console.log(`Expense approval app listening on http://localhost:${PORT}`);
      console.log(`Auth mode: ${AUTH_MODE}`);
    });
  } catch (error) {
    console.error('Startup failed:', error);
    process.exit(1);
  }
})();

