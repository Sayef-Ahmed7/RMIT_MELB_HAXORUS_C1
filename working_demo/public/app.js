const state = {
  currentUser: null,
  policy: null,
  authMode: 'mock',
  papers: [],
  notifications: [],
  auditLog: [],
  custodians: []
};

const userListEl = document.getElementById('user-list');
const loginStatusEl = document.getElementById('login-status');
const paperListEl = document.getElementById('paper-list');
const notificationsFeedEl = document.getElementById('notifications-feed');
const auditLogEl = document.getElementById('audit-log');
const attackOutputEl = document.getElementById('attack-output');

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }
  return data;
}

function hasRole(user, roleName) {
  if (!user) return false;
  const roles = Array.isArray(user.roles) ? user.roles : [user.role];
  return roles.includes(roleName);
}

function renderUsers(users) {
  userListEl.innerHTML = '';

  if (state.authMode === 'oidc') {
    const loginButton = document.createElement('button');
    loginButton.className = 'role-button';
    loginButton.textContent = 'Sign in with TideCloak';
    loginButton.addEventListener('click', () => {
      window.location.href = '/auth/login';
    });
    userListEl.appendChild(loginButton);
    return;
  }

  users.forEach((user) => {
    const button = document.createElement('button');
    button.className = 'role-button';
    button.textContent = `${user.name} (${user.roles.join(', ')})`;
    button.addEventListener('click', async () => {
      try {
        const data = await fetchJson('/api/login', {
          method: 'POST',
          body: JSON.stringify({ userId: user.id })
        });
        state.currentUser = data.currentUser;
        state.policy = data.policy;
        await loadNotifications();
        await loadPapers();
        renderAuth();
      } catch (error) {
        loginStatusEl.textContent = `Login failed: ${error.message}`;
      }
    });
    userListEl.appendChild(button);
  });
}

function renderAuth() {
  if (!state.currentUser) {
    loginStatusEl.textContent = 'No user signed in.';
    return;
  }

  const roleText = Array.isArray(state.currentUser.roles) ? state.currentUser.roles.join(', ') : state.currentUser.role || 'user';
  loginStatusEl.textContent = `Signed in as ${state.currentUser.name} (${roleText}).`;
}

function renderNotifications() {
  notificationsFeedEl.innerHTML = '';

  if (!state.notifications.length) {
    notificationsFeedEl.innerHTML = '<p class="empty-state">No active notifications.</p>';
    return;
  }

  const visible = state.notifications.filter((item) => {
    if (!state.currentUser) return false;
    return item.recipientId === state.currentUser.id || item.recipientId === 'exam-admin';
  });

  if (!visible.length) {
    notificationsFeedEl.innerHTML = '<p class="empty-state">No notifications for this actor.</p>';
    return;
  }

  visible.forEach((notification) => {
    const item = document.createElement('div');
    item.className = 'notification-item';

    const isCustodianAction = state.currentUser && state.custodians.includes(state.currentUser.id);
    const canAct = isCustodianAction && notification.recipientId === state.currentUser.id;

    item.innerHTML = `
      <strong>${notification.paperTitle}</strong>
      <div>Requester: ${notification.requesterName}</div>
      <div>Created: ${new Date(notification.createdAt).toLocaleString()}</div>
      ${canAct ? '<div class="notification-actions"><button data-decision="approve" data-notification-id="' + notification.id + '">Approve</button><button data-decision="reject" data-notification-id="' + notification.id + '" class="secondary-button">Reject</button></div>' : ''}
    `;

    notificationsFeedEl.appendChild(item);
  });

  document.querySelectorAll('[data-notification-id]').forEach((button) => {
    button.addEventListener('click', async () => {
      const decision = button.dataset.decision;
      const notificationId = button.dataset.notificationId;
      try {
        await fetchJson(`/api/notifications/${notificationId}/decision`, {
          method: 'POST',
          body: JSON.stringify({ decision })
        });
        await loadNotifications();
        await loadPapers();
        loginStatusEl.textContent = `Notification ${decision} recorded for ${state.currentUser?.name || 'user'}.`;
      } catch (error) {
        loginStatusEl.textContent = `Decision failed: ${error.message}`;
      }
    });
  });
}

function renderAuditLog() {
  auditLogEl.innerHTML = '';
  if (!state.auditLog.length) {
    auditLogEl.innerHTML = '<p class="empty-state">No audit events yet.</p>';
    return;
  }

  state.auditLog.slice(0, 12).forEach((entry) => {
    const item = document.createElement('div');
    item.className = 'audit-item';
    item.innerHTML = `<strong>${entry.event}</strong> — ${entry.actorId} at ${new Date(entry.at).toLocaleString()}`;
    auditLogEl.appendChild(item);
  });
}

function renderPapers() {
  paperListEl.innerHTML = '';

  state.papers.forEach((paper) => {
    const card = document.createElement('div');
    card.className = `paper-card ${paper.status === 'Opened' ? 'opened' : 'sealed'}`;

    const contentLink = paper.status === 'Opened'
      ? `<div class="paper-content"><strong>Decrypted content:</strong><br>${paper.content || '—'}</div>`
      : '<div class="sealed-tag">Sealed</div>';

    const requestButton = !state.currentUser
      ? '<span>Sign in to request access</span>'
      : paper.status === 'Opened'
        ? '<button class="secondary-button" data-view-paper="' + paper.id + '">View opened paper</button>'
        : '<button data-open-paper="' + paper.id + '">Request open</button>';

    const approvalButton = state.currentUser && state.custodians.includes(state.currentUser.id) && paper.status !== 'Opened'
      ? `<button data-paper-approve="${paper.id}">Approve</button>`
      : '';

    card.innerHTML = `
      <div class="paper-header">
        <strong>${paper.title}</strong>
        <span class="paper-status">${paper.status}</span>
      </div>
      <div>Subject: ${paper.subject}</div>
      <div>Exam date: ${paper.examDate}</div>
      <div>Approvals: ${(paper.approvals || []).join(', ') || 'None yet'}</div>
      ${contentLink}
      <div class="paper-actions">
        ${requestButton}
        ${approvalButton}
      </div>
    `;

    paperListEl.appendChild(card);
  });

  document.querySelectorAll('[data-open-paper]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        await fetchJson(`/api/papers/${button.dataset.openPaper}/open-request`, {
          method: 'POST',
          body: JSON.stringify({ requesterId: state.currentUser.id })
        });
        await loadNotifications();
        await loadPapers();
        loginStatusEl.textContent = 'Open request created. Custodians were notified.';
      } catch (error) {
        loginStatusEl.textContent = `Open request failed: ${error.message}`;
      }
    });
  });

  document.querySelectorAll('[data-paper-approve]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        await fetchJson(`/api/papers/${button.dataset.paperApprove}/approve`, {
          method: 'POST',
          body: JSON.stringify({ userId: state.currentUser.id })
        });
        await loadNotifications();
        await loadPapers();
        loginStatusEl.textContent = `${state.currentUser.name} approved the paper opening.`;
      } catch (error) {
        loginStatusEl.textContent = `Approval failed: ${error.message}`;
      }
    });
  });

  document.querySelectorAll('[data-view-paper]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        const data = await fetchJson(`/api/papers/${button.dataset.viewPaper}`);
        const paper = data.paper;
        const message = paper.content || 'This paper is still sealed.';
        loginStatusEl.textContent = message;
      } catch (error) {
        loginStatusEl.textContent = `Paper view failed: ${error.message}`;
      }
    });
  });
}

async function loadSession() {
  const data = await fetchJson('/api/session');
  state.authMode = data.authMode || 'mock';
  state.currentUser = data.currentUser;
  state.policy = data.policy;
  state.custodians = data.custodians || [];
  renderUsers(data.users || []);
  renderAuth();
  return data;
}

async function loadPapers() {
  const data = await fetchJson('/api/papers');
  state.papers = data.papers;
  renderPapers();
}

async function loadNotifications() {
  if (!state.currentUser) {
    state.notifications = [];
    renderNotifications();
    return;
  }

  const data = await fetchJson('/api/notifications');
  state.notifications = data.notifications || [];
  renderNotifications();
}

async function loadAuditLog() {
  const data = await fetchJson('/api/session');
  state.auditLog = data.auditLog || [];
  renderAuditLog();
}

async function refreshEverything() {
  await loadSession();
  await loadPapers();
  await loadNotifications();
  await loadAuditLog();
}

document.getElementById('paper-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.currentUser || (!hasRole(state.currentUser, 'paper-setter') && !hasRole(state.currentUser, 'exam-admin'))) {
    loginStatusEl.textContent = 'Only the paper setter or exam admin can upload papers.';
    return;
  }

  const body = {
    title: document.getElementById('paper-title').value,
    subject: document.getElementById('paper-subject').value,
    examDate: document.getElementById('paper-date').value,
    content: document.getElementById('paper-content').value
  };

  try {
    await fetchJson('/api/papers', {
      method: 'POST',
      body: JSON.stringify(body)
    });
    await loadPapers();
    loginStatusEl.textContent = 'Paper encrypted and stored. Only custodians can open it.';
  } catch (error) {
    loginStatusEl.textContent = `Upload failed: ${error.message}`;
  }
});

document.getElementById('reset-demo-btn').addEventListener('click', async () => {
  try {
    const data = await fetchJson('/api/reset-demo', { method: 'POST' });
    loginStatusEl.textContent = data.message;
    await refreshEverything();
  } catch (error) {
    loginStatusEl.textContent = `Reset failed: ${error.message}`;
  }
});

document.getElementById('admin-open-alone-btn').addEventListener('click', async () => {
  try {
    const data = await fetchJson('/api/login', {
      method: 'POST',
      body: JSON.stringify({ userId: 'exam-admin' })
    });
    state.currentUser = data.currentUser;
    const paper = state.papers[0];
    const response = await fetchJson(`/api/papers/${paper.id}/open-request`, {
      method: 'POST',
      body: JSON.stringify({ requesterId: 'exam-admin' })
    });
    attackOutputEl.textContent = `Admin request created: ${JSON.stringify({ status: response.request.status, paper: response.paper.title }, null, 2)}\nAll 3 custodians were notified, but no decryption is allowed without a 2-of-3 approval quorum.`;
    await loadNotifications();
    await loadPapers();
  } catch (error) {
    attackOutputEl.textContent = `Admin open request failed: ${error.message}`;
  }
});

document.getElementById('read-database-btn').addEventListener('click', async () => {
  try {
    const data = await fetchJson('/api/database');
    attackOutputEl.textContent = JSON.stringify(data, null, 2);
    const cText = JSON.stringify(data).toLowerCase();
    if (cText.includes('plaintext') || cText.includes('content')) {
      attackOutputEl.textContent += '\nWarning: plaintext content was found in the database output.';
    }
  } catch (error) {
    attackOutputEl.textContent = `Database read failed: ${error.message}`;
  }
});

document.getElementById('admin-custodian-btn').addEventListener('click', async () => {
  try {
    const data = await fetchJson('/api/login', {
      method: 'POST',
      body: JSON.stringify({ userId: 'exam-admin' })
    });
    state.currentUser = data.currentUser;
    const response = await fetchJson('/api/admin/custodians', {
      method: 'POST',
      body: JSON.stringify({
        initiatorId: 'exam-admin',
        confirmers: ['custodian-1'],
        newCustodians: ['exam-admin', 'custodian-2', 'custodian-3']
      })
    });
    attackOutputEl.textContent = JSON.stringify(response, null, 2);
  } catch (error) {
    attackOutputEl.textContent = `Admin custodian change blocked: ${error.message}`;
  }
});

document.getElementById('custodian-quorum-btn').addEventListener('click', async () => {
  try {
    const firstLogin = await fetchJson('/api/login', {
      method: 'POST',
      body: JSON.stringify({ userId: 'custodian-1' })
    });
    state.currentUser = firstLogin.currentUser;
    await fetchJson(`/api/papers/${state.papers[0].id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ userId: 'custodian-1' })
    });

    const secondLogin = await fetchJson('/api/login', {
      method: 'POST',
      body: JSON.stringify({ userId: 'custodian-2' })
    });
    state.currentUser = secondLogin.currentUser;
    const response = await fetchJson(`/api/papers/${state.papers[0].id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ userId: 'custodian-2' })
    });

    attackOutputEl.textContent = JSON.stringify(response, null, 2);
    await loadPapers();
    await loadNotifications();
  } catch (error) {
    attackOutputEl.textContent = `Custodian quorum flow failed: ${error.message}`;
  }
});

(async function init() {
  try {
    await refreshEverything();
  } catch (error) {
    loginStatusEl.textContent = `Error loading app: ${error.message}`;
  }
})();
