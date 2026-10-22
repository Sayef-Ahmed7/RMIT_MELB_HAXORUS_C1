const state = {
  currentUser: null,
  policy: null,
  expenses: [],
  authMode: 'mock'
};

const userListEl = document.getElementById('user-list');
const loginStatusEl = document.getElementById('login-status');
const expenseTableBodyEl = document.getElementById('expense-table-body');
const adminStatusEl = document.getElementById('admin-status');

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
    button.textContent = `${user.name} (${user.roles?.join(', ') || user.role})`;
    button.addEventListener('click', async () => {
      try {
        const data = await fetchJson('/api/login', {
          method: 'POST',
          body: JSON.stringify({ userId: user.id })
        });
        state.currentUser = data.currentUser;
        state.policy = data.policy;
        renderAuth();
        await loadExpenses();
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

function renderExpenses() {
  expenseTableBodyEl.innerHTML = '';

  state.expenses.forEach((expense) => {
    const row = document.createElement('tr');
    const employee = expense.employeeId || 'N/A';
    const canApprove = state.currentUser && hasRole(state.currentUser, 'manager') && !expense.approvals.includes(state.currentUser.id);

    row.innerHTML = `
      <td>${expense.id}</td>
      <td>${employee}</td>
      <td>$${Number(expense.amount).toFixed(2)}</td>
      <td>${expense.description}</td>
      <td>${expense.status}</td>
      <td>${expense.approvals.length ? expense.approvals.join(', ') : 'None yet'}</td>
      <td>${canApprove ? `<button data-expense-id="${expense.id}">Approve</button>` : '<span>—</span>'}</td>
    `;

    expenseTableBodyEl.appendChild(row);
  });

  document.querySelectorAll('[data-expense-id]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!state.currentUser) {
        loginStatusEl.textContent = 'Please sign in as a manager first.';
        return;
      }

      try {
        await fetchJson(`/api/expenses/${button.dataset.expenseId}/approve`, {
          method: 'POST',
          body: JSON.stringify({ userId: state.currentUser.id })
        });
        await loadExpenses();
        loginStatusEl.textContent = `Approval recorded for ${state.currentUser.name}.`;
      } catch (error) {
        loginStatusEl.textContent = `Approval failed: ${error.message}`;
      }
    });
  });
}

async function loadUsers() {
  const data = await fetchJson('/api/session');
  state.authMode = data.authMode || 'mock';
  state.policy = data.policy;
  state.currentUser = data.currentUser;
  renderUsers(data.users || []);
  renderAuth();
  return data;
}

async function loadExpenses() {
  const data = await fetchJson('/api/expenses');
  state.expenses = data.expenses;
  renderExpenses();
}

document.getElementById('expense-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.currentUser || !hasRole(state.currentUser, 'employee')) {
    loginStatusEl.textContent = 'Only employees can submit expenses.';
    return;
  }

  const amount = Number(document.getElementById('amount').value);
  const description = document.getElementById('description').value;

  try {
    await fetchJson('/api/expenses', {
      method: 'POST',
      body: JSON.stringify({ employeeId: state.currentUser.id, amount, description })
    });
    document.getElementById('expense-form').reset();
    document.getElementById('amount').value = '1200';
    await loadExpenses();
    loginStatusEl.textContent = 'Expense submitted successfully.';
  } catch (error) {
    loginStatusEl.textContent = `Submission failed: ${error.message}`;
  }
});

document.getElementById('change-approvers-btn').addEventListener('click', async () => {
  if (!state.currentUser || !hasRole(state.currentUser, 'admin')) {
    adminStatusEl.textContent = 'Only admins can update the approval policy.';
    return;
  }

  const list = document.getElementById('new-manager-list').value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  const confirmers = ['nora', 'imran'];

  try {
    const data = await fetchJson('/api/admin/change-approvers', {
      method: 'POST',
      body: JSON.stringify({
        initiatorId: state.currentUser.id,
        confirmers,
        newManagers: list
      })
    });

    state.policy = data;
    adminStatusEl.textContent = data.message;
    await loadUsers();
    await loadExpenses();
  } catch (error) {
    adminStatusEl.textContent = `Policy change failed: ${error.message}`;
  }
});

(async function init() {
  try {
    await loadUsers();
    await loadExpenses();
  } catch (error) {
    loginStatusEl.textContent = `Error loading app: ${error.message}`;
  }
})();
