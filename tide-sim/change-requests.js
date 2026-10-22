// Sim mode only: a stand-in for TideCloak's change requests (IGA), so `npm test` can exercise
// 2-of-3 admin governance offline. With TIDE_MODE=tidecloak none of this runs: admins file and
// approve real TideCloak change requests from their own browsers, each signing in their Tide enclave.
module.exports = function mountChangeRequests(app, { directory, log }) {
  const { users, policyState: policy } = directory;
  const changeRequests = [];
  const name = (id) => (users[id] ? users[id].name : id);
  const isAdmin = (id) => !!users[id] && users[id].roles.includes('admin');

  function caller(req) {
    return directory.caller(req);
  }

  function describeChange(c) {
    if (c.type === 'grant-role') return `Grant ${c.role} role to ${name(c.target)}`;
    if (c.type === 'revoke-role') return `Revoke ${c.role} role from ${name(c.target)}`;
    if (c.type === 'set-policy') {
      const label = { engineerApprovals: 'engineer approvals required', adminQuorum: 'admin quorum' }[c.key] || c.key;
      return `Set ${label} to ${c.value}`;
    }
    return 'Unknown change';
  }

  function validateChange(c) {
    if (c.type === 'grant-role' || c.type === 'revoke-role') {
      if (!users[c.target]) return 'Unknown user';
      if (!['operator', 'engineer', 'admin'].includes(c.role)) return 'Unknown role';
      return null;
    }
    if (c.type === 'set-policy') {
      if (!['engineerApprovals', 'adminQuorum'].includes(c.key)) return 'Unknown policy key';
      const v = Number(c.value);
      if (!Number.isInteger(v) || v < 0 || v > 3) return 'Policy value must be an integer 0–3';
      return null;
    }
    return 'Unknown change type';
  }

  function applyChange(c) {
    if (c.type === 'grant-role' && !users[c.target].roles.includes(c.role)) users[c.target].roles.push(c.role);
    if (c.type === 'revoke-role') users[c.target].roles = users[c.target].roles.filter((r) => r !== c.role);
    if (c.type === 'set-policy') {
      policy[c.key] = Number(c.value);
      policy.version += 1;
    }
  }

  function maybeApply(cr) {
    if (cr.status === 'pending' && cr.approvals.length >= cr.quorum) {
      applyChange(cr);
      cr.status = 'applied';
      log('ok', `Change request "${cr.description}" applied with approvals from ${cr.approvals.map(name).join(' + ')}`);
    }
  }

  app.get('/admin/change-requests', (req, res) => res.json({ changeRequests, policy }));

  app.post('/admin/change-requests', async (req, res) => {
    const who = await caller(req);
    if (!who || !isAdmin(who)) return res.status(403).json({ error: 'Admin session required' });
    const { type, target, role, key, value } = req.body || {};
    const change = { type, target, role, key, value };
    const invalid = validateChange(change);
    if (invalid) return res.status(400).json({ error: invalid });
    const cr = {
      id: `cr-${changeRequests.length + 1}`,
      ...change,
      description: describeChange(change),
      createdBy: who,
      createdAt: new Date().toISOString(),
      approvals: [who],
      rejectedBy: null,
      status: 'pending',
      quorum: policy.adminQuorum
    };
    changeRequests.unshift(cr);
    log('warn', `${name(who)} opened change request "${cr.description}". Needs ${cr.quorum} admins; has 1.`);
    maybeApply(cr);
    res.status(cr.status === 'applied' ? 200 : 202).json(cr);
  });

  app.post('/admin/change-requests/:id/approve', async (req, res) => {
    const who = await caller(req);
    if (!who || !isAdmin(who)) return res.status(403).json({ error: 'Admin session required' });
    const cr = changeRequests.find((c) => c.id === req.params.id);
    if (!cr) return res.status(404).json({ error: 'Not found' });
    if (cr.status !== 'pending') return res.status(409).json({ error: `Change request is ${cr.status}` });
    if (cr.approvals.includes(who)) {
      log('blocked', `${name(who)} tried to approve their own change request "${cr.description}" a second time`);
      return res.status(409).json({ error: `${name(who)} has already approved. A different admin must approve.` });
    }
    cr.approvals.push(who);
    maybeApply(cr);
    res.json(cr);
  });

  app.post('/admin/change-requests/:id/reject', async (req, res) => {
    const who = await caller(req);
    if (!who || !isAdmin(who)) return res.status(403).json({ error: 'Admin session required' });
    const cr = changeRequests.find((c) => c.id === req.params.id);
    if (!cr) return res.status(404).json({ error: 'Not found' });
    if (cr.status !== 'pending') return res.status(409).json({ error: `Change request is ${cr.status}` });
    cr.status = 'rejected';
    cr.rejectedBy = who;
    log('blocked', `${name(who)} rejected change request "${cr.description}"`);
    res.json(cr);
  });
};
