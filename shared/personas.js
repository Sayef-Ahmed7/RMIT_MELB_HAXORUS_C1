// The synthetic plant staff. tide-sim uses these as its user store; with real TideCloak they are
// the realm users the bootstrap creates, and roles come from TideCloak, not from this file.
const PERSONAS = [
  { username: 'sam', name: 'Sam', title: 'Operator (on shift)', roles: ['operator'] },
  { username: 'priya', name: 'Priya', title: 'Process engineer', roles: ['engineer'] },
  { username: 'alex', name: 'Alex', title: 'Process engineer', roles: ['engineer'] },
  { username: 'morgan', name: 'Morgan', title: 'IT administrator', roles: ['admin'] },
  { username: 'jordan', name: 'Jordan', title: 'IT administrator', roles: ['admin'] },
  { username: 'casey', name: 'Casey', title: 'IT administrator', roles: ['admin'] }
];

module.exports = { PERSONAS };
