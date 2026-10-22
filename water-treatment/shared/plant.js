// Synthetic plant definition and the deterministic "AI" anomaly scorer.
// The same scorer runs independently in the app (for display), in the Tide policy and in the PLC.
// It only looks at the requested value and the request context, never at backend-supplied state.

const PLANT_ID = 'demo-valley-wtp';
const PLANT_NAME = 'Demo Valley Water Treatment Plant';

const PARAMETERS = {
  naoh_ppm: {
    label: 'Sodium hydroxide (NaOH)',
    unit: 'ppm',
    kind: 'number',
    normal: 100,
    safe: [0, 200],
    routineBand: 30,
    hazard: 'At this concentration the water would be caustic: skin burns and unsafe to drink.'
  },
  chlorine_mgL: {
    label: 'Chlorine',
    unit: 'mg/L',
    kind: 'number',
    normal: 1.0,
    safe: [0.2, 4],
    routineBand: 0.5,
    hazard: 'Chlorine outside 0.2–4 mg/L either fails to disinfect or makes water unsafe.'
  },
  ph: {
    label: 'pH',
    unit: '',
    kind: 'number',
    normal: 7.2,
    safe: [6.5, 8.5],
    routineBand: 0.4,
    hazard: 'pH outside 6.5–8.5 corrodes pipes and leaches metals into drinking water.'
  },
  filter: {
    label: 'Main filter',
    unit: '',
    kind: 'enum',
    options: ['online', 'offline'],
    normal: 'online',
    danger: 'offline',
    hazard: 'Disabling the filter sends unfiltered water to town.'
  },
  bypass_valve: {
    label: 'Bypass valve',
    unit: '',
    kind: 'enum',
    options: ['closed', 'open'],
    normal: 'closed',
    danger: 'open',
    hazard: 'Opening the bypass skips treatment entirely.'
  }
};

const LEVELS = ['low', 'medium', 'high'];

function raise(level) {
  return LEVELS[Math.min(LEVELS.indexOf(level) + 1, LEVELS.length - 1)];
}

function fmt(v) {
  return Number.isInteger(v) ? v.toLocaleString('en-AU') : String(v);
}

// Returns { level, reasons[], explanation, ratio } or { error }.
function scoreRequest({ parameter, value, context = {} }) {
  const p = PARAMETERS[parameter];
  if (!p) return { error: `Unknown parameter "${parameter}"` };

  const reasons = [];
  let level = 'low';
  let ratio = null;

  if (p.kind === 'number') {
    const v = Number(value);
    if (!Number.isFinite(v)) return { error: 'Value must be a number' };
    ratio = p.normal ? v / p.normal : null;
    const [min, max] = p.safe;
    if (v < min || v > max) {
      level = 'high';
      reasons.push(`Outside the safe range ${min}–${max} ${p.unit}`.trim());
    }
    if (ratio !== null && ratio > 3) {
      level = 'high';
      reasons.push(`${fmt(Math.round(ratio * 10) / 10)}× the normal operating value (${p.normal} ${p.unit})`.replace(' )', ')'));
    }
    if (level === 'low' && Math.abs(v - p.normal) > p.routineBand) {
      level = 'medium';
      reasons.push(`Larger than a routine adjustment (±${p.routineBand} ${p.unit} from normal)`.replace(' )', ')'));
    }
  } else {
    if (!p.options.includes(value)) return { error: `Value must be one of ${p.options.join(', ')}` };
    if (value === p.danger) {
      level = 'high';
      reasons.push(`Sets ${p.label.toLowerCase()} to "${value}"`);
    }
  }

  if (context.device && context.device !== 'control-room-console') {
    const before = level;
    level = raise(level);
    reasons.push(`Unrecognised device or location (${context.device})${before !== level ? ': risk raised one level' : ''}`);
  }

  if (!reasons.length) reasons.push('Within the routine operating band');
  return { level, reasons, ratio, explanation: templateExplanation(p, value, level, ratio) };
}

function templateExplanation(p, value, level, ratio) {
  if (level === 'low') return `Routine adjustment of ${p.label.toLowerCase()} within the normal operating band.`;
  if (p.kind === 'number' && ratio && ratio > 3) {
    return `This change is ${fmt(Math.round(ratio))}× the normal ${p.label} level. ${p.hazard}`;
  }
  if (level === 'high') return p.hazard;
  return `Unusual ${p.label.toLowerCase()} change; a second engineer should confirm it is intended.`;
}

// Policy: anything that is not routine needs an independent engineer.
function requiresEngineer(level) {
  return level === 'medium' || level === 'high';
}

function initialSetpoints() {
  return Object.fromEntries(Object.entries(PARAMETERS).map(([k, p]) => [k, p.normal]));
}

module.exports = { PLANT_ID, PLANT_NAME, PARAMETERS, scoreRequest, requiresEngineer, initialSetpoints };
