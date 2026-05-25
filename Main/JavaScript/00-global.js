/* ═══════════════════════════════════════════════════
   00-globals.js
   Shared state, constants, utility functions.
   Must be loaded FIRST before all other scripts.
   ═══════════════════════════════════════════════════ */

const API_BASE = 'http://localhost:5000';

/* ── Session State ── */
let state = {
  connected: false,
  connecting: false,
  justConnectedUntil: 0,
  mode: 'remote',
  protocol: 'ldap',
  domain: null,
  user: null,
  dc: null,
  ip: null,
  sessionStart: null,
  connectMode: 'fast',
  deepEnumRunning: false,
};

/* ── Timer IDs ── */
let sessionTimerId  = null;
let apiPingTimerId  = null;

/* ── AD Object Data ── */
let usersData     = [];
let usersMeta     = {};
let computersData = [];
let ousData       = [];
let gposData      = [];
let groupsData    = [];
let trustsData    = [];
let aclData       = [];

/* ── Filtered lists (render-time) ── */
let filteredOUs    = [];
let filteredGPOs   = [];
let filteredGroups = [];
let filteredTrusts = [];
let filteredACLs   = [];

/* ── Cache flags ── */
let enumCacheLoaded = {
  users:     false,
  computers: false,
  ous:       false,
  gpos:      false,
  groups:    false,
  trusts:    false,
  acl:       false,
};

/* ── Saved users ── */
let savedUsersCache = [];

/* ── Security status ── */
let securityStatusMeta = {
  kerberos: { value: null, source: 'Unknown', protocol: '—' },
  ntlm:     { value: null, source: 'Unknown', protocol: '—' },
  smb:      { value: null, source: 'Unknown', protocol: '—' },
};
let securityCheckerLastResults = { kerberos: null, ntlm: null, smb: null };
let securityCheckerSessionId   = 0;

/* ── Groups ── */
let groupMembersLoading       = new Set();
let nestedGroupMembersLoading = new Map();
let nestedGroupMembersCache   = new Map();

/* ═══════════════════════════════════════════════════
   UTILITY FUNCTIONS
   ═══════════════════════════════════════════════════ */

function now() {
  return new Date().toLocaleTimeString('az', { hour12: false });
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtDate(raw) {
  if (!raw) return '—';
  try {
    const d = new Date(raw);
    if (isNaN(d)) return raw;
    return d.toISOString().slice(0, 16).replace('T', ' ');
  } catch { return raw; }
}

const DESCRIPTION_SENSITIVE_TERMS = [
  'password', 'passwd', 'pass', 'pwd', 'p@ssword', 'p@ss', 'passw0rd',
  'hash', 'api', 'token', 'auth', 'bearer', 'jwt',
  'private', 'public', 'secret', 'encryption', 'aes', 'rsa', 'ssh', 'pgp',
  'gpg', 'master', 'session', 'symmetric', 'asymmetric', 'crypto',
  'credential', 'credentials', 'cred', 'username', 'login', 'oauth',
  'admin', 'db', 'connection', 'dsn', 'saml', 'sso', 'mfa', 'otp', '2fa',
  'client', 'app', 'aws', 'azure', 'gcp', 'vault', 'env', 'dotenv', '.env',
  'config', 'personal', 'deploy', 'webhook', 'stripe', 'sendgrid',
  'firebase', 'database', 'mongo'
];

function _escapeRegExp(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function _descriptionTermRegex(term) {
  const safe = _escapeRegExp(term);
  return new RegExp(`(^|[^A-Za-z0-9])(${safe})(?=$|[^A-Za-z0-9])`, 'i');
}

function getSensitiveDescriptionMatches(description) {
  const src = String(description || '');
  if (!src.trim()) return [];
  const found = [];
  DESCRIPTION_SENSITIVE_TERMS.forEach(term => {
    if (_descriptionTermRegex(term).test(src)) found.push(term);
  });
  return found;
}

function highlightSensitiveDescriptionTerms(description) {
  const escaped = escapeHtml(description);
  const union = DESCRIPTION_SENSITIVE_TERMS
    .slice()
    .sort((a, b) => b.length - a.length)
    .map(_escapeRegExp)
    .join('|');
  if (!union) return escaped;
  const rx = new RegExp(`(^|[^A-Za-z0-9])(${union})(?=$|[^A-Za-z0-9])`, 'gi');
  return escaped.replace(rx, '$1<span class="desc-keyword-risk">$2</span>');
}

function detailSection(title, rows) {
  const rowsHtml = rows.map(([lbl, val, cls]) => `
    <div class="detail-row">
      <span class="d-label">${lbl}</span>
      <span class="d-val ${cls || ''}">${val}</span>
    </div>`).join('');
  return `<div class="detail-section">
    <div class="detail-section-title">${title}</div>
    ${rowsHtml}
  </div>`;
}

function showToast(msg, type = 'info') {
  const ct = document.getElementById('toasts');
  const t  = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  t.innerHTML = `<span style="color:${
    type === 'success' ? 'var(--green)' : type === 'error' ? 'var(--red)' : 'var(--accent)'
  }">${icons[type] || 'ℹ'}</span> ${msg}`;
  ct.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function addLog(msg, type = 'info') {
  const term = document.getElementById('log-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className = `log-line log-${type}`;
  line.innerHTML = `<span class="log-time">[${now()}]</span> <span class="log-msg">${msg}</span>`;
  term.appendChild(line);
  while (term.children.length > 400) term.removeChild(term.children[0]);
  term.scrollTop = term.scrollHeight;
}

function setObjectCountStat(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value ?? 0;
  el.className = 'stat-mini-val active';
}

async function copyTextValue(text, label) {
  if (!text) { showToast(`${label} is empty`, 'info'); return; }
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${label} copied`, 'success');
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showToast(`${label} copied`, 'success'); }
    catch (_e) { showToast('Clipboard access denied', 'error'); }
    finally { ta.remove(); }
  }
}

function buildEnumerationPayload() {
  if (state.mode === 'local' || state.protocol === 'local') {
    return { mode: 'local' };
  }
  const dcInput    = (document.getElementById('f-dc')?.value || '').trim();
  const ldapTarget = dcInput || state.dc || state.domain;
  const passInput  = (document.getElementById('f-pass')?.value || '').trim();
  const hashInput  = (document.getElementById('f-hash')?.value || '').trim();
  const savedPass  = (state._pass || '').trim();
  const savedHash  = (state._hash || '').trim();
  return {
    mode:      'remote',
    protocol:  state.protocol,
    ip:        document.getElementById('f-ip').value.trim() || state.dc,
    dc:        ldapTarget,
    ldap_host: ldapTarget,
    domain:    document.getElementById('f-domain').value.trim() || state.domain,
    username:  document.getElementById('f-user').value.trim()   || state.user,
    password:  passInput  || (!hashInput ? savedPass : ''),
    hash:      hashInput  || (!passInput ? savedHash : ''),
  };
}

// Prevent accidental form submission
document.addEventListener('submit', (e) => e.preventDefault(), true);