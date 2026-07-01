/* ═══════════════════════════════════════════════════
   00-globals.js
   Shared state, constants, utility functions.
   Must be loaded FIRST before all other scripts.
   ═══════════════════════════════════════════════════ */

/* Must match core/config.py DEFAULT_PORTS["connection"] (connection.py). */
const API_BASE = 'http://localhost:30100';

/* Base URL of the sqlite_reader.py (port 30104, see core/config.py
   DEFAULT_PORTS["sqlite_reader"]) REST API — the Users section
   (and gradually other sections) uses this to read domain_data.db directly,
   without loading large JSON/JSONL files into browser memory. */
const DB_BASE = 'http://localhost:30104';

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

  // Form inputs may be empty (when switching tabs), so we fall back to state
  const finalPass = passInput || (!hashInput && !savedHash ? savedPass : savedPass && !hashInput ? savedPass : '');
  const finalHash = hashInput || (!passInput && !savedPass ? savedHash : savedHash && !passInput ? savedHash : '');

  return {
    mode:      'remote',
    protocol:  state.protocol,
    ip:        document.getElementById('f-ip')?.value.trim()     || state.ip || state.dc,
    dc:        ldapTarget,
    ldap_host: ldapTarget,
    domain:    document.getElementById('f-domain')?.value.trim() || state.domain,
    username:  document.getElementById('f-user')?.value.trim()   || state.user,
    password:  finalPass,
    hash:      finalHash,
  };
}

// Prevent accidental form submission
document.addEventListener('submit', (e) => e.preventDefault(), true);

/* ═══════════════════════════════════════════════════
   DB-READER-FIRST LOADER
   The jsonl file is NOT read. Instead, we read domain_data.db over HTTP
   via db_reader's (sqlite_reader.py) own REST functions
   (/api/export/<table>, /api/list/<table>) — without requiring a
   "connect". All loadX() functions call this BEFORE the connect check;
   if found, it does not fall back to a live LDAP query.

   resetEnumCacheFlags() must be called after a successful connect so
   that each loadX() reads fresh data from the DB again.
   ═══════════════════════════════════════════════════ */

/**
 * Resets all enum cache flags after the connect completes, so that
 * loadUsers(), loadComputers(), etc. always read fresh data from
 * sqlite_reader (domain_data.db) on their next call.
 */
function resetEnumCacheFlags() {
  Object.keys(enumCacheLoaded).forEach(k => { enumCacheLoaded[k] = false; });
}

/* db_reader (sqlite_reader.py) runs on its own port as an independent
   service (see core/config.py DEFAULT_PORTS["sqlite_reader"]). */
const DB_READER_BASE = 'http://localhost:30104';

/* section -> table name in domain_data.db */
const DB_READER_TABLE = {
  users:     'users',
  computers: 'computers',
  ous:       'ous',
  gpos:      'gpos',
  groups:    'groups',
  trusts:    'trusts',
  acl:       'aces',
};

/* "Parent" tables (users/computers/groups/gpos/ous/trusts) are read via
   /api/export MERGED with their child fields (member_of, spn, etc.).
   "aces", however, is a standalone table, read with a simple /api/list. */
const DB_READER_PARENT_TABLES = new Set(['users', 'computers', 'groups', 'gpos', 'ous', 'trusts']);

/**
 * Attempts to read domain_data.db via the db_reader (sqlite_reader.py)
 * service's own REST functions. No jsonl file is read at all.
 * @returns {Promise<{records: Array, meta: object}|null>}
 *          null → db_reader is unreachable / table not found (the caller
 *          should continue with its normal flow — connect check or
 *          live loading).
 */
async function tryLoadSnapshotSection(section) {
  const table = DB_READER_TABLE[section];
  if (!table) return null;

  const isParent = DB_READER_PARENT_TABLES.has(table);
  const url = isParent
    ? `${DB_READER_BASE}/api/export/${table}`
    : `${DB_READER_BASE}/api/list/${table}?limit=500000`;

  try {
    const resp = await fetch(url, { method: 'GET' });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data) return null;
    // /api/export → {success, rows, ...}   /api/list → {table, rows, ...} (no success field)
    if (isParent && !data.success) return null;
    const records = Array.isArray(data.rows) ? data.rows : [];

    return { records, meta: { source: 'sqlite', table } };
  } catch (_err) {
    return null;
  }
}


let dbReadyPollTimerId = null;

function stopDbReadyPolling() {
  if (dbReadyPollTimerId) {
    clearInterval(dbReadyPollTimerId);
    dbReadyPollTimerId = null;
  }
}

async function isDbReaderAlive() {
  try {
    const resp = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!resp.ok) return false;
    const data = await resp.json();
    return !!data && data.status === 'ok';
  } catch (_err) {
    return false;
  }
}

function pollForDbReady(onReady, { intervalMs = 2000, timeoutMs = 5 * 60 * 1000 } = {}) {
  stopDbReadyPolling();
  const startedAt = Date.now();

  dbReadyPollTimerId = setInterval(async () => {
    if (Date.now() - startedAt > timeoutMs) {
      stopDbReadyPolling();
      state.connecting = false;
      showToast('Database preparation timed out', 'error');
      addLog('DB-reader (30104) did not come up within the expected time', 'error');
      return;
    }
    const alive = await isDbReaderAlive();
    if (alive) {
      stopDbReadyPolling();
      onReady();
    }
  }, intervalMs);
}

/**
 * Once the DB is ready, re-calls all tab functions. These loaders
 * (loadUsers, loadComputers, etc.) will already read and render
 * domain_data.db from port 30104 internally via tryLoadSnapshotSection() —
 * here we only reset the cache flags so they don't fall into the
 * "snapshot already loaded" state.
 *
 * NOTE: The following function names (loadUsers, loadComputers, ...)
 * must be defined in the other tab files (e.g. 01-users.js). If those
 * files name the functions differently, either fix this list to match
 * the real names, or register them at the end of each tab file with
 *   registerSectionLoader('users', loadUsers);
 * (see below) — there's no need to change the
 * DEFAULT_SECTION_LOADER_NAMES list.
 */
const DEFAULT_SECTION_LOADER_NAMES = [
  'loadUsers', 'loadComputers', 'loadOUs', 'loadGPOs',
  'loadGroups', 'loadTrusts', 'loadACLs',
];

// Tab files may manually register their own loader function here so that
// the DEFAULT_SECTION_LOADER_NAMES list doesn't need to change when there's
// a name mismatch: registerSectionLoader('users', myLoadFn);
const registeredSectionLoaders = new Map();
function registerSectionLoader(section, fn) {
  if (typeof fn === 'function') registeredSectionLoaders.set(section, fn);
}

function refreshAllSectionsAfterConnect() {
  resetEnumCacheFlags();

  const missing = [];
  const called  = [];

  registeredSectionLoaders.forEach((fn, section) => {
    try { fn(); called.push(section); }
    catch (err) { addLog(`${section} loader error: ${err.message}`, 'error'); }
  });

  DEFAULT_SECTION_LOADER_NAMES.forEach((fnName) => {
    const section = fnName.replace(/^load/, '').toLowerCase();
    if (registeredSectionLoaders.has(section)) return; // already called via registry
    const fn = window[fnName];
    if (typeof fn === 'function') {
      try { fn(); called.push(fnName); }
      catch (err) { addLog(`${fnName} error: ${err.message}`, 'error'); }
    } else {
      missing.push(fnName);
    }
  });

  if (called.length) {
    addLog(`Loaded from DB: ${called.join(', ')}`, 'success');
  }
  if (missing.length) {
    // This explains why requests aren't going to sqlite_reader.py:
    // these names were not found on window. Either fix the actual
    // loader function names in DEFAULT_SECTION_LOADER_NAMES, or
    // register them via registerSectionLoader().
    addLog(`Loader functions not found (DB query not sent): ${missing.join(', ')}`, 'error');
    showToast(`No loader function found for ${missing.length} section(s) — check the console`, 'error');
    console.warn('[refreshAllSectionsAfterConnect] Functions not found:', missing,
      '— register these with registerSectionLoader() or fix their names.');
  }
}

/**
 * Processes the response coming from connect(). New flow: {status:"processing_db"}
 * → poll → DB ready → refresh all tabs. Backward compatibility is preserved for
 * old-format success/error responses (e.g. local mode) that don't return a 202.
 */
function handleConnectResponse(data) {
  if (data && data.status === 'processing_db') {
    state.dc       = data.dc || state.dc;
    state.ip       = data.ip || state.ip;
    state.domain   = data.domain || state.domain;
    state.user     = data.user || state.user;
    state.protocol = data.protocol || state.protocol;

    showToast('Data collected. Preparing the database...', 'info');
    addLog('Collector finished, building domain_data.db...', 'info');

    pollForDbReady(() => {
      state.connected  = true;
      state.connecting = false;
      state.justConnectedUntil = Date.now() + 5000;
      state.sessionStart = state.sessionStart || Date.now();
      showToast('Connection complete', 'success');
      addLog('sqlite_reader.py (30104) is ready — loading tables', 'success');
      refreshAllSectionsAfterConnect();
    });
    return;
  }

  // Backward compatibility: local mode (or an older backend) responds
  // directly in success/error format, without a "processing_db" stage.
  if (data && data.success) {
    state.connected  = true;
    state.connecting = false;
    showToast('Connection complete', 'success');
    addLog('Connection succeeded', 'success');
    refreshAllSectionsAfterConnect();
  } else {
    state.connecting = false;
    const errMsg = (data && (data.error || data.message)) || 'Connection failed';
    showToast(errMsg, 'error');
    addLog(`Connect failed: ${errMsg}`, 'error');
  }
}

/**
 * Main handler for the "Connect" button. Uses the same fields
 * (ip/dc/domain/username/password/hash/protocol) as buildEnumerationPayload(),
 * plus adds connect_mode. The frontend then follows the 202 response from
 * /api/connect without expecting any live JSON.
 */
async function connectToTarget() {
  if (state.connecting) return;
  state.connecting = true;
  stopDbReadyPolling();

  const payload = buildEnumerationPayload();
  payload.connect_mode = state.connectMode || 'deep';

  try {
    const resp = await fetch(`${API_BASE}/api/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(() => null);

    if (!resp.ok && (!data || !data.status)) {
      state.connecting = false;
      const errMsg = (data && (data.error || data.message)) || `Connection error (HTTP ${resp.status})`;
      showToast(errMsg, 'error');
      addLog(`Connect failed: HTTP ${resp.status}`, 'error');
      return;
    }

    handleConnectResponse(data);
  } catch (err) {
    state.connecting = false;
    showToast(`Network error: ${err.message}`, 'error');
    addLog(`Connect network error: ${err.message}`, 'error');
  }
}