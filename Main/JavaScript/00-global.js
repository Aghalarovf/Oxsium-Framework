const API_BASE = 'http://localhost:30100';


const DB_BASE = 'http://localhost:30104';


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
  ssl: false,
};


let sessionTimerId  = null;
let apiPingTimerId  = null;


let usersData     = [];
let usersMeta     = {};
let computersData = [];
let ousData       = [];
let gposData      = [];
let groupsData    = [];
let trustsData    = [];
let aclData       = [];


let filteredOUs    = [];
let filteredGPOs   = [];
let filteredGroups = [];
let filteredTrusts = [];
let filteredACLs   = [];


let enumCacheLoaded = {
  users:     false,
  computers: false,
  ous:       false,
  gpos:      false,
  groups:    false,
  trusts:    false,
  acl:       false,
};


let savedUsersCache = [];


let securityStatusMeta = {
  kerberos: { value: null, source: 'Unknown', protocol: '—' },
  ntlm:     { value: null, source: 'Unknown', protocol: '—' },
  smb:      { value: null, source: 'Unknown', protocol: '—' },
};
let securityCheckerLastResults = { kerberos: null, ntlm: null, smb: null };
let securityCheckerSessionId   = 0;


let groupMembersLoading       = new Set();
let nestedGroupMembersLoading = new Map();
let nestedGroupMembersCache   = new Map();


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

function _readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result || '';
      const b64 = String(result).split(',')[1] || '';
      resolve(b64);
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

async function handleCcacheFileSelect(evt) {
  const file = evt.target.files && evt.target.files[0];
  const nameEl = document.getElementById('ccache-filename');
  if (!file) return;
  try {
    const b64 = await _readFileAsBase64(file);
    state._ccacheName = file.name;
    state._ccacheData = b64;
    if (nameEl) nameEl.textContent = file.name;
    showToast(`Loaded ccache: ${file.name}`, 'success');
    addLog(`Kerberos ccache file loaded: ${file.name}`, 'info');
  } catch (err) {
    showToast('Failed to read ccache file', 'error');
    addLog(`ccache read error: ${err.message}`, 'error');
  }
}

async function handlePfxFileSelect(evt) {
  const file = evt.target.files && evt.target.files[0];
  const nameEl = document.getElementById('pfx-filename');
  if (!file) return;
  try {
    const b64 = await _readFileAsBase64(file);
    state._pfxName = file.name;
    state._pfxData = b64;
    if (nameEl) nameEl.textContent = file.name;
    showToast(`Loaded PFX: ${file.name}`, 'success');
    addLog(`PFX certificate loaded: ${file.name}`, 'info');
  } catch (err) {
    showToast('Failed to read PFX file', 'error');
    addLog(`PFX read error: ${err.message}`, 'error');
  }
}

async function checkAuthMethodPlatformSupport() {
  const ccacheBtn  = document.getElementById('btn-ccache');
  const pfxBtn     = document.getElementById('btn-pfx');
  const ccacheNote = document.getElementById('ccache-os-note');
  const pfxNote    = document.getElementById('pfx-os-note');
  const pfxPassEl  = document.getElementById('f-pfx-pass');

  try {
    const resp = await fetch(`${API_BASE}/api/platform`);
    const data = await resp.json();
    const platform = (data && data.platform) || '';

    if (platform === 'Windows') {
      if (ccacheBtn)  { ccacheBtn.disabled = true; ccacheBtn.classList.add('api-locked'); }
      if (pfxBtn)     { pfxBtn.disabled = true; pfxBtn.classList.add('api-locked'); }
      if (pfxPassEl)  pfxPassEl.disabled = true;
      if (ccacheNote) ccacheNote.style.display = 'block';
      if (pfxNote)    pfxNote.style.display = 'block';
    }
  } catch (_err) {
    // Backend not reachable yet — leave buttons as-is, will retry on next ping.
  }
}

document.addEventListener('DOMContentLoaded', checkAuthMethodPlatformSupport);


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


  const finalPass = passInput || (!hashInput && !savedHash ? savedPass : savedPass && !hashInput ? savedPass : '');
  const finalHash = hashInput || (!passInput && !savedPass ? savedHash : savedHash && !passInput ? savedHash : '');

  // When SSL is toggled on, ensure the protocol field is "ldaps" so the
  // backend opens an LDAPS connection on port 636, regardless of which
  // protocol button (ldap / rpc / ...) was last selected.
  const effectiveProtocol = state.ssl
    ? 'ldaps'
    : state.protocol;

  return {
    mode:      'remote',
    protocol:  effectiveProtocol,
    use_ssl:   !!state.ssl,
    ip:        document.getElementById('f-ip')?.value.trim()     || state.ip || state.dc,
    dc:        ldapTarget,
    ldap_host: ldapTarget,
    domain:    document.getElementById('f-domain')?.value.trim() || state.domain,
    username:  document.getElementById('f-user')?.value.trim()   || state.user,
    password:  finalPass,
    hash:      finalHash,
    ccache_filename: state._ccacheName || null,
    ccache_data:     state._ccacheData || null,
    pfx_filename:    state._pfxName || null,
    pfx_data:        state._pfxData || null,
    pfx_password:    (document.getElementById('f-pfx-pass')?.value || '').trim() || null,
  };
}



document.addEventListener('submit', (e) => e.preventDefault(), true);


function resetEnumCacheFlags() {
  Object.keys(enumCacheLoaded).forEach(k => { enumCacheLoaded[k] = false; });
}


const DB_READER_BASE = 'http://localhost:30104';


const DB_READER_TABLE = {
  users:     'users',
  computers: 'computers',
  ous:       'ous',
  gpos:      'gpos',
  groups:    'groups',
  trusts:    'trusts',
  acl:       'aces',
};


const DB_READER_PARENT_TABLES = new Set(['users', 'computers', 'groups', 'gpos', 'ous', 'trusts']);


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


const DEFAULT_SECTION_LOADER_NAMES = [
  'loadUsers', 'loadComputers', 'loadOUs', 'loadGPOs',
  'loadGroups', 'loadTrusts', 'loadACLs',
];


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
    if (registeredSectionLoaders.has(section)) return;
    const fn = window[fnName];
    if (typeof fn === 'function') {
      try { fn(); called.push(fnName); }
      catch (err) { addLog(`${fnName} error: ${err.message}`, 'error'); }
    } else {
      missing.push(fnName);
    }
  });

    if (called.length) {
      // Loaded from DB log suppressed for cleaner UI
    }
  if (missing.length) {


    addLog(`Loader functions not found (DB query not sent): ${missing.join(', ')}`, 'error');
    showToast(`No loader function found for ${missing.length} section(s) — check the console`, 'error');
    console.warn('[refreshAllSectionsAfterConnect] Functions not found:', missing,
      '— register these with registerSectionLoader() or fix their names.');
  }
}


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
      // sqlite_reader ready log suppressed
      refreshAllSectionsAfterConnect();
    });
    return;
  }


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