const API_BASE = 'http://localhost:5000';

let state = {
  connected: false,
  mode: 'remote',
  protocol: 'winrm',
  domain: null,
  user: null,
  dc: null,
  sessionStart: null
};

let sessionTimerId = null;

function buildEnumerationPayload() {
  if (state.mode === 'local' || state.protocol === 'local') {
    return { mode: 'local' };
  }

  const dcInput = (document.getElementById('f-dc')?.value || '').trim();
  const ldapTarget = dcInput || state.dc || state.domain;
  const passInput = document.getElementById('f-pass').value;
  const hashInput = (document.getElementById('f-hash')?.value || '').trim();
  const authSecret = passInput || hashInput || state._pass || state._hash || '';

  return {
    mode: 'remote',
    protocol: state.protocol,
    ip: document.getElementById('f-ip').value.trim() || state.dc,
    dc: ldapTarget,
    ldap_host: ldapTarget,
    domain: document.getElementById('f-domain').value.trim() || state.domain,
    username: document.getElementById('f-user').value.trim() || state.user,
    password: authSecret,
    hash: hashInput || state._hash || ''
  };
}

/* ── UTILITY ── */
function now() {
  return new Date().toLocaleTimeString('az', { hour12: false });
}

function addLog(msg, type = 'info') {
  const term = document.getElementById('log-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className = `log-line log-${type}`;
  line.innerHTML = `<span class="log-time">[${now()}]</span> <span class="log-msg">${msg}</span>`;
  term.appendChild(line);
  const maxLines = 400;
  while (term.children.length > maxLines) {
    term.removeChild(term.children[0]);
  }
  term.scrollTop = term.scrollHeight;
}

function showToast(msg, type = 'info') {
  const ct = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  t.innerHTML = `<span style="color:${type==='success'?'var(--green)':type==='error'?'var(--red)':'var(--accent)'}">${icons[type]||'ℹ'}</span> ${msg}`;
  ct.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function setConnState(s) {
  const dot = document.getElementById('top-conn-dot');
  const lbl = document.getElementById('top-conn-label');
  const sv  = document.getElementById('stat-conn');
  const sb  = document.getElementById('sb-status');

  if (s === 'connected') {
    dot.className = 'conn-dot connected';
    lbl.textContent = 'CONNECTED'; lbl.className = 'conn-label connected';
    sv.textContent = 'ACTIVE'; sv.className = 'stat-value green';
    sb.textContent = 'CONNECTED'; sb.className = 's-val ok';
  } else if (s === 'connecting') {
    dot.className = 'conn-dot connecting';
    lbl.textContent = 'CONNECTING...'; lbl.className = 'conn-label';
    sv.textContent = 'CONNECTING'; sv.className = 'stat-value amber';
    sb.textContent = 'CONNECTING'; sb.className = 's-val warn';
  } else if (s === 'error') {
    dot.className = 'conn-dot error';
    lbl.textContent = 'AUTH FAILED'; lbl.className = 'conn-label error';
    sv.textContent = 'AUTH FAILED'; sv.className = 'stat-value red';
    sb.textContent = 'ERROR'; sb.className = 's-val';
  } else {
    dot.className = 'conn-dot';
    lbl.textContent = 'DISCONNECTED'; lbl.className = 'conn-label';
    sv.textContent = 'OFFLINE'; sv.className = 'stat-value dim';
    sb.textContent = 'IDLE'; sb.className = 's-val';
  }
  updateConnectButtonState();
  updateModeButtonState();
  updateShellTabState();
  updateEnumerationTabState();
  updateReconnaissanceTabState();
}

function updateEnumerationTabState() {
  const enumBtn = document.querySelector('.main-tab[data-tab="enumeration"]');
  const enumTab = document.getElementById('tab-enumeration');
  if (!enumBtn || !enumTab) return;

  if (state.connected) {
    enumBtn.disabled = false;
    enumBtn.classList.remove('disabled');
    enumBtn.title = 'Open Enumeration';
  } else {
    enumBtn.disabled = true;
    enumBtn.classList.add('disabled');
    enumBtn.title = 'Connect first';
    if (enumTab.style.display !== 'none') {
      switchMainTab('connect');
    }
  }
}

function toggleEnumerationModuleList() {
  const list = document.getElementById('enum-module-list');
  if (!list) return;
  const isOpen = list.style.display === 'block';
  list.style.display = isOpen ? 'none' : 'block';
}

function selectEnumerationModule(name, btn) {
  const selected = document.getElementById('enum-selected-name');
  if (selected) selected.textContent = name;
  document.querySelectorAll('#enum-modules-scroll .module-item').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('enum-module-list').style.display = 'none';
}

function updateReconnaissanceTabState() {
  const reconBtn = document.querySelector('.main-tab[data-tab="reconnaissance"]');
  const reconTab = document.getElementById('tab-reconnaissance');
  if (!reconBtn || !reconTab) return;

  if (state.connected) {
    reconBtn.disabled = false;
    reconBtn.classList.remove('disabled');
    reconBtn.title = 'Open Reconnaissance';
  } else {
    reconBtn.disabled = true;
    reconBtn.classList.add('disabled');
    reconBtn.title = 'Connect first';
    if (reconTab.style.display !== 'none') {
      switchMainTab('connect');
    }
  }
}

function setBtnLoading(loading) {
  const btn = document.getElementById('btn-connect');
  const txt = document.getElementById('btn-connect-text');
  if (loading) {
    btn.disabled = true;
    txt.innerHTML = '<span class="spinner"></span>&nbsp;CONNECTING';
  } else {
    btn.disabled = false;
    updateConnectButtonState();
  }
}

function updateConnectButtonState() {
  const btn = document.getElementById('btn-connect');
  const txt = document.getElementById('btn-connect-text');
  if (!btn || !txt) return;

  const localDisconnectBtn = document.getElementById('btn-local-disconnect');

  if (state.connected) {
    btn.classList.add('btn-danger');
    btn.classList.remove('btn-primary');
    btn.onclick = doDisconnect;
    txt.textContent = 'DISCONNECT';
  } else {
    btn.classList.remove('btn-danger');
    btn.classList.add('btn-primary');
    btn.onclick = doConnect;
    txt.textContent = 'CONNECT';
  }

  if (localDisconnectBtn) {
    const localActive = state.connected && state.protocol === 'local';
    localDisconnectBtn.disabled = !localActive;
    localDisconnectBtn.classList.toggle('btn-danger', localActive);
    localDisconnectBtn.classList.toggle('btn-secondary', !localActive);
  }
}

function updateModeButtonState() {
  const remoteBtn = document.getElementById('mode-remote');
  const localBtn = document.getElementById('mode-local');
  if (!remoteBtn || !localBtn) return;

  remoteBtn.disabled = false;
  remoteBtn.classList.remove('disabled');
  localBtn.disabled = false;
  localBtn.classList.remove('disabled');

  if (state.connected) {
    if (state.protocol === 'local') {
      remoteBtn.disabled = true;
      remoteBtn.classList.add('disabled');
    } else {
      localBtn.disabled = true;
      localBtn.classList.add('disabled');
    }
  }
}

function validate() {
  let ok = true;
  const fields = [
    { id: 'f-domain', err: 'err-domain' },
    { id: 'f-ip',     err: 'err-ip' },
    { id: 'f-user',   err: 'err-user' }
  ];
  fields.forEach(f => {
    const el = document.getElementById(f.id);
    const er = document.getElementById(f.err);
    if (!el.value.trim()) {
      el.classList.add('error');
      er.classList.add('show');
      ok = false;
    } else {
      el.classList.remove('error');
      er.classList.remove('show');
    }
  });

  const passEl = document.getElementById('f-pass');
  const hashEl = document.getElementById('f-hash');
  const passErr = document.getElementById('err-pass');
  const hashErr = document.getElementById('err-hash');
  const hasPass = !!passEl.value.trim();
  const hasHash = !!(hashEl?.value || '').trim();

  if (!hasPass && !hasHash) {
    passEl.classList.add('error');
    hashEl?.classList.add('error');
    passErr.classList.add('show');
    hashErr?.classList.add('show');
    ok = false;
  } else {
    passEl.classList.remove('error');
    hashEl?.classList.remove('error');
    passErr.classList.remove('show');
    hashErr?.classList.remove('show');
  }

  return ok;
}

function updateStats(data) {
  const set = (id, val, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val || '—';
    if (cls) el.className = `stat-value ${cls}`;
  };
  set('stat-domain',  data.domain || state.domain,          'accent');
  set('stat-dc',      data.dc     || state.dc     || state.domain, 'accent');
  set('stat-user',    data.username,         'accent');
  set('stat-proto',   (state.protocol || '').toUpperCase(), 'accent');
  set('stat-os',      data.os_version,       '');
  set('stat-level',   data.domain_level,     '');
  set('stat-kerb',    data.kerberos_enabled ? 'Enabled' : 'Disabled',
                      data.kerberos_enabled ? 'green' : 'red');
  set('stat-api',     'Reachable',           'green');
  set('stat-latency', data.latency_ms ? `${data.latency_ms} ms` : '—', '');
  document.getElementById('sb-proto').textContent = (state.protocol || '').toUpperCase();
  document.getElementById('api-ping-bar').style.width = '100%';

  if (data.counts) {
    const c = data.counts;
    const setMini = (id, val) => {
      const el = document.getElementById(id);
      if (el) { el.textContent = val ?? 0; el.className = 'stat-mini-val active'; }
    };
    setMini('cnt-users',  c.users);
    setMini('cnt-comp',   c.computers);
    setMini('cnt-groups', c.groups);
    setMini('cnt-ous',    c.ous);
    setMini('cnt-gpos',   c.gpos);
    setMini('cnt-trusts', c.trusts);
  }
}

function startSessionTimer() {
  state.sessionStart = Date.now();
  if (sessionTimerId) {
    clearInterval(sessionTimerId);
    sessionTimerId = null;
  }
  sessionTimerId = setInterval(() => {
    if (!state.connected) return;
    const s = Math.floor((Date.now() - state.sessionStart) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    document.getElementById('sb-time').textContent = `${h}:${m}:${sec}`;
  }, 1000);
}

/* ── CONNECT ── */
async function doConnect() {
  if (!validate()) {
    addLog('Validation failed — fill all required fields', 'err');
    return;
  }

  const domain   = document.getElementById('f-domain').value.trim();
  const ip       = document.getElementById('f-ip').value.trim();
  const dcHost   = (document.getElementById('f-dc')?.value || '').trim();
  const username = document.getElementById('f-user').value.trim();
  const password = document.getElementById('f-pass').value;
  const hash     = (document.getElementById('f-hash')?.value || '').trim();
  const authSecret = password || hash;

  state.domain   = domain;
  state.user     = username;
  state.protocol = state.protocol;

  if (state.connected && state.protocol === 'local') {
    addLog('Detaching local session before remote connect...', 'info');
    state.connected = false;
    setConnState('disconnected');
  }

  setBtnLoading(true);
  setConnState('connecting');
  addLog(`Initiating ${state.protocol.toUpperCase()} connection to ${ip} (${domain})...`, 'info');

  try {
    const resp = await fetch(`${API_BASE}/api/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'remote',
        protocol: state.protocol,
        domain, ip, username,
        password: authSecret,
        hash,
        dc: dcHost,
        ldap_host: dcHost
      })
    });

    const data = await resp.json();

    if (resp.ok && data.success) {
      state.connected = true;
      state.mode = 'remote';
      state.domain = data.domain || domain;
      state.dc = dcHost || data.dc || ip;
      setConnState('connected');
      addLog(`Connected as ${username}@${state.domain} via ${state.protocol.toUpperCase()}`, 'ok');
      addLog(`Domain Controller: ${state.dc || 'N/A'}`, 'ok');
      updateStats(data);
      startSessionTimer();
      state._pass = password || '';
      state._hash = hash || '';
      document.getElementById('nav-users-count').textContent = data.counts?.users ?? '?';
      showToast(`Connected to ${state.domain}`, 'success');
    } else {
      throw new Error(data.error || data.message || 'LDAP Authentication Failed!');
    }

  } catch (err) {
    state.connected = false;
    setConnState('error');
    addLog(`Connection failed: ${err.message}`, 'err');
    showToast(err.message, 'error');
  } finally {
    setBtnLoading(false);
  }
}

function doDisconnect() {
  if (!state.connected) return;

  addLog('Disconnecting active session...', 'warn');
  if (sessionTimerId) {
    clearInterval(sessionTimerId);
    sessionTimerId = null;
  }
  state.connected = false;
  setConnState('disconnected');
  showLoginScreen();
  showToast('Session disconnected', 'info');
}

async function doLocalConnect() {
  if (state.connected && state.protocol !== 'local') {
    addLog('Disconnecting remote session before attaching local session...', 'info');
    state.connected = false;
    setConnState('disconnected');
  }

  setConnState('connecting');
  addLog('Attaching to local session via Python API...', 'info');
  try {
    const resp = await fetch(`${API_BASE}/api/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'local' })
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      state.connected = true;
      state.mode     = 'local';
      state.protocol = 'local';
      state.user     = data.username || state.user;
      state.domain   = data.domain || state.domain;
      state.dc       = data.dc || state.dc;
      setConnState('connected');
      addLog(`Local session attached: ${data.username}`, 'ok');
      updateStats(data);
      startSessionTimer();
      document.getElementById('nav-users-count').textContent = data.counts?.users ?? '?';
      showToast('Local session attached', 'success');
    } else {
      throw new Error(data.error || data.message || 'Failed to attach session');
    }
  } catch (err) {
    state.connected = false;
    setConnState('error');
    addLog(`Local connect failed: ${err.message}`, 'err');
    showToast(err.message, 'error');
  }
}

async function testConn() {
  if (!validate()) return;
  const ip     = document.getElementById('f-ip').value.trim();
  const domain = document.getElementById('f-domain').value.trim();
  addLog(`Testing reachability of ${ip}...`, 'info');
  try {
    const resp = await fetch(`${API_BASE}/api/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, protocol: state.protocol, domain })
    });
    const data = await resp.json();
    if (resp.ok && data.reachable) {
      addLog(`Host ${ip} is reachable. Port open: ${data.port}`, 'ok');
      showToast('Host is reachable', 'success');
    } else {
      addLog(`Host ${ip} is unreachable or port closed`, 'err');
      showToast('Host unreachable', 'error');
    }
  } catch (err) {
    addLog(`Test failed: ${err.message}`, 'err');
    showToast('API backend not running', 'error');
  }
}

/* ── UI ── */
function switchMode(m) {
  if (state.connected && state.mode !== m) {
    showToast('Disconnect before switching session type', 'info');
    return;
  }
  state.mode = m;
  document.getElementById('remote-form').style.display = m === 'remote' ? 'block' : 'none';
  document.getElementById('local-form').style.display  = m === 'local'  ? 'block' : 'none';
  document.getElementById('mode-remote').className = 'mode-btn' + (m === 'remote' ? ' active' : '');
  document.getElementById('mode-local').className  = 'mode-btn' + (m === 'local'  ? ' active' : '');
}

function selectProto(p) {
  state.protocol = p;
  ['winrm','psexec','smb','ssh'].forEach(x => {
    document.getElementById(`proto-${x}`).className = 'proto-btn' + (x === p ? ' selected' : '');
  });
  document.getElementById('sb-proto').textContent = p.toUpperCase();
}

function togglePass() {
  const f = document.getElementById('f-pass');
  f.type = f.type === 'password' ? 'text' : 'password';
}

function toggleHash() {
  const f = document.getElementById('f-hash');
  if (!f) return;
  f.type = f.type === 'password' ? 'text' : 'password';
}

function clearForm() {
  ['f-domain','f-ip','f-dc','f-user','f-pass','f-hash'].forEach(id => {
    const el = document.getElementById(id);
    el.value = '';
    el.classList.remove('error');
  });
  ['err-domain','err-ip','err-user','err-pass','err-hash'].forEach(id =>
    document.getElementById(id).classList.remove('show')
  );
  addLog('Form cleared', 'info');
}

function showLoginScreen() {
  switchMainTab('connect');
  document.getElementById('tab-users').style.display   = 'none';
  document.getElementById('tab-computers').style.display = 'none';
  document.getElementById('tab-ous').style.display = 'none';
  document.getElementById('tab-gpo').style.display = 'none';
  document.getElementById('tab-groups').style.display = 'none';
  document.getElementById('tab-trusts').style.display = 'none';

  // Nav items
  document.querySelectorAll('.nav-item[id^="nav-"]').forEach(el => el.classList.remove('active'));

  if (!state.connected) {
    state._pass = null;
    state._hash = null;
    usersData   = [];

    // Conn state sıfırla
    setConnState('disconnected');

    // Counters sıfırla
    ['nav-users-count','nav-computers-count','nav-ous-count','nav-gpo-count','nav-groups-count','nav-trusts-count'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '—';
    });

    // Stats sıfırla
    ['stat-domain','stat-dc','stat-user','stat-proto',
     'stat-os','stat-level','stat-kerb','stat-latency'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = '—'; el.className = 'stat-value dim'; }
    });
    document.getElementById('stat-conn').textContent  = 'OFFLINE';
    document.getElementById('stat-conn').className    = 'stat-value dim';
    document.getElementById('api-ping-bar').style.width = '0%';
    ['cnt-users','cnt-comp','cnt-groups','cnt-ous','cnt-gpos','cnt-trusts'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = '—'; el.className = 'stat-mini-val'; }
    });

    // Form temizle
    ['f-domain','f-ip','f-dc','f-user','f-pass','f-hash'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.value = ''; el.classList.remove('error'); }
    });
    ['err-domain','err-ip','err-user','err-pass','err-hash'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.remove('show');
    });

    addLog('Session terminated. Ready for new connection.', 'warn');
  } else {
    addLog('Connect tab opened while session remains active.', 'info');
  }
}

function appendShellOutput(text, type = 'info') {
  const term = document.getElementById('shell-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className = `shell-line shell-${type}`;
  line.textContent = text;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function clearShellOutput() {
  const term = document.getElementById('shell-terminal');
  if (!term) return;
  term.innerHTML = '<div class="shell-line shell-info">Ready. Enter commands and press Enter.</div>';
}

function updateShellTabState() {
  const input = document.getElementById('shell-input');
  const btn = document.getElementById('btn-shell-send');
  const enabled = state.connected && ['local', 'winrm'].includes(state.protocol);
  if (input) input.disabled = !enabled;
  if (btn) btn.disabled = !enabled;
}

async function sendShellCommand() {
  const input = document.getElementById('shell-input');
  const btn = document.getElementById('btn-shell-send');
  if (!input || !btn) return;
  const command = input.value.trim();
  if (!command) return;
  if (!state.connected) {
    showToast('Connect first to use the shell', 'error');
    return;
  }

  appendShellOutput(`PS> ${command}`, 'prompt');
  input.value = '';
  btn.disabled = true;

  try {
    const payload = {
      mode: state.mode,
      protocol: state.protocol,
      command,
      domain: state.domain,
      ip: document.getElementById('f-ip').value.trim() || state.dc,
      username: document.getElementById('f-user').value.trim() || state.user,
      password: state._pass || state._hash || '',
      hash: state._hash || ''
    };

    const resp = await fetch(`${API_BASE}/api/shell`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();

    if (resp.ok && data.success) {
      if (data.output) appendShellOutput(data.output, 'output');
      if (data.stderr) appendShellOutput(data.stderr, 'error');
      if (!data.output && !data.stderr) appendShellOutput('Command executed.', 'info');
    } else {
      appendShellOutput(data.error || 'Shell command failed', 'error');
    }
  } catch (err) {
    appendShellOutput(err.message || 'Shell request failed', 'error');
  } finally {
    btn.disabled = false;
  }
}

function handleShellKey(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendShellCommand();
  }
}

function switchMainTab(tab, btn) {
  if ((tab === 'enumeration' || tab === 'reconnaissance') && !state.connected) {
    return;
  }

  document.getElementById('tab-connect').style.display = 'none';
  document.getElementById('tab-powershell').style.display = 'none';
  document.getElementById('tab-enumeration').style.display = 'none';
  document.getElementById('tab-reconnaissance').style.display = 'none';
  document.getElementById('tab-users').style.display = 'none';
  document.getElementById('tab-computers').style.display = 'none';
  document.getElementById('tab-ous').style.display = 'none';
  document.getElementById('tab-gpo').style.display = 'none';
  document.getElementById('tab-groups').style.display = 'none';
  document.getElementById('tab-trusts').style.display = 'none';
  document.querySelectorAll('.main-tab').forEach(el => el.classList.remove('active'));

  if (btn) {
    btn.classList.add('active');
  } else {
    const activeBtn = document.querySelector(`.main-tab[data-tab="${tab}"]`);
    if (activeBtn) activeBtn.classList.add('active');
  }

  if (tab === 'powershell') {
    document.getElementById('tab-powershell').style.display = '';
    const term = document.getElementById('shell-terminal');
    if (term) {
      if (!state.connected) {
        term.innerHTML = '<div class="shell-line shell-warn">Shell unavailable: connect with WinRM or Local session first.</div>';
      } else if (!['local','winrm'].includes(state.protocol)) {
        term.innerHTML = '<div class="shell-line shell-warn">Shell is only available for WinRM or Local sessions.</div>';
      } else if (term.children.length === 0 || term.textContent.includes('Connect first')) {
        term.innerHTML = '<div class="shell-line shell-info">Ready. Enter commands and press Enter.</div>';
      }
    }
    updateShellTabState();
    return;
  }

  if (tab === 'users') {
    document.getElementById('tab-users').style.display = '';
    loadUsers();
    return;
  }

  if (tab === 'computers') {
    document.getElementById('tab-computers').style.display = '';
    loadComputers();
    return;
  }

  if (tab === 'enumeration') {
    document.getElementById('tab-enumeration').style.display = '';
    const titleEl = document.querySelector('#enumeration-placeholder .enumeration-placeholder-title');
    const copyEl = document.querySelector('#enumeration-placeholder .enumeration-placeholder-copy');
    if (titleEl && copyEl) {
      if (state.connected) {
        titleEl.textContent = 'Enumeration is ready';
        copyEl.textContent = 'This panel is prepared for the enumeration modules you will add next.';
      } else {
        titleEl.textContent = 'Connect first to unlock Enumeration';
        copyEl.textContent = 'Enumeration features appear here once a Local or Remote session is active.';
      }
    }
    return;
  }

  if (tab === 'reconnaissance') {
    document.getElementById('tab-reconnaissance').style.display = '';
    const placeholder = document.getElementById('reconnaissance-placeholder');
    if (placeholder) {
      if (state.connected) {
        placeholder.innerHTML = '<div class="reconnaissance-placeholder-title">Reconnaissance is ready</div><div class="reconnaissance-placeholder-copy">This panel is prepared for reconnaissance workflows once you add modules.</div>';
      } else {
        placeholder.innerHTML = '<div class="reconnaissance-placeholder-title">Connect first to unlock Reconnaissance</div><div class="reconnaissance-placeholder-copy">Reconnaissance modules appear here once a session is connected.</div>';
      }
    }
    return;
  }

  document.getElementById('tab-connect').style.display = '';
  updateShellTabState();
}

/* ── PING API HEALTH ── */
async function pingApi() {
  try {
    const t0 = Date.now();
    const resp = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(2000) });
    const ms = Date.now() - t0;
    if (resp.ok) {
      document.getElementById('stat-api').textContent = 'Reachable';
      document.getElementById('stat-api').className = 'stat-value green';
      document.getElementById('stat-latency').textContent = `${ms} ms`;
      document.getElementById('api-ping-bar').style.width = `${Math.min(100, ms)}%`;
    } else { throw new Error(); }
  } catch {
    document.getElementById('stat-api').textContent = 'Unreachable';
    document.getElementById('stat-api').className = 'stat-value red';
    document.getElementById('stat-latency').textContent = 'N/A';
  }
}

pingApi();
setInterval(pingApi, 20000);


/* ══════════ USERS TAB ══════════ */

let usersData   = [];   // full list from API
let usersFilter = 'all';
let usersSearch = '';

function switchTab(tab) {
  // hide all
  document.getElementById('tab-connect').style.display = 'none';
  document.getElementById('tab-users').style.display   = 'none';
  document.getElementById('tab-computers').style.display = 'none';
  document.getElementById('tab-ous').style.display = 'none';
  document.getElementById('tab-gpo').style.display = 'none';
  document.getElementById('tab-groups').style.display = 'none';
  document.getElementById('tab-trusts').style.display = 'none';

  // nav items
  document.querySelectorAll('.nav-item[id^="nav-"]').forEach(el => el.classList.remove('active'));

  // attack modules — yalnız users tab-da görünür
  document.getElementById('sidebar-attacks').style.display = tab === 'users' ? 'flex' : 'none';

  if (tab === 'users') {
    document.getElementById('tab-users').style.display = 'flex';
    document.getElementById('nav-users').classList.add('active');
    if (!state.connected) {
      document.getElementById('u-empty').innerHTML = '<svg width="36" height="36" viewBox="0 0 36 36" fill="none" opacity="0.2"><circle cx="18" cy="12" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M4 32c0-7.7 6.3-14 14-14s14 6.3 14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><p>Connect to a domain first</p>';
    } else if (usersData.length === 0) {
      loadUsers();
    }
  } else if (tab === 'computers') {
    document.getElementById('tab-computers').style.display = 'flex';
    document.getElementById('nav-computers').classList.add('active');
    if (!state.connected) {
      document.getElementById('c-empty').innerHTML = '<svg width="36" height="36" viewBox="0 0 36 36" fill="none" opacity="0.2"><circle cx="18" cy="12" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M4 32c0-7.7 6.3-14 14-14s14 6.3 14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><p>Connect to a domain first</p>';
    } else if (computersData.length === 0) {
      loadComputers();
    }
  } else if (tab === 'ous') {
    document.getElementById('tab-ous').style.display = 'flex';
    document.getElementById('nav-ous').classList.add('active');
    if (!state.connected) {
      document.getElementById('o-empty').innerHTML = '<svg width="36" height="36" viewBox="0 0 36 36" fill="none" opacity="0.2"><circle cx="18" cy="12" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M4 32c0-7.7 6.3-14 14-14s14 6.3 14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><p>Connect to a domain first</p>';
    } else if (ousData.length === 0) {
      loadOUs();
    }
  } else if (tab === 'gpo') {
    document.getElementById('tab-gpo').style.display = 'flex';
    document.getElementById('nav-gpo').classList.add('active');
    if (!state.connected) {
      document.getElementById('g-empty').innerHTML = '<svg width="36" height="36" viewBox="0 0 36 36" fill="none" opacity="0.2"><circle cx="18" cy="12" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M4 32c0-7.7 6.3-14 14-14s14 6.3 14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><p>Connect to a domain first</p>';
    } else if (gposData.length === 0) {
      loadGPOs();
    }
  } else if (tab === 'groups') {
    document.getElementById('tab-groups').style.display = 'flex';
    document.getElementById('nav-groups').classList.add('active');
    if (!state.connected) {
      document.getElementById('gr-empty').innerHTML = '<p>Connect to a domain first</p>';
    } else if (groupsData.length === 0) {
      loadGroups();
    }
  } else if (tab === 'trusts') {
    document.getElementById('tab-trusts').style.display = 'flex';
    document.getElementById('nav-trusts').classList.add('active');
    if (!state.connected) {
      document.getElementById('tr-empty').innerHTML = '<p>Connect to a domain first</p>';
    } else if (trustsData.length === 0) {
      loadTrusts();
    }
  } else {
    document.getElementById('tab-connect').style.display = '';
  }
}

async function loadUsers() {
  if (!state.connected) {
    addLog('Users: domain connection required', 'warn');
    return;
  }
  document.getElementById('users-loading').style.display = 'flex';
  document.getElementById('u-table-body').innerHTML = '';
  closeDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load users');

    usersData = data.users;
    document.getElementById('nav-users-count').textContent = usersData.length;
    document.getElementById('users-meta').textContent =
      `${usersData.length} users · domain: ${(state.domain||'').toUpperCase()}`;
    renderUsers();
    updatePentestCounts();
    addLog(`Users loaded: ${usersData.length} accounts enumerated`, 'ok');
  } catch (err) {
    addLog(`Users: ${err.message}`, 'err');
    document.getElementById('u-table-body').innerHTML =
      `<div class="u-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('users-loading').style.display = 'none';
  }
}

function setFilter(f, btn) {
  usersFilter = f;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  renderUsers();
}

function filterUsers() {
  usersSearch = document.getElementById('users-search').value.toLowerCase();
  renderUsers();
}

function renderUsers() {
  const body = document.getElementById('u-table-body');
  body.innerHTML = '';

  let list = usersData;

  // text filter
  if (usersSearch) {
    list = list.filter(u =>
      u.username.toLowerCase().includes(usersSearch) ||
      (u.sid||'').toLowerCase().includes(usersSearch)
    );
  }

  // chip filter
  if (usersFilter === 'admin')    list = list.filter(u => u.is_admin);
  if (usersFilter === 'spn')      list = list.filter(u => u.spn && u.spn.length > 0);
  if (usersFilter === 'asrep')    list = list.filter(u => u.asrep);
  if (usersFilter === 'disabled') list = list.filter(u => u.disabled);

  if (list.length === 0) {
    body.innerHTML = '<div class="u-empty"><p>No matching users</p></div>';
    return;
  }

  list.forEach(u => {
    const row = document.createElement('div');
    row.className = 'u-row';
    row.dataset.sam = u.username;

    const avatarCls = u.is_admin ? 'u-avatar admin' : u.disabled ? 'u-avatar disabled' : 'u-avatar';
    const initial   = u.username.charAt(0).toUpperCase();
    const sidFull   = u.sid || '—';

    const flagAdmin = u.is_admin ? '<span class="flag yes-admin">ADM</span>'  : '<span class="flag no">—</span>';
    const flagSpn   = (u.spn && u.spn.length > 0) ? '<span class="flag yes-spn">SPN</span>' : '<span class="flag no">—</span>';
    const flagAsrep = u.asrep    ? '<span class="flag yes-asrep">✓</span>'   : '<span class="flag no">—</span>';
    const flagStat  = u.disabled ? '<span class="flag yes-dis">DIS</span>'   : '<span class="flag yes-ok">●</span>';

    row.innerHTML = `
      <div class="u-name">
        <div class="${avatarCls}">${initial}</div>
        ${u.username}
      </div>
      <div class="u-sid" title="${sidFull}">${sidFull}</div>
      <div class="u-flag-cell">${flagAdmin}</div>
      <div class="u-flag-cell">${flagSpn}</div>
      <div class="u-flag-cell">${flagAsrep}</div>
      <div class="u-flag-cell">${flagStat}</div>
    `;

    row.addEventListener('click', () => openDetail(u, row));
    body.appendChild(row);
  });
}

function openDetail(u, row) {
  // mark selected
  document.querySelectorAll('.u-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('user-detail').style.display = 'flex';
  document.getElementById('d-avatar').textContent = u.username.charAt(0).toUpperCase();
  document.getElementById('d-name').textContent   = u.username;
  document.getElementById('d-dn').textContent     = u.dn || '—';

  const body = document.getElementById('detail-body');
  body.innerHTML = '';

  // ── Identity section ──
  body.innerHTML += detailSection('Identity', [
    ['Username',     u.username,                   'accent'],
    ['Display Name', u.display_name || '—',         u.display_name ? '' : 'dim'],
    ['SID',          u.sid          || '—',         u.sid ? '' : 'dim'],
    ['RID',          u.sid ? u.sid.split('-').pop() : '—', ''],
    ['UPN',          u.upn          || '—',         u.upn ? '' : 'dim'],
    ['Description',  u.description  || '—',         u.description ? '' : 'dim'],
  ]);

  // ── Account Flags ──
  body.innerHTML += detailSection('Account Flags', [
    ['Status',           u.disabled ? 'Disabled' : 'Enabled',         u.disabled ? 'red' : 'green'],
    ['Admin',            u.is_admin  ? 'Yes'      : 'No',              u.is_admin ? 'amber' : ''],
    ['Pre-Auth Req.',    u.preauth_required === false ? 'NOT Required (⚠ AS-REP)' : 'Required',
                                                                        u.preauth_required === false ? 'red' : 'green'],
    ['Password Expired', u.pwd_expired ? 'Yes' : 'No',                 u.pwd_expired ? 'amber' : ''],
    ['Locked Out',       u.locked_out  ? 'Yes' : 'No',                 u.locked_out ? 'red' : ''],
    ['Must Change Pwd',  u.must_change_pwd ? 'Yes' : 'No',             u.must_change_pwd ? 'amber' : ''],
    ['Pwd Never Expires',u.pwd_never_expires ? 'Yes' : 'No',           u.pwd_never_expires ? 'amber' : ''],
    ['Delegatable',      u.trusted_for_delegation ? 'Yes' : 'No',      u.trusted_for_delegation ? 'red' : ''],
  ]);

  // ── Dates ──
  body.innerHTML += detailSection('Timestamps', [
    ['Created',        fmtDate(u.when_created), ''],
    ['Last Modified',  fmtDate(u.when_changed),  ''],
    ['Last Logon',     fmtDate(u.last_logon),     u.last_logon ? '' : 'dim'],
    ['Pwd Last Set',   fmtDate(u.pwd_last_set),   u.pwd_last_set ? '' : 'dim'],
  ]);

  // ── Groups ──
  const groupsHtml = (u.member_of && u.member_of.length > 0)
    ? u.member_of.map(g => `<div class="group-item">${g}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  body.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">Member Of (${(u.member_of||[]).length})</div>
      <div class="spn-list">${groupsHtml}</div>
    </div>`;

  // ── SPN ──
  if (u.spn && u.spn.length > 0) {
    const spnHtml = u.spn.map(s => `<div class="spn-item">${s}</div>`).join('');
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Service Principal Names (${u.spn.length})</div>
        <div class="spn-list">${spnHtml}</div>
      </div>`;
  }
}

function detailSection(title, rows) {
  const rowsHtml = rows.map(([lbl, val, cls]) => `
    <div class="detail-row">
      <span class="d-label">${lbl}</span>
      <span class="d-val ${cls||''}">${val}</span>
    </div>`).join('');
  return `<div class="detail-section">
    <div class="detail-section-title">${title}</div>
    ${rowsHtml}
  </div>`;
}

function fmtDate(raw) {
  if (!raw) return '—';
  try {
    const d = new Date(raw);
    if (isNaN(d)) return raw;
    return d.toISOString().slice(0,16).replace('T',' ');
  } catch { return raw; }
}

function closeDetail() {
  document.getElementById('user-detail').style.display = 'none';
  document.querySelectorAll('.u-row').forEach(r => r.classList.remove('selected'));
}

// OUs Functions
let ousData = [];
let filteredOUs = [];
let ousFilter = 'all';
let ousSearch = '';

// GPOs Functions
let gposData = [];
let filteredGPOs = [];
let gposFilter = 'all';
let gposSearch = '';
let groupsData = [];
let filteredGroups = [];
let groupsFilter = 'all';
let groupsSearch = '';
let trustsData = [];
let filteredTrusts = [];
let trustsFilter = 'all';
let trustsSearch = '';

async function loadOUs() {
  if (!state.connected) {
    addLog('OUs: domain connection required', 'warn');
    return;
  }
  document.getElementById('ous-loading').style.display = 'flex';
  document.getElementById('o-table-body').innerHTML = '';
  closeOUDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/ous`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load OUs');

    ousData = data.ous || data.organizational_units || [];
    document.getElementById('nav-ous-count').textContent = ousData.length;
    document.getElementById('ous-meta').textContent =
      `${ousData.length} OUs · domain: ${(state.domain||'').toUpperCase()}`;
    renderOUs();
    addLog(`OUs loaded: ${ousData.length} organizational units enumerated`, 'ok');
  } catch (err) {
    addLog(`OUs: ${err.message}`, 'err');
    document.getElementById('o-table-body').innerHTML =
      `<div class="o-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('ous-loading').style.display = 'none';
  }
}

function renderOUs() {
  const body = document.getElementById('o-table-body');
  let list = ousData;

  if (ousSearch) {
    list = list.filter(ou =>
      (ou.name || '').toLowerCase().includes(ousSearch) ||
      (ou.path || '').toLowerCase().includes(ousSearch) ||
      (ou.description || '').toLowerCase().includes(ousSearch)
    );
  }

  if (ousFilter === 'gpo') {
    list = list.filter(ou => !!ou.has_gpo_links);
  }
  if (ousFilter === 'inheritance') {
    list = list.filter(ou => !!ou.inheritance_blocked);
  }
  if (ousFilter === 'permissions') {
    list = list.filter(ou => !!ou.delegated_permissions);
  }

  filteredOUs = list;
  body.innerHTML = '';

  if (filteredOUs.length === 0) {
    body.innerHTML = '<div class="o-empty"><p>No matching OUs</p></div>';
    return;
  }

  filteredOUs.forEach(ou => {
    const row = document.createElement('div');
    row.className = 'o-row';
    row.onclick = () => showOUDetail(ou, row);
    
    row.innerHTML = `
      <div class="o-cell o-cell-name">${ou.name}</div>
      <div class="o-cell o-cell-path" title="${ou.path}">${ou.path}</div>
      <div class="o-cell o-cell-desc" title="${ou.description}">${ou.description || '—'}</div>
      <div class="o-cell o-cell-managed" title="${ou.managed_by}">${ou.managed_by || '—'}</div>
    `;
    
    body.appendChild(row);
  });
}

function filterOUs() {
  ousSearch = (document.getElementById('ous-search').value || '').toLowerCase();
  renderOUs();
}

function setOUFilter(filter, btn) {
  ousFilter = filter;
  document.querySelectorAll('#ou-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderOUs();
}

function showOUDetail(ou, row) {
  document.querySelectorAll('.o-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  const ouName = (ou.name || 'OU');
  const ouPath = (ou.path || '—');
  const gpoLinks = Array.isArray(ou.gpo_links) ? ou.gpo_links : [];

  document.getElementById('od-avatar').textContent = ouName.slice(0, 2).toUpperCase();
  document.getElementById('od-name').textContent = ouName;
  document.getElementById('od-dn').textContent = ouPath;

  const detailBody = document.getElementById('ou-detail-body');
  detailBody.innerHTML = '';

  detailBody.innerHTML += detailSection('OU Identity', [
    ['Name', ouName, 'accent'],
    ['Type', ou.type || 'organizationalUnit', ''],
    ['Path', ouPath, ou.path ? '' : 'dim'],
    ['Description', ou.description || '—', ou.description ? '' : 'dim'],
    ['Managed By', ou.managed_by || '—', ou.managed_by ? '' : 'dim'],
  ]);

  detailBody.innerHTML += detailSection('Security & Policy', [
    ['GPO Linked', ou.has_gpo_links ? 'Yes' : 'No', ou.has_gpo_links ? 'accent' : 'dim'],
    ['Inheritance Blocked', ou.inheritance_blocked ? 'Yes' : 'No', ou.inheritance_blocked ? 'amber' : 'green'],
    ['Delegated Permissions', ou.delegated_permissions ? 'Yes' : 'No', ou.delegated_permissions ? 'red' : 'dim'],
  ]);

  detailBody.innerHTML += detailSection('Timestamps', [
    ['Created', fmtDate(ou.created), ou.created ? '' : 'dim'],
    ['Modified', fmtDate(ou.modified), ou.modified ? '' : 'dim'],
  ]);

  const gpoLinksHtml = gpoLinks.length > 0
    ? gpoLinks.map(g => `<div class="group-item">${g}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  detailBody.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">Linked GPOs (${gpoLinks.length})</div>
      <div class="spn-list">${gpoLinksHtml}</div>
    </div>`;

  document.getElementById('ou-detail').style.display = 'flex';
}

function closeOUDetail() {
  document.getElementById('ou-detail').style.display = 'none';
  document.querySelectorAll('.o-row').forEach(r => r.classList.remove('selected'));
}

async function loadGPOs() {
  if (!state.connected) {
    addLog('GPOs: domain connection required', 'warn');
    return;
  }
  document.getElementById('gpos-loading').style.display = 'flex';
  document.getElementById('g-table-body').innerHTML = '';
  closeGPODetail();

  try {
    const resp = await fetch(`${API_BASE}/api/gpo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load GPOs');

    gposData = data.gpos || [];
    document.getElementById('nav-gpo-count').textContent = gposData.length;
    document.getElementById('gpos-meta').textContent =
      `${gposData.length} GPOs · domain: ${(state.domain||'').toUpperCase()}`;
    renderGPOs();
    addLog(`GPOs loaded: ${gposData.length} group policy objects enumerated`, 'ok');
  } catch (err) {
    addLog(`GPOs: ${err.message}`, 'err');
    document.getElementById('g-table-body').innerHTML =
      `<div class="g-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('gpos-loading').style.display = 'none';
  }
}

function renderGPOs() {
  const body = document.getElementById('g-table-body');
  let list = gposData;

  if (gposSearch) {
    list = list.filter(gpo =>
      (gpo.name || '').toLowerCase().includes(gposSearch) ||
      (gpo.display_name || '').toLowerCase().includes(gposSearch)
    );
  }

  if (gposFilter === 'vulnerable') {
    list = list.filter(gpo => !!gpo.vulnerable);
  }
  if (gposFilter === 'links') {
    list = list.filter(gpo => (gpo.linked_count || 0) > 0);
  }
  if (gposFilter === 'settings') {
    list = list.filter(gpo => !!gpo.has_settings_markers);
  }

  filteredGPOs = list;
  body.innerHTML = '';

  if (filteredGPOs.length === 0) {
    body.innerHTML = '<div class="g-empty"><p>No matching GPOs</p></div>';
    return;
  }
  
  filteredGPOs.forEach(gpo => {
    const row = document.createElement('div');
    row.className = 'g-row';
    row.onclick = () => showGPODetail(gpo, row);
    
    row.innerHTML = `
      <div class="g-cell g-cell-name">${gpo.name}</div>
      <div class="g-cell g-cell-display" title="${gpo.display_name}">${gpo.display_name}</div>
      <div class="g-cell g-cell-status">${gpo.version || '0'}</div>
      <div class="g-cell g-cell-owner" title="${gpo.modified}">${gpo.modified || '—'}</div>
    `;
    
    body.appendChild(row);
  });
}

function filterGPOs() {
  gposSearch = (document.getElementById('gpo-search').value || '').toLowerCase();
  renderGPOs();
}

function setGPOFilter(filter, btn) {
  gposFilter = filter;
  document.querySelectorAll('#gpo-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderGPOs();
}

function showGPODetail(gpo, row) {
  document.querySelectorAll('.g-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  const gpoName = gpo.name || 'GPO';
  const gpoDisplay = gpo.display_name || gpoName;
  const linkedContainers = Array.isArray(gpo.linked_containers) ? gpo.linked_containers : [];

  document.getElementById('gd-avatar').textContent = gpoName.slice(0, 2).toUpperCase();
  document.getElementById('gd-name').textContent = gpoDisplay;
  document.getElementById('gd-dn').textContent = gpo.guid || '—';

  const detailBody = document.getElementById('gpo-detail-body');
  detailBody.innerHTML = '';

  detailBody.innerHTML += detailSection('GPO Identity', [
    ['Name', gpoName, 'accent'],
    ['Display Name', gpoDisplay, ''],
    ['GUID', gpo.guid || '—', gpo.guid ? '' : 'dim'],
    ['Path', gpo.path || '—', gpo.path ? '' : 'dim'],
  ]);

  detailBody.innerHTML += detailSection('Risk & Linkage', [
    ['Vulnerable', gpo.vulnerable ? 'Yes' : 'No', gpo.vulnerable ? 'red' : 'green'],
    ['Linked Containers', gpo.linked_count || 0, (gpo.linked_count || 0) > 0 ? 'accent' : 'dim'],
    ['Settings Markers', gpo.has_settings_markers ? 'Yes' : 'No', gpo.has_settings_markers ? 'amber' : 'dim'],
  ]);

  detailBody.innerHTML += detailSection('Version & Timestamps', [
    ['Version', gpo.version || 0, ''],
    ['User Version', gpo.user_version || 0, ''],
    ['Computer Version', gpo.computer_version || 0, ''],
    ['Created', fmtDate(gpo.created), gpo.created ? '' : 'dim'],
    ['Modified', fmtDate(gpo.modified), gpo.modified ? '' : 'dim'],
  ]);

  const linksHtml = linkedContainers.length > 0
    ? linkedContainers.map(link => `<div class="group-item">${link}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  detailBody.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">Linked Containers (${linkedContainers.length})</div>
      <div class="spn-list">${linksHtml}</div>
    </div>`;

  document.getElementById('gpo-detail').style.display = 'flex';
}

function closeGPODetail() {
  document.getElementById('gpo-detail').style.display = 'none';
  document.querySelectorAll('.g-row').forEach(r => r.classList.remove('selected'));
}

async function loadGroups() {
  if (!state.connected) {
    addLog('Groups: domain connection required', 'warn');
    return;
  }
  document.getElementById('groups-loading').style.display = 'flex';
  document.getElementById('gr-table-body').innerHTML = '';
  closeGroupDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/groups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load groups');

    groupsData = data.groups || [];
    document.getElementById('nav-groups-count').textContent = groupsData.length;
    document.getElementById('groups-meta').textContent = `${groupsData.length} groups · domain: ${(state.domain || '').toUpperCase()}`;
    renderGroups();
    addLog(`Groups loaded: ${groupsData.length} groups enumerated`, 'ok');
  } catch (err) {
    addLog(`Groups: ${err.message}`, 'err');
    document.getElementById('gr-table-body').innerHTML = `<div class="gr-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('groups-loading').style.display = 'none';
  }
}

function setGroupFilter(filter, btn) {
  groupsFilter = filter;
  document.querySelectorAll('#groups-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderGroups();
}

function filterGroups() {
  groupsSearch = (document.getElementById('groups-search').value || '').toLowerCase();
  renderGroups();
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function toggleGroupMembers(btn, membersRowId) {
  const row = document.getElementById(membersRowId);
  if (!row) return;
  const isOpen = row.style.display === 'block';
  row.style.display = isOpen ? 'none' : 'block';
  btn.classList.toggle('open', !isOpen);
}

function renderGroups() {
  const body = document.getElementById('gr-table-body');
  body.innerHTML = '';

  let list = groupsData;
  if (groupsSearch) {
    list = list.filter(g =>
      (g.name || '').toLowerCase().includes(groupsSearch) ||
      (g.sam_name || '').toLowerCase().includes(groupsSearch) ||
      (g.description || '').toLowerCase().includes(groupsSearch)
    );
  }
  if (groupsFilter === 'privileged') {
    list = list.filter(g => g.is_privileged || g.is_protected);
  }
  if (groupsFilter === 'empty') {
    list = list.filter(g => g.is_empty);
  }
  if (groupsFilter === 'nested') {
    list = list.filter(g => g.is_nested);
  }

  if (list.length === 0) {
    body.innerHTML = '<div class="gr-empty"><p>No matching groups</p></div>';
    return;
  }

  list.forEach(group => {
    const row = document.createElement('div');
    row.className = 'gr-row';
    row.onclick = () => showGroupDetail(group, row);
    const members = Array.isArray(group.member_users) ? group.member_users : [];
    const membersCount = Number.isFinite(group.member_users_count) ? group.member_users_count : members.length;
    const membersRowId = `gr-members-${Math.random().toString(36).slice(2)}`;
    row.innerHTML = `
      <div class="gr-cell gr-cell-name">${group.name || '—'}</div>
      <div class="gr-cell gr-cell-type">${group.group_type || '—'}</div>
      <div class="gr-cell gr-cell-members">
        <button class="gr-members-toggle" type="button" onclick="event.stopPropagation();toggleGroupMembers(this, '${membersRowId}')" title="Show members">
          <span class="gr-arrow">▾</span>
          <span>${membersCount}</span>
        </button>
      </div>
      <div class="gr-cell gr-cell-protected">${group.is_protected ? '<span class="flag yes-admin">YES</span>' : '<span class="flag no">—</span>'}</div>
    `;
    body.appendChild(row);

    const membersRow = document.createElement('div');
    membersRow.id = membersRowId;
    membersRow.className = 'gr-members-row';
    membersRow.style.display = 'none';
    if (members.length === 0) {
      membersRow.innerHTML = '<div class="gr-members-empty">No user members found in this group.</div>';
    } else {
      membersRow.innerHTML = `
        <div class="gr-members-head">
          <span>Member User</span>
          <span>SID</span>
        </div>
        ${members.map(m => `
          <div class="gr-members-item">
            <span class="gr-member-name">${escapeHtml(m.name || m.dn || '—')}</span>
            <span class="gr-member-sid">${escapeHtml(m.sid || '—')}</span>
          </div>
        `).join('')}
      `;
    }
    body.appendChild(membersRow);
  });
}

function showGroupDetail(group, row) {
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('grd-avatar').textContent = (group.name || 'GR').slice(0, 2).toUpperCase();
  document.getElementById('grd-name').textContent = group.name || '—';
  document.getElementById('grd-dn').textContent = group.dn || '—';

  const detailBody = document.getElementById('group-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('Group', [
    ['Name', group.name || '—', 'accent'],
    ['sAMAccountName', group.sam_name || '—', group.sam_name ? '' : 'dim'],
    ['Type', group.group_type || '—', ''],
    ['Members', group.member_count ?? 0, ''],
  ]);

  detailBody.innerHTML += detailSection('Security', [
    ['Privileged', group.is_privileged ? 'Yes' : 'No', group.is_privileged ? 'red' : ''],
    ['Protected', group.is_protected ? 'Yes' : 'No', group.is_protected ? 'amber' : ''],
    ['Empty', group.is_empty ? 'Yes' : 'No', group.is_empty ? 'dim' : ''],
    ['Nested', group.is_nested ? 'Yes' : 'No', group.is_nested ? 'accent' : ''],
    ['Managed By', group.managed_by || '—', group.managed_by ? '' : 'dim'],
    ['SID', group.sid || '—', group.sid ? '' : 'dim'],
    ['Description', group.description || '—', group.description ? '' : 'dim'],
  ]);

  document.getElementById('group-detail').style.display = 'flex';
}

function closeGroupDetail() {
  document.getElementById('group-detail').style.display = 'none';
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
}

async function loadTrusts() {
  if (!state.connected) {
    addLog('Trusts: domain connection required', 'warn');
    return;
  }
  document.getElementById('trusts-loading').style.display = 'flex';
  document.getElementById('tr-table-body').innerHTML = '';
  closeTrustDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/trusts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load trusts');

    trustsData = data.trusts || [];
    document.getElementById('nav-trusts-count').textContent = trustsData.length;
    document.getElementById('trusts-meta').textContent = `${trustsData.length} trusts · domain: ${(state.domain || '').toUpperCase()}`;
    renderTrusts();
    addLog(`Trusts loaded: ${trustsData.length} trust relationships enumerated`, 'ok');
  } catch (err) {
    addLog(`Trusts: ${err.message}`, 'err');
    document.getElementById('tr-table-body').innerHTML = `<div class="tr-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('trusts-loading').style.display = 'none';
  }
}

function filterTrusts() {
  trustsSearch = (document.getElementById('trusts-search').value || '').toLowerCase();
  renderTrusts();
}

function setTrustFilter(filter, btn) {
  trustsFilter = filter;
  document.querySelectorAll('#trusts-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderTrusts();
}

function renderTrusts() {
  const body = document.getElementById('tr-table-body');
  body.innerHTML = '';

  let list = trustsData;
  if (trustsSearch) {
    list = list.filter(t =>
      (t.name || '').toLowerCase().includes(trustsSearch) ||
      (t.partner || '').toLowerCase().includes(trustsSearch) ||
      (t.direction || '').toLowerCase().includes(trustsSearch)
    );
  }

  if (trustsFilter === 'inbound') {
    list = list.filter(t => !!t.inbound);
  }
  if (trustsFilter === 'outbound') {
    list = list.filter(t => !!t.outbound);
  }
  if (trustsFilter === 'transitive') {
    list = list.filter(t => !!t.transitive);
  }
  if (trustsFilter === 'forest') {
    list = list.filter(t => !!t.forest);
  }

  if (list.length === 0) {
    body.innerHTML = '<div class="tr-empty"><p>No matching trusts</p></div>';
    return;
  }

  list.forEach(trust => {
    const row = document.createElement('div');
    row.className = 'tr-row';
    row.onclick = () => showTrustDetail(trust, row);
    row.innerHTML = `
      <div class="tr-cell tr-cell-name">${trust.name || '—'}</div>
      <div class="tr-cell tr-cell-partner">${trust.partner || '—'}</div>
      <div class="tr-cell tr-cell-direction">${trust.direction || '—'}</div>
      <div class="tr-cell tr-cell-type">${trust.trust_type || '—'}</div>
    `;
    body.appendChild(row);
  });
}

function showTrustDetail(trust, row) {
  document.querySelectorAll('.tr-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('trd-avatar').textContent = (trust.name || 'TR').slice(0, 2).toUpperCase();
  document.getElementById('trd-name').textContent = trust.name || '—';
  document.getElementById('trd-dn').textContent = trust.dn || '—';

  const detailBody = document.getElementById('trust-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('Trust', [
    ['Name', trust.name || '—', 'accent'],
    ['Partner', trust.partner || '—', trust.partner ? '' : 'dim'],
    ['Direction', trust.direction || '—', ''],
    ['Type', trust.trust_type || '—', ''],
  ]);

  detailBody.innerHTML += detailSection('Attributes', [
    ['Flat Name', trust.flat_name || '—', trust.flat_name ? '' : 'dim'],
    ['Inbound', trust.inbound ? 'Yes' : 'No', trust.inbound ? 'green' : ''],
    ['Outbound', trust.outbound ? 'Yes' : 'No', trust.outbound ? 'accent' : ''],
    ['Transitive', trust.transitive ? 'Yes' : 'No', trust.transitive ? 'amber' : ''],
    ['Forest', trust.forest ? 'Yes' : 'No', trust.forest ? 'red' : ''],
    ['Attributes', trust.attributes ?? 0, ''],
    ['SID', trust.sid || '—', trust.sid ? '' : 'dim'],
  ]);

  document.getElementById('trust-detail').style.display = 'flex';
}

function closeTrustDetail() {
  document.getElementById('trust-detail').style.display = 'none';
  document.querySelectorAll('.tr-row').forEach(r => r.classList.remove('selected'));
}

/* ══════════ PENTEST PANEL ══════════ */

function updatePentestCounts() {
  if (!usersData.length) return;

  const spnUsers    = usersData.filter(u => u.spn && u.spn.length > 0);
  const asrepUsers  = usersData.filter(u => u.asrep);
  const activeUsers = usersData.filter(u => !u.disabled);

  const set = (id, count) => {
    const el = document.getElementById(id);
    if (el) el.textContent = count;
  };

  set('pt-kerb-count',   spnUsers.length);
  set('pt-asrep-count',  asrepUsers.length);
  set('pt-spray-count',  activeUsers.length);
  set('pt-silver-count', spnUsers.length);
  set('pt-brute-count',  activeUsers.length);
}

/* ── Stub functions — funksionallığı özün əlavə et ── */
function runKerberoasting()  { addLog('Kerberoasting: not implemented yet', 'warn'); }
function runASREPRoasting()  { addLog('AS-REP Roasting: not implemented yet', 'warn'); }
function runSilverTicket()   { addLog('Silver Ticket: not implemented yet', 'warn'); }
function runBruteForce()     { addLog('Brute Force: not implemented yet', 'warn'); }
/* ══════════ COMPUTERS ══════════ */
let computersData = [];
let computersFilter = 'all';
let computersSearch = '';

async function loadComputers() {
  if (!state.connected) {
    addLog('Computers: domain connection required', 'warn');
    return;
  }
  document.getElementById('computers-loading').style.display = 'flex';
  document.getElementById('c-table-body').innerHTML = '';
  closeComputerDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/computers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload())
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load computers');

    computersData = data.computers;
    document.getElementById('nav-computers-count').textContent = computersData.length;
    document.getElementById('computers-meta').textContent =
      `${computersData.length} computers · domain: ${(state.domain||'').toUpperCase()}`;
    renderComputers();
    addLog(`Computers loaded: ${computersData.length} systems enumerated`, 'ok');
  } catch (err) {
    addLog(`Computers: ${err.message}`, 'err');
    document.getElementById('c-table-body').innerHTML =
      `<div class="c-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('computers-loading').style.display = 'none';
  }
}

function setComputerFilter(f, btn) {
  computersFilter = f;
  document.querySelectorAll('#comp-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderComputers();
}

function filterComputers() {
  computersSearch = document.getElementById('computers-search').value.toLowerCase();
  renderComputers();
}

function renderComputers() {
  const body = document.getElementById('c-table-body');
  body.innerHTML = '';

  let list = computersData;

  // text filter
  if (computersSearch) {
    list = list.filter(c =>
      (c.computer_name || '').toLowerCase().includes(computersSearch) ||
      (c.dns_name || '').toLowerCase().includes(computersSearch)
    );
  }

  // chip filter
  if (computersFilter === 'unconstrained') list = list.filter(c => c.unconstrained_delegation);
  if (computersFilter === 'constrained')   list = list.filter(c => c.constrained_delegation);
  if (computersFilter === 'stale')         list = list.filter(c => c.is_stale);
  if (computersFilter === 'dc')            list = list.filter(c => c.is_domain_controller);
  if (computersFilter === 'legacy_os') {
    list = list.filter(c => {
      const os = (c.os || '').toLowerCase();
      return os.includes('2003') || os.includes('2008') || os.includes('2012') || os.includes('xp') || os.includes('vista');
    });
  }

  if (list.length === 0) {
    body.innerHTML = '<div class="c-empty"><p>No matching computers</p></div>';
    return;
  }

  list.forEach(c => {
    const row = document.createElement('div');
    row.className = 'c-row';
    row.onclick = () => showComputerDetail(c, row);
    row.innerHTML = `
      <div class="c-name">${c.computer_name || '—'}</div>
      <div class="c-os">${c.os || '—'}</div>
      <div class="c-flag-cell">
        ${c.is_server ? '<span class="flag yes-ok">SRV</span>' : (c.is_workstation ? '<span class="flag yes-ok">WS</span>' : '<span class="flag no">—</span>')}
      </div>
      <div class="c-flag-cell">
        ${c.has_spn ? '<span class="flag yes-spn">✓</span>' : '<span class="flag no">—</span>'}
      </div>
      <div class="c-flag-cell">
        ${c.disabled ? '<span class="flag yes-dis">✕</span>' : '<span class="flag yes-ok">✓</span>'}
      </div>
    `;
    body.appendChild(row);
  });
}

function showComputerDetail(c, row) {
  document.querySelectorAll('.c-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('computer-detail').style.display = 'flex';
  document.getElementById('cd-avatar').textContent = (c.computer_name || '?').charAt(0).toUpperCase();
  document.getElementById('cd-name').textContent = c.computer_name || '—';
  document.getElementById('cd-dn').textContent = c.dn || '—';

  const body = document.getElementById('computer-detail-body');
  body.innerHTML = '';

  // Identity section
  body.innerHTML += detailSection('Computer', [
    ['Name',         c.computer_name || '—',  'accent'],
    ['DNS',          c.dns_name || '—',        c.dns_name ? '' : 'dim'],
    ['OS',           c.os || '—',              c.os ? '' : 'dim'],
    ['OS Version',   c.os_version || '—',      c.os_version ? '' : 'dim']
  ]);

  // Flags section
  body.innerHTML += detailSection('Flags', [
    ['Server',              c.is_server ? '✓' : '✕', c.is_server ? 'green' : 'dim'],
    ['Workstation',         c.is_workstation ? '✓' : '✕', c.is_workstation ? 'green' : 'dim'],
    ['Unconstrained Delegation', c.unconstrained_delegation ? '✓' : '✕', c.unconstrained_delegation ? 'red' : 'dim'],
    ['Constrained Delegation',   c.constrained_delegation ? '✓' : '✕', c.constrained_delegation ? 'amber' : 'dim'],
    ['Domain Controller',   c.is_domain_controller ? '✓' : '✕', c.is_domain_controller ? 'accent' : 'dim'],
    ['Stale',               c.is_stale ? '✓' : '✕', c.is_stale ? 'amber' : 'green'],
    ['Disabled',            c.disabled ? '✓' : '✕', c.disabled ? 'red' : 'green'],
    ['SPN Count',           c.spn && c.spn.length > 0 ? c.spn.length : '0', c.spn && c.spn.length > 0 ? 'accent' : 'dim']
  ]);

  // SPN section
  if (c.spn && c.spn.length > 0) {
    body.innerHTML += `<div style="padding:12px 0 8px; font-family:var(--head); font-size:10px; letter-spacing:1.5px; text-transform:uppercase; color:var(--text-dim); margin-top:8px;">Service Principals</div>`;
    c.spn.forEach(s => {
      body.innerHTML += `<div style="padding:4px 0; font-size:10px; color:var(--text-sec); font-family:var(--mono);">${s}</div>`;
    });
  }
}

function closeComputerDetail() {
  document.getElementById('computer-detail').style.display = 'none';
  document.querySelectorAll('.c-row').forEach(r => r.classList.remove('selected'));
}
/* ── ENTER TO CONNECT ── */
['f-domain','f-ip','f-user','f-pass','f-hash'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') doConnect();
  });
});
