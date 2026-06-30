/* ═══════════════════════════════════════════════════
   02-ui.js
   Navigation, tab switching, form controls,
   shell terminal, API ping, protocol probing.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ── Mode / Protocol selectors ── */
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
  ['ldap','rpc','agent','beacon'].forEach(x => {
    document.getElementById(`proto-${x}`).className = 'proto-btn' + (x === p ? ' selected' : '');
  });
  document.getElementById('sb-proto').textContent = p.toUpperCase();
}

/* ── Auth input lock (password ↔ hash mutual exclusion) ── */
function updateAuthInputLockState(source = '') {
  const passEl = document.getElementById('f-pass');
  const hashEl = document.getElementById('f-hash');
  if (!passEl || !hashEl) return;

  const passWrap   = passEl.closest('.input-wrap');
  const hashWrap   = hashEl.closest('.input-wrap');
  const passEyeBtn = passWrap?.querySelector('.eye-btn');
  const hashEyeBtn = hashWrap?.querySelector('.eye-btn');

  if (source === 'pass' && passEl.value.trim() && hashEl.value.trim()) hashEl.value = '';
  if (source === 'hash' && hashEl.value.trim() && passEl.value.trim()) passEl.value = '';

  const finalHasPass = !!passEl.value.trim();
  const finalHasHash = !!hashEl.value.trim();

  hashEl.disabled = finalHasPass; passEl.disabled = finalHasHash;
  hashEl.readOnly = finalHasPass; passEl.readOnly = finalHasHash;
  if (hashEyeBtn) hashEyeBtn.disabled = finalHasPass;
  if (passEyeBtn) passEyeBtn.disabled = finalHasHash;
  if (hashWrap) hashWrap.classList.toggle('auth-locked', finalHasPass);
  if (passWrap) passWrap.classList.toggle('auth-locked', finalHasHash);
}

function togglePass() {
  const f = document.getElementById('f-pass');
  if (!f || f.disabled || f.readOnly) return;
  f.type = f.type === 'password' ? 'text' : 'password';
}

function toggleHash() {
  const f = document.getElementById('f-hash');
  if (!f || f.disabled || f.readOnly) return;
  f.type = f.type === 'password' ? 'text' : 'password';
}

/* ── Form clear ── */
function clearForm() {
  ['f-domain','f-ip','f-dc','f-user','f-pass','f-hash'].forEach(id => {
    const el = document.getElementById(id);
    el.value = '';
    el.classList.remove('error');
  });
  ['err-domain','err-ip','err-user','err-pass','err-hash'].forEach(id =>
    document.getElementById(id).classList.remove('show')
  );
  updateAuthInputLockState();
  addLog('Form cleared', 'info');
}

/* ── Login / disconnect screen reset ── */
function showLoginScreen() {
  switchMainTab('connect');
  ['tab-users','tab-computers','tab-ous','tab-gpo','tab-groups','tab-trusts','tab-acl'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  document.querySelectorAll('.nav-item[id^="nav-"]').forEach(el => el.classList.remove('active'));

  if (!state.connected) {
    state._pass = null; state._hash = null;
    state._zipOffline = false;
    if (typeof ZIP_IMPORT !== 'undefined') { ZIP_IMPORT.active = false; ZIP_IMPORT.files = []; }
    usersData = []; computersData = []; ousData = []; gposData = [];
    groupsData = []; trustsData = []; aclData = []; usersMeta = {};
    enumCacheLoaded = { users: false, computers: false, ous: false, gpos: false, groups: false, trusts: false, acl: false };

    setConnState('disconnected');

    ['nav-users-count','nav-computers-count','nav-ous-count','nav-gpo-count',
     'nav-groups-count','nav-trusts-count','nav-acl-count'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '—';
    });

    ['stat-domain','stat-dc','stat-user','stat-proto','stat-os','stat-level',
     'stat-kerb','stat-ntlm','stat-smb','stat-latency'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = '—'; el.className = 'stat-value dim'; }
    });
    document.getElementById('stat-conn').textContent = 'OFFLINE';
    document.getElementById('stat-conn').className   = 'stat-value dim';
    document.getElementById('api-ping-bar').style.width = '0%';

    ['cnt-users','cnt-comp','cnt-groups','cnt-ous','cnt-gpos','cnt-trusts'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = '—'; el.className = 'stat-mini-val'; }
    });

    ['f-domain','f-ip','f-dc','f-user','f-pass','f-hash'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.value = ''; el.classList.remove('error'); }
    });
    updateAuthInputLockState();
    ['err-domain','err-ip','err-user','err-pass','err-hash'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.remove('show');
    });

    addLog('Session terminated. Ready for new connection.', 'warn');
    closeSecurityStatusPanel();
  } else {
    addLog('Connect tab opened while session remains active.', 'info');
  }
}

/* ── Main tab switching ── */
function switchMainTab(tab, btn) {
  const comingSoonTabs = new Set(['powershell', 'enumeration', 'reconnaissance']);
  if (comingSoonTabs.has(tab)) return;
  if (tab === 'enumeration' && !state.connected) return;
  if (tab !== 'decision-engine' && typeof restoreDecisionTreeHost === 'function') {
    restoreDecisionTreeHost();
  }

  const sidebarEl = document.querySelector('.sidebar');
  const statusbarEl = document.querySelector('.statusbar');
  const rightPanelEl = document.querySelector('.right-panel');
  if (tab === 'decision-engine') {
    document.body.classList.add('decision-tree-mode');
    if (sidebarEl) sidebarEl.style.display = 'none';
    if (statusbarEl) statusbarEl.style.display = 'none';
    if (rightPanelEl) rightPanelEl.style.display = 'none';
  } else {
    document.body.classList.remove('decision-tree-mode');
    if (sidebarEl) sidebarEl.style.display = '';
    if (statusbarEl) statusbarEl.style.display = '';
    if (rightPanelEl) rightPanelEl.style.display = '';
  }

  const allTabs = ['connect','powershell','enumeration','reconnaissance',
                   'users','computers','ous','gpo','groups','trusts','acl'];
  allTabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    if (el) el.style.display = 'none';
  });
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
          term.innerHTML = '<div class="shell-line shell-warn">Shell unavailable: connect with Local session first.</div>';
        } else if (state.protocol !== 'local') {
          term.innerHTML = '<div class="shell-line shell-warn">Shell is only available for Local sessions.</div>';
      } else if (term.children.length === 0 || term.textContent.includes('Connect first')) {
        term.innerHTML = '<div class="shell-line shell-info">Ready. Enter commands and press Enter.</div>';
      }
    }
    updateShellTabState();
    return;
  }

  if (tab === 'decision-engine') {
    openDecisionEnginePage();
    return;
  }

  if (tab === 'users') {
    document.getElementById('tab-users').style.display = '';
    if (!state.connected && !state._zipOffline) { document.getElementById('u-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; }
    else loadUsers();
    return;
  }
  if (tab === 'computers') {
    document.getElementById('tab-computers').style.display = '';
    if (!state.connected && !state._zipOffline) { document.getElementById('c-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; }
    else loadComputers();
    return;
  }
  if (tab === 'enumeration') {
    document.getElementById('tab-enumeration').style.display = '';
    refreshEnumerationProtocolPanel();
    resetEnumerationProtocolStats();
    const titleEl = document.querySelector('#enumeration-placeholder .enumeration-placeholder-title');
    const copyEl  = document.querySelector('#enumeration-placeholder .enumeration-placeholder-copy');
    if (titleEl && copyEl) {
      if (state.connected) {
        titleEl.textContent = 'Protocol Hierarchy';
        copyEl.textContent  = 'Protocol checks are manual. Click Scan to start probing.';
      } else {
        titleEl.textContent = 'Connect first to unlock Enumeration';
        copyEl.textContent  = 'Enumeration features appear here once a Local or Remote session is active.';
      }
    }
    return;
  }
  if (tab === 'reconnaissance') {
    document.getElementById('tab-reconnaissance').style.display = '';
    return;
  }

  document.getElementById('tab-connect').style.display = '';
  updateShellTabState();
}

function openDecisionEnginePage() {
  const targetUrl = new URL('Decision Engine/Main/Oxsium-Decision.html', window.location.href).href;
  const page = window.open(targetUrl, '_blank', 'noopener,noreferrer');
  if (page) {
    page.focus();
    return;
  }

  const fallbackLink = document.createElement('a');
  fallbackLink.href = targetUrl;
  fallbackLink.target = '_blank';
  fallbackLink.rel = 'noopener noreferrer';
  fallbackLink.click();

  if (typeof showToast === 'function') {
    showToast('Decision Engine page could not be opened. Your browser may be blocking popups.', 'error');
  }
}

/* ── AD object sub-tab switching ── */
function switchTab(tab) {
  const allObjTabs = ['connect','users','computers','ous','gpo','groups','trusts','acl'];
  allObjTabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    if (el) el.style.display = 'none';
  });
  document.querySelectorAll('.nav-item[id^="nav-"]').forEach(el => el.classList.remove('active'));

  const attackTabs = new Set(['users','computers','ous','gpo','groups','trusts','acl']);
  document.getElementById('sidebar-attacks').style.display = attackTabs.has(tab) ? 'flex' : 'none';
  renderAssessmentToolkit(tab);

  /* Helper: true if user can browse AD object tabs (live session OR ZIP offline mode) */
  const _canBrowse = () => state.connected || !!state._zipOffline;

  const tabMap = {
    users:     { el: 'tab-users',     nav: 'nav-users',     load: () => { if (!_canBrowse()) { document.getElementById('u-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; } else loadUsers(); }},
    computers: { el: 'tab-computers', nav: 'nav-computers', load: () => { if (!_canBrowse()) { document.getElementById('c-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; } else loadComputers(); }},
    ous:       { el: 'tab-ous',       nav: 'nav-ous',       load: () => { if (!_canBrowse()) { document.getElementById('o-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; } else loadOUs(); }},
    gpo:       { el: 'tab-gpo',       nav: 'nav-gpo',       load: () => { if (!_canBrowse()) { document.getElementById('g-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; } else loadGPOs(); }},
    groups:    { el: 'tab-groups',    nav: 'nav-groups',    load: () => {
      if (typeof groupsFilter !== 'undefined') groupsFilter = 'all';
      const allChip = document.querySelector('#groups-filter-chips .chip[onclick*="setGroupFilter(\'all\'"]');
      document.querySelectorAll('#groups-filter-chips .chip').forEach(ch => ch.classList.remove('active'));
      if (allChip) allChip.classList.add('active');
      if (!_canBrowse()) {
        document.getElementById('gr-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>';
      } else {
        loadGroups();
      }
    }},
    trusts:    { el: 'tab-trusts',    nav: 'nav-trusts',    load: () => { if (!_canBrowse()) { document.getElementById('tr-empty').innerHTML = '<p>Connect to a domain first or import a ZIP</p>'; } else loadTrusts(); }},
    acl:       { el: 'tab-acl',       nav: 'nav-acl',       load: () => {
      // Reset ACL search fields
      ['acl-search','acl-target-search','acl-principal-search'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      aclSearch = ''; aclTargetSearch = ''; aclPrincipalSearch = '';
      aclFilter = 'all'; aclObjectFilter = 'all';
      const wrap = document.getElementById('acl-filter-chips');
      if (wrap) {
        wrap.querySelectorAll('.chip').forEach(ch => ch.classList.remove('active'));
        const allChip = wrap.querySelector('.chip[data-filter="all"]');
        if (allChip) allChip.classList.add('active');
      }
      renderACLObjectFilters();
      const _aclHasData = _canBrowse() ||
                          (typeof ZIP_IMPORT !== 'undefined' && ZIP_IMPORT.active) ||
                          (typeof aclData !== 'undefined' && aclData.length > 0) ||
                          enumCacheLoaded.acl;
      if (!_aclHasData) {
        document.getElementById('acl-meta').textContent = '—';
        document.getElementById('acl-table-body').innerHTML = '<div class="acl-empty"><p>Connect to a domain first or import a ZIP</p></div>';
      } else {
        loadACLs();
      }
    }},
  };

  const entry = tabMap[tab];
  if (entry) {
    document.getElementById(entry.el).style.display = 'flex';
    document.getElementById(entry.nav).classList.add('active');
    entry.load();
  } else {
    document.getElementById('tab-connect').style.display = '';
  }
}

function openCertificatePanel(btn) {
  if (!state.connected) {
    if (typeof showToast === 'function') showToast('Connect first to view certificate tools', 'info');
    switchMainTab('connect', document.querySelector('.main-tab[data-tab="connect"]'));
    return;
  }

  switchMainTab('connect', document.querySelector('.main-tab[data-tab="connect"]'));

  const certPanel = document.getElementById('cert-panel');
  if (certPanel) {
    certPanel.style.display = 'block';
    certPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  if (btn) {
    document.querySelectorAll('.main-tab').forEach(el => el.classList.remove('active'));
    btn.classList.add('active');
  }
}

function openCertificatePage() {
  const targetUrl = new URL('Certificate Service/Main/Oxsium-Certificate.html', window.location.href).href;
  const page = window.open(targetUrl, '_blank', 'noopener,noreferrer');
  if (page) {
    page.focus();
    return;
  }

  const fallbackLink = document.createElement('a');
  fallbackLink.href = targetUrl;
  fallbackLink.target = '_blank';
  fallbackLink.rel = 'noopener noreferrer';
  fallbackLink.click();

  if (typeof showToast === 'function') {
    showToast('Certificate page could not be opened. Your browser may be blocking popups.', 'error');
  }
}

/* ── Enumeration tab state ── */
function updateEnumerationTabState() {
  const enumBtn = document.querySelector('.main-tab[data-tab="enumeration"]');
  const enumTab = document.getElementById('tab-enumeration');
  if (!enumBtn || !enumTab) return;
  // Enumeration UI is removed/disabled in this build — keep the tab visually disabled.
  enumBtn.disabled = true;
  enumBtn.classList.add('disabled');
  enumBtn.title = 'Coming Soon';
  if (enumTab.style.display !== 'none') switchMainTab('connect');
}

function updateReconnaissanceTabState() {
  const reconBtn = document.querySelector('.main-tab[data-tab="reconnaissance"]');
  if (!reconBtn) return;
  // Reconnaissance tab is always disabled in the UI.
  reconBtn.disabled = true;
  reconBtn.classList.add('disabled');
  reconBtn.title = 'Coming Soon';
}

/* ── Shell terminal ── */
function appendShellOutput(text, type = 'info') {
  const term = document.getElementById('shell-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className   = `shell-line shell-${type}`;
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
  const input   = document.getElementById('shell-input');
  const btn     = document.getElementById('btn-shell-send');
  const enabled = state.connected && state.protocol === 'local';
  if (input) input.disabled = !enabled;
  if (btn)   btn.disabled   = !enabled;
}

async function sendShellCommand() {
  const input = document.getElementById('shell-input');
  const btn   = document.getElementById('btn-shell-send');
  if (!input || !btn) return;
  const command = input.value.trim();
  if (!command) return;
  if (!state.connected) { showToast('Connect first to use the shell', 'error'); return; }

  appendShellOutput(`PS> ${command}`, 'prompt');
  input.value  = '';
  btn.disabled = true;

  try {
    const payload = {
      mode: state.mode, protocol: state.protocol, command,
      domain:   state.domain,
      ip:       document.getElementById('f-ip').value.trim()   || state.dc,
      username: document.getElementById('f-user').value.trim() || state.user,
      password: state._pass || state._hash || '',
      hash:     state._hash || '',
    };
    const resp = await fetch(`${API_BASE}/api/shell`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
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
  if (e.key === 'Enter') { e.preventDefault(); sendShellCommand(); }
}

/* ── Enumeration module selector ── */
function toggleEnumerationModuleList() {
  const list = document.getElementById('enum-module-list');
  if (!list) return;
  list.style.display = list.style.display === 'block' ? 'none' : 'block';
}

function selectEnumerationModule(name, btn) {
  const selected = document.getElementById('enum-selected-name');
  if (selected) selected.textContent = name;
  document.querySelectorAll('#enum-modules-scroll .module-item').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('enum-module-list').style.display = 'none';
}

function setEnumerationOutput(text) {
  const pre = document.getElementById('enum-output-pre');
  if (!pre) return;
  pre.textContent = text || 'No output';
}

async function executeEnumerationModule() {
  if (!state.connected) { showToast('Connect first to run modules', 'error'); return; }
  const selected = document.getElementById('enum-selected-name')?.textContent?.trim() || '';
  if (selected !== 'Local Inventory (C)') {
    setEnumerationOutput(`Module "${selected}" is not implemented yet.`);
    return;
  }
  const btn = document.getElementById('btn-enum-exec');
  if (btn) btn.disabled = true;
  setEnumerationOutput('Running Local Inventory (C)...');
  try {
    const resp = await fetch(`${API_BASE}/api/enumeration/local-inventory`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: state.mode || 'local' }),
    });
    const data = await resp.json();
    setEnumerationOutput((!resp.ok || !data.success) ? (data.error || 'Module execution failed.') : JSON.stringify(data.result || data, null, 2));
  } catch (err) {
    setEnumerationOutput(err.message || 'Module request failed.');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ── Misc / Credential / Certificate scan panels ── */
function selectMiscMisconfig(name, btn) {
  const el = document.getElementById('misc-selected-name');
  if (el) el.textContent = name;
  document.querySelectorAll('#misc-misconfig-tabs .misc-tab-item').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

async function runMiscManualScan() {
  if (!state.connected) { showToast('Manual scan requires an active connection', 'error'); return; }
  const selected = document.getElementById('misc-selected-name')?.textContent?.trim() || 'noPAC';
  const btn = document.getElementById('btn-misc-scan');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  try {
    addLog(`[MISC] Manual scan started: ${selected}`, 'info');
    await new Promise(resolve => setTimeout(resolve, 450));
    showToast(`${selected} manual scan started`, 'ok');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Manual Scan'; }
  }
}

function selectCredentialHarvesting(name, btn) {
  const el = document.getElementById('cred-selected-name');
  if (el) el.textContent = name;
  document.querySelectorAll('#cred-harvest-tabs .cred-tab-item').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
  addLog(`[CRED] Selected module: ${name}`, 'info');
}

async function runCredentialHarvestScan() {
  if (!state.connected) { showToast('Scan requires an active connection', 'error'); return; }
  const selected = document.getElementById('cred-selected-name')?.textContent?.trim() || 'SAM & SYSTEM Dumping';
  const btn = document.getElementById('btn-cred-scan');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  try {
    addLog(`[CRED] Scan started: ${selected}`, 'info');
    await new Promise(resolve => setTimeout(resolve, 450));
    showToast(`${selected} scan started`, 'ok');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan'; }
  }
}

function selectCertificateMisconfig(name, btn) {
  const el = document.getElementById('cert-selected-name');
  if (el) el.textContent = name;
  document.querySelectorAll('#cert-misconfig-tabs .cert-tab-item').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
  addLog(`[CERT] Selected module: ${name}`, 'info');
}

async function runCertificateMisconfigScan() {
  if (!state.connected) { showToast('Scan requires an active connection', 'error'); return; }
  const selected = document.getElementById('cert-selected-name')?.textContent?.trim() || 'ESC1 - Misconfigured Template';
  const btn = document.getElementById('btn-cert-scan');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  try {
    addLog(`[CERT] Scan started: ${selected}`, 'info');
    await new Promise(resolve => setTimeout(resolve, 450));
    showToast(`${selected} scan started`, 'ok');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan'; }
  }
}

/* ── Enumeration protocol panel ── */
const TOOLS_PROBE_KEYS = [
  'dns','rpc','telnet','ftp','ssh','smtp','imap','pop3','ldap',
  'http','tftp','snmp','ntp','dhcp','radius','rdp',
  'mysql','mssql','postgresql','oracle','mongodb',
];

function refreshEnumerationProtocolPanel() {
  const panel    = document.getElementById('enum-proto-panel');
  const miscPanel= document.getElementById('misc-panel');
  const credPanel= document.getElementById('cred-panel');
  const certPanel= document.getElementById('cert-panel');
  if (!panel) return;

  if (!state.connected) {
    panel.style.display = 'none';
    if (miscPanel) miscPanel.style.display = 'none';
    if (credPanel) credPanel.style.display = 'none';
    if (certPanel) certPanel.style.display = 'none';
    return;
  }

  panel.style.display = 'block';
  if (miscPanel) miscPanel.style.display = 'block';
  if (credPanel) credPanel.style.display = 'block';
  if (certPanel) certPanel.style.display = 'block';

  const copyValue = (fromId, toId) => {
    const from = document.getElementById(fromId);
    const to   = document.getElementById(toId);
    if (!to) return;
    to.textContent = from?.textContent?.trim() || '—';
    const cls = String(from?.className || '');
    if      (cls.includes('green')) to.className = 'enum-proto-value green';
    else if (cls.includes('amber')) to.className = 'enum-proto-value amber';
    else if (cls.includes('red'))   to.className = 'enum-proto-value red';
    else                            to.className = 'enum-proto-value dim';
  };
  copyValue('stat-kerb', 'enum-stat-kerb');
  copyValue('stat-ntlm', 'enum-stat-ntlm');
  copyValue('stat-smb',  'enum-stat-smb');
}

function resetEnumerationProtocolStats() {
  ['kerb','ntlm','smb',...TOOLS_PROBE_KEYS].forEach(key => {
    const el = document.getElementById(`enum-stat-${key}`);
    if (!el) return;
    el.textContent = '—';
    el.className   = 'enum-proto-value dim';
  });
}

function _sortProtoRows() {
  const panel = document.getElementById('enum-proto-panel');
  if (!panel) return;
  const rows = Array.from(panel.querySelectorAll('.enum-proto-row'));
  const rank = (row) => {
    const val = row.querySelector('.enum-proto-value');
    if (!val) return 2;
    if (val.classList.contains('green')) return 0;
    if (val.classList.contains('red'))   return 1;
    return 2;
  };
  rows.sort((a, b) => rank(a) - rank(b));
  rows.forEach(r => panel.appendChild(r));
}

async function probeProtocols() {
  if (!state.connected || !state.ip) return;
  TOOLS_PROBE_KEYS.forEach(k => {
    const el = document.getElementById(`enum-stat-${k}`);
    if (el) { el.textContent = '…'; el.className = 'enum-proto-value dim'; }
  });
  try {
    const resp = await fetch(`${API_BASE}/api/probe-protocols`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: state.ip, timeout: 5 }),
    });
    const data = await resp.json();
    if (!data.success) return;
    Object.entries(data.results || {}).forEach(([key, info]) => {
      const el = document.getElementById(`enum-stat-${key}`);
      if (!el) return;
      el.textContent = info.status || '—';
      el.className   = 'enum-proto-value ' + (info.level === 'good' ? 'green' : info.level === 'bad' ? 'red' : 'dim');
    });
  } catch (_) {}
}

async function runToolsEnumeration() {
  if (!state.connected || state.deepEnumRunning) return;
  const scanBtn = document.getElementById('btn-enum-proto-scan');
  state.deepEnumRunning = true;
  if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = 'Scanning...'; }

  _showEnumTabProgress();
  _updateEnumTabProgress(0, 'Starting protocol checks...');

  const ip          = state.ip;
  const total       = TOOLS_PROBE_KEYS.length;
  const CONCURRENCY = 5;
  let   completed   = 0;

  const probeOne = async (key) => {
    try {
      const resp = await fetch(`${API_BASE}/api/probe-protocols`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, timeout: 5, protocols: [key] }),
      });
      const data = await resp.json();
      const info = data.results?.[key];
      if (info) {
        const el = document.getElementById(`enum-stat-${key}`);
        if (el) {
          el.textContent = info.status || '—';
          el.className   = 'enum-proto-value ' + (info.level === 'good' ? 'green' : info.level === 'bad' ? 'red' : 'dim');
        }
      }
      addLog(`${key.toUpperCase()} probe: ${info?.status || 'done'}`, 'ok');
    } catch (_) {
      addLog(`${key.toUpperCase()} probe failed`, 'err');
    }
    completed++;
    _updateEnumTabProgress(Math.round((completed / total) * 100), `Checking protocols... (${completed}/${total})`);
  };

  try {
    for (let i = 0; i < total; i += CONCURRENCY) {
      await Promise.all(TOOLS_PROBE_KEYS.slice(i, i + CONCURRENCY).map(probeOne));
    }
    _sortProtoRows();
    _updateEnumTabProgress(100, 'All tools complete ✓');
  } finally {
    state.deepEnumRunning = false;
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = 'Scan'; }
    setTimeout(_hideEnumTabProgress, 1200);
  }
}

/* ── API health ping ── */
async function pingApi() {
  try {
    const t0   = Date.now();
    const resp = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(2000) });
    const ms   = Date.now() - t0;
    if (resp.ok) {
      document.getElementById('stat-api').textContent = 'Reachable';
      document.getElementById('stat-api').className   = 'stat-value green';
      document.getElementById('stat-latency').textContent = `${ms} ms`;
      document.getElementById('api-ping-bar').style.width = `${Math.min(100, ms)}%`;
    } else { throw new Error(); }
  } catch {
    document.getElementById('stat-api').textContent = 'Unreachable';
    document.getElementById('stat-api').className   = 'stat-value red';
    document.getElementById('stat-latency').textContent = 'N/A';
  }
}

pingApi();
if (!apiPingTimerId) apiPingTimerId = setInterval(pingApi, 20000);

/* ── Enter key → connect ── */
function bindConnectHotkeysOnce() {
  ['f-domain','f-ip','f-dc','f-user','f-pass','f-hash'].forEach(id => {
    const el = document.getElementById(id);
    if (!el || el.dataset.enterBound === '1') return;
    el.dataset.enterBound = '1';
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); handleConnectClick(e); }
    });
  });
}
bindConnectHotkeysOnce();

/* ── Auth input event binding ── */
['f-pass','f-hash'].forEach((id, i) => {
  const source = ['pass','hash'][i];
  const el = document.getElementById(id);
  if (!el || el.dataset.authBound) return;
  el.dataset.authBound = '1';
  el.addEventListener('input',  () => updateAuthInputLockState(source));
  el.addEventListener('change', () => updateAuthInputLockState(source));
});
updateAuthInputLockState();

/* ── Escape closes modals ── */
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (typeof hideAttackHintModal    === 'function') hideAttackHintModal();
    closeSecurityStatusPanel();
  }
});