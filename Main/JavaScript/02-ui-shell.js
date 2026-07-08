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


function switchMainTab(tab, btn) {
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

  const allTabs = ['connect',
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
  document.getElementById('tab-connect').style.display = '';
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


['f-pass','f-hash'].forEach((id, i) => {
  const source = ['pass','hash'][i];
  const el = document.getElementById(id);
  if (!el || el.dataset.authBound) return;
  el.dataset.authBound = '1';
  el.addEventListener('input',  () => updateAuthInputLockState(source));
  el.addEventListener('change', () => updateAuthInputLockState(source));
});
updateAuthInputLockState();


document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (typeof hideAttackHintModal    === 'function') hideAttackHintModal();
    closeSecurityStatusPanel();
  }
});