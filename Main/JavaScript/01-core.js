/* ═══════════════════════════════════════════════════
   01-core.js
   Connection lifecycle, stats panel, security
   checker, deep enumeration, session timer.
   Depends on: 00-globals.js
   ═══════════════════════════════════════════════════ */

/* ── Assessment Toolkit config ── */
const ASSESSMENT_TOOLKITS = {
  users: [
    { label: 'Kerberoasting',  color: 'var(--accent)', countClass: 'accent',  countId: 'pt-kerb-count',  action: 'runKerberoasting()' },
    { label: 'AS-REP Roasting',color: 'var(--red)',    countClass: 'red',     countId: 'pt-asrep-count', action: 'runASREPRoasting()' },
    { label: 'Silver Ticket',  color: '#a78bfa',       countClass: 'purple',  countId: 'pt-silver-count',action: 'runSilverTicket()' },
    { label: 'Brute Force',    color: '#fb923c',       countClass: 'orange',  countId: 'pt-brute-count', action: 'runBruteForce()' },
    { label: 'DCSync',         color: 'var(--amber)',  countClass: 'red',     countId: 'pt-dcsync-count',action: 'runDCSync()' },
  ],
  computers: [
    { label: 'LAPS Password Dumping', color: 'var(--accent)', countClass: 'dim' },
    { label: 'Spooler Service',       color: 'var(--amber)',  countClass: 'dim' },
  ],
  ous: [
    { label: 'ACE/ACL Abuse', color: 'var(--red)',    countClass: 'dim' },
    { label: 'GPO Injection',  color: 'var(--accent)', countClass: 'dim' },
  ],
  gpo: [
    { label: 'GPP Decryption',             color: 'var(--amber)', countClass: 'dim' },
    { label: 'Scheduled Tasks Injection',  color: 'var(--red)',   countClass: 'dim' },
  ],
  groups: [
    { label: 'Group Membership Hijacking', color: 'var(--accent)', countClass: 'dim' },
    { label: 'DNSAdmins RCE',              color: 'var(--red)',    countClass: 'dim' },
  ],
  trusts: [
    { label: 'Inter-realm Kerberoasting',  color: '#a78bfa',      countClass: 'dim' },
    { label: 'SID History Injection',      color: 'var(--red)',   countClass: 'dim' },
  ],
  acl: [
    { label: 'GenericAll',                   color: 'var(--red)',    countClass: 'dim' },
    { label: 'GenericWrite / WriteProperty', color: 'var(--amber)', countClass: 'dim' },
    { label: 'WriteDACL',                    color: 'var(--accent)', countClass: 'dim' },
    { label: 'WriteOwner',                   color: '#a78bfa',      countClass: 'dim' },
    { label: 'AddMember',                    color: '#fb923c',      countClass: 'dim' },
  ],
};

function renderAssessmentToolkit(tab) {
  const body  = document.getElementById('sidebar-attacks-body');
  if (!body) return;
  const items = ASSESSMENT_TOOLKITS[tab] || [];
  body.innerHTML = items.map(item => {
    const clickAttr = item.action ? ` onclick="${item.action}"` : '';
    return `
      <div class="atk-item"${clickAttr}>
        <span class="atk-dot" style="background:${item.color}"></span>
        <span class="atk-name">${item.label}</span>
        <span class="atk-count ${item.countClass || 'dim'}"${
          item.countId ? ` id="${item.countId}"` : ''}>—</span>
      </div>`;
  }).join('');
}

/* ── Connection state display ── */
function setConnState(s) {
  const dot = document.getElementById('top-conn-dot');
  const lbl = document.getElementById('top-conn-label');
  const sv  = document.getElementById('stat-conn');
  const sb  = document.getElementById('sb-status');

  if (s === 'connected') {
    dot.className = 'conn-dot connected';
    lbl.textContent = 'CONNECTED';   lbl.className = 'conn-label connected';
    sv.textContent  = 'ACTIVE';      sv.className  = 'stat-value green';
    sb.textContent  = 'CONNECTED';   sb.className  = 's-val ok';
  } else if (s === 'offline-zip') {
    dot.className = 'conn-dot connecting';
    lbl.textContent = 'OFFLINE (ZIP)'; lbl.className = 'conn-label';
    sv.textContent  = 'OFFLINE (ZIP)'; sv.className  = 'stat-value amber';
    sb.textContent  = 'OFFLINE';       sb.className  = 's-val warn';
  } else if (s === 'connecting') {
    dot.className = 'conn-dot connecting';
    lbl.textContent = 'CONNECTING...'; lbl.className = 'conn-label';
    sv.textContent  = 'CONNECTING';    sv.className  = 'stat-value amber';
    sb.textContent  = 'CONNECTING';    sb.className  = 's-val warn';
  } else if (s === 'error') {
    dot.className = 'conn-dot error';
    lbl.textContent = 'AUTH FAILED'; lbl.className = 'conn-label error';
    sv.textContent  = 'AUTH FAILED'; sv.className  = 'stat-value red';
    sb.textContent  = 'ERROR';       sb.className  = 's-val';
  } else {
    dot.className = 'conn-dot';
    lbl.textContent = 'DISCONNECTED'; lbl.className = 'conn-label';
    sv.textContent  = 'OFFLINE';      sv.className  = 'stat-value dim';
    sb.textContent  = 'IDLE';         sb.className  = 's-val';
  }
  updateConnectButtonState();
  updateModeButtonState();
  updateShellTabState();
  updateEnumerationTabState();
  updateReconnaissanceTabState();
  refreshEnumerationProtocolPanel();
}

function setEnvironmentDomainController(value, cls = 'accent') {
  const el = document.getElementById('stat-dc');
  if (!el) return;
  if (!value) { el.textContent = '—'; el.className = 'stat-value dim'; return; }
  el.textContent = value;
  el.className   = `stat-value ${cls}`;
}
window.setEnvironmentDomainController = setEnvironmentDomainController;

function formatLdapPortFailure(data, fallback = 'LDAP connection failed') {
  const ports = Array.isArray(data?.ports) ? data.ports : [];
  if (ports.length === 0) return data?.error || fallback;

  const openPorts = ports.filter(p => p?.port_open).map(p => p.port);
  const closedPorts = ports.filter(p => !p?.port_open).map(p => p.port);

  if (closedPorts.length > 0 && openPorts.length === 0) {
    return `LDAP connection failed because ports ${closedPorts.join(' and ')} are closed or refused. Check the domain controller firewall or LDAP service.`;
  }

  if (openPorts.length > 0 && closedPorts.length > 0) {
    return `LDAP connection is partial: port ${openPorts.join(', ')} is reachable, but port ${closedPorts.join(', ')} is closed or refused.`;
  }

  return data?.error || fallback;
}

function updateStats(data) {
  const set = (id, val, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val || '—';
    if (cls) el.className = `stat-value ${cls}`;
  };

  const inferSecurityStatus = (input) => {
    const proto = String(state.protocol || '').toLowerCase();
    let kerberos = input?.kerberos_enabled;
    let ntlm     = input?.ntlm_enabled;
    let smb      = input?.smb_enabled;
    if (typeof kerberos !== 'boolean') {
      if (proto === 'ldap' || proto === 'ldaps') kerberos = true;
      else if (proto === 'local') kerberos = false;
    }
    return { kerberos, ntlm, smb };
  };

  const toStatusText = (value) => {
    if (value === true)  return { text: 'Enabled',  cls: 'green' };
    if (value === false) return { text: 'Disabled', cls: 'red' };
    return { text: 'Unknown', cls: 'dim' };
  };

  set('stat-domain', data.domain   || state.domain, 'accent');
  setEnvironmentDomainController('', 'dim');
  set('stat-user',   data.username,                  'accent');
  set('stat-proto',  (state.protocol || '').toUpperCase(), 'accent');
  set('stat-os',     data.os_version, '');
  set('stat-level',  data.domain_level, '');

  const inferred = inferSecurityStatus(data);
  const kerb = toStatusText(inferred.kerberos);
  const ntlm = toStatusText(inferred.ntlm);
  const smb  = toStatusText(inferred.smb);
  set('stat-kerb', kerb.text, kerb.cls);
  set('stat-ntlm', ntlm.text, ntlm.cls);
  set('stat-smb',  smb.text,  smb.cls);
  refreshEnumerationProtocolPanel();
  set('stat-api', 'Reachable', 'green');
  set('stat-latency', data.latency_ms ? `${data.latency_ms} ms` : '—', '');
  document.getElementById('sb-proto').textContent = (state.protocol || '').toUpperCase();
  document.getElementById('api-ping-bar').style.width = '100%';

  const source = (data?.meta?.profile_source || data?.ldap_target) ? 'runtime probe' : 'connect response';
  const proto  = (state.protocol || '—').toUpperCase();
  securityStatusMeta = {
    kerberos: { value: inferred.kerberos, source, protocol: proto },
    ntlm:     { value: inferred.ntlm,     source, protocol: proto },
    smb:      { value: inferred.smb,      source, protocol: proto },
  };

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

/* ── Session timer ── */
function startSessionTimer() {
  state.sessionStart = Date.now();
  if (sessionTimerId) { clearInterval(sessionTimerId); sessionTimerId = null; }
  sessionTimerId = setInterval(() => {
    if (!state.connected) return;
    const s   = Math.floor((Date.now() - state.sessionStart) / 1000);
    const h   = String(Math.floor(s / 3600)).padStart(2, '0');
    const m   = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    document.getElementById('sb-time').textContent = `${h}:${m}:${sec}`;
  }, 1000);
}

/* ── Deep enumeration progress ── */
function setDeepEnumProgress(percent, label = '') {
  const wrap = document.getElementById('enum-progress-wrap');
  const fill = document.getElementById('enum-progress-fill');
  const ptxt = document.getElementById('enum-progress-percent');
  const ltxt = document.getElementById('enum-progress-label');
  if (!wrap || !fill || !ptxt || !ltxt) return;
  const bounded = Math.max(0, Math.min(100, Number(percent) || 0));
  wrap.style.display = 'block';
  fill.style.width   = `${bounded}%`;
  ptxt.textContent   = `${Math.round(bounded)}%`;
  if (label) ltxt.textContent = label;
}
function resetDeepEnumProgress() {
  const fill = document.getElementById('enum-progress-fill');
  const ptxt = document.getElementById('enum-progress-percent');
  const ltxt = document.getElementById('enum-progress-label');
  if (fill) fill.style.width   = '0%';
  if (ptxt) ptxt.textContent   = '0%';
  if (ltxt) ltxt.textContent   = 'Deep enumeration in progress...';
}
function hideDeepEnumProgress() {
  const wrap = document.getElementById('enum-progress-wrap');
  if (wrap) wrap.style.display = 'none';
}

function _showEnumTabProgress() {
  const wrap  = document.getElementById('enum-tab-progress');
  const panel = document.getElementById('enumeration-panel');
  if (wrap)  wrap.style.display  = 'flex';
  if (panel) panel.style.display = 'none';
}
function _hideEnumTabProgress() {
  const wrap  = document.getElementById('enum-tab-progress');
  const panel = document.getElementById('enumeration-panel');
  if (wrap)  wrap.style.display  = 'none';
  if (panel) panel.style.display = '';
}
function _updateEnumTabProgress(pct, moduleName) {
  const fill  = document.getElementById('enum-tab-bar-fill');
  const pctEl = document.getElementById('enum-tab-pct');
  const modEl = document.getElementById('enum-tab-module');
  const bounded = Math.max(0, Math.min(100, Number(pct) || 0));
  if (fill)  fill.style.width  = `${bounded}%`;
  if (pctEl) pctEl.textContent = `${Math.round(bounded)}%`;
  if (modEl && moduleName) modEl.textContent = moduleName;
}

/* ── Deep discovery (runs all modules in sequence) ──────────────────────
   YALNIZ collectorlara əmr verir (connection.py, API_BASE). POST cavabının
   body-si RENDER üçün İSTİFADƏ OLUNMUR. Bütün collector-lar tetiklendikdən
   sonra domain_data.db-nin tikilməsi gözlənilir və render YALNIZ
   sqlite_reader.py-dən (DB_READER_BASE, tryLoadSnapshotSection vasitəsilə)
   alınır — connection.py heç bir render funksiyası görmür. ── */

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * sqlite_reader.py (DB_READER_BASE) hazır olana qədər gözləyir.
 * pollForDbReady()-dən fərqli olaraq paylaşılan polling timer-ə
 * toxunmur (connect axını ilə paralel təhlükəsiz işləyə bilsin deyə)
 * və timeout zamanı sadəcə false qaytarır, asılı qalmır.
 */
async function _waitForDbReaderReady(timeoutMs = 60000, intervalMs = 1000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await isDbReaderAlive()) return true;
    await _sleep(intervalMs);
  }
  return false;
}

async function runDeepDiscoveryCounts() {
  const payload = buildEnumerationPayload();
  const modules = [
    { name: 'Access Control List', path: '/api/acl',       cntId: null,          navId: 'nav-acl-count',       section: 'acl' },
    { name: 'Domain Groups',       path: '/api/groups',    cntId: 'cnt-groups',  navId: 'nav-groups-count',    section: 'groups' },
    { name: 'Group Policies',      path: '/api/gpo',       cntId: 'cnt-gpos',    navId: 'nav-gpo-count',       section: 'gpos' },
    { name: 'Org. Units',          path: '/api/ous',       cntId: 'cnt-ous',     navId: 'nav-ous-count',       section: 'ous' },
    { name: 'Domain Trusts',       path: '/api/trusts',    cntId: 'cnt-trusts',  navId: 'nav-trusts-count',    section: 'trusts' },
    { name: 'Computers',           path: '/api/computers', cntId: 'cnt-comp',    navId: 'nav-computers-count', section: 'computers' },
    { name: 'Users',               path: '/api/users',     cntId: 'cnt-users',   navId: 'nav-users-count',     section: 'users' },
  ];

  const setMini = (id, val) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = val; el.className = 'stat-mini-val active'; }
  };

  if (state.deepEnumRunning) return;
  state.deepEnumRunning = true;

  resetDeepEnumProgress();
  setDeepEnumProgress(0, 'Deep enumeration in progress...');
  _showEnumTabProgress();
  _updateEnumTabProgress(0, 'Initializing...');

  /* ── Mərhələ 1: collector-ları ardıcıl tetiklə ──────────────────────
     Hər POST connection.py-də müvafiq collector-u işə salır və
     domain_*.jsonl snapshot-unu yazır (DB build debounce ilə planlaşdırılır).
     Cavab body-si yalnız uğur/uğursuzluq üçün yoxlanılır, render datası
     kimi İSTİFADƏ OLUNMUR. */
  for (let idx = 0; idx < modules.length; idx++) {
    const ep = modules[idx];
    try {
      const resp = await fetch(`${API_BASE}${ep.path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });
      const data = await resp.json().catch(() => ({}));
      const ok   = resp.ok && data && data.success !== false;
      addLog(`[Collector] ${ep.name}: ${ok ? 'enumeration complete' : 'enumeration failed'}.`, ok ? 'ok' : 'err');
    } catch (err) {
      addLog(`[Collector] ${ep.name}: request failed (${err.message || 'unknown error'})`, 'err');
    }

    const percent = Math.round(((idx + 1) / modules.length) * 70);
    setDeepEnumProgress(percent, `Collectors running... ${idx + 1}/${modules.length}`);
    _updateEnumTabProgress(percent, ep.name);
  }

  /* ── Mərhələ 2: domain_data.db-nin tikilməsini gözlə ── */
  setDeepEnumProgress(75, 'Verilənlər bazası hazırlanır...');
  _updateEnumTabProgress(75, 'Building database...');
  await _sleep(3500); // debounced DB build (~3s) üçün gözləmə
  const dbReady = await _waitForDbReaderReady(60000, 1000);
  if (!dbReady) {
    addLog('sqlite_reader.py (8800) gözlənilən müddətdə hazır olmadı — bəzi bölmələr köhnə/boş qala bilər', 'error');
  }

  /* ── Mərhələ 3: RENDER — YALNIZ sqlite_reader.py-dən (DB_READER_BASE) ──
     connection.py-nin POST cavabları burada heç vaxt istifadə olunmur. */
  setDeepEnumProgress(90, 'Cədvəllər yüklənir...');
  _updateEnumTabProgress(90, 'Loading tables...');

  for (let idx = 0; idx < modules.length; idx++) {
    const ep    = modules[idx];
    const snap  = await tryLoadSnapshotSection(ep.section);
    const items = snap ? snap.records : [];
    const count = items.length;

    if (snap) {
      if (ep.section === 'users') {
        usersData = items;
        usersMeta = snap.meta || {};
        if (typeof updatePentestCounts === 'function') updatePentestCounts();
        const usersMeta2 = document.getElementById('users-meta');
        if (usersMeta2) usersMeta2.textContent = `${usersData.length} users · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTab = document.getElementById('tab-users');
        if (activeTab && activeTab.style.display !== 'none' && typeof renderUsers === 'function') renderUsers();
      } else if (ep.section === 'computers') {
        computersData = items;
        const dcComputer = computersData.find(c => c?.is_domain_controller);
        const dcDns = dcComputer?.dns_name || dcComputer?.computer_name || '';
        setEnvironmentDomainController(dcDns, dcDns ? 'accent' : 'dim');
        const compMeta = document.getElementById('computers-meta');
        if (compMeta) compMeta.textContent = `${computersData.length} computers · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabComp = document.getElementById('tab-computers');
        if (activeTabComp && activeTabComp.style.display !== 'none' && typeof renderComputers === 'function') renderComputers();
      } else if (ep.section === 'ous') {
        ousData = items;
        const ousMeta = document.getElementById('ous-meta');
        if (ousMeta) ousMeta.textContent = `${ousData.length} OUs · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabOUs = document.getElementById('tab-ous');
        if (activeTabOUs && activeTabOUs.style.display !== 'none' && typeof renderOUs === 'function') renderOUs();
      } else if (ep.section === 'gpos') {
        gposData = items;
        const gposMeta = document.getElementById('gpos-meta');
        if (gposMeta) gposMeta.textContent = `${gposData.length} GPOs · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabGPO = document.getElementById('tab-gpo');
        if (activeTabGPO && activeTabGPO.style.display !== 'none' && typeof renderGPOs === 'function') renderGPOs();
      } else if (ep.section === 'groups') {
        groupsData = items;
        const groupsMeta = document.getElementById('groups-meta');
        if (groupsMeta) groupsMeta.textContent = `${groupsData.length} groups · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabGroups = document.getElementById('tab-groups');
        if (activeTabGroups && activeTabGroups.style.display !== 'none' && typeof renderGroups === 'function') renderGroups();
      } else if (ep.section === 'trusts') {
        trustsData = items;
        const trustsMeta = document.getElementById('trusts-meta');
        if (trustsMeta) trustsMeta.textContent = `${trustsData.length} trusts · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabTrusts = document.getElementById('tab-trusts');
        if (activeTabTrusts && activeTabTrusts.style.display !== 'none' && typeof renderTrusts === 'function') renderTrusts();
      } else if (ep.section === 'acl') {
        aclData = items;
        const aclMeta = document.getElementById('acl-meta');
        if (aclMeta) aclMeta.textContent = `${aclData.length} ACEs · domain: ${(state.domain || '').toUpperCase()}`;
        const activeTabACL = document.getElementById('tab-acl');
        if (activeTabACL && activeTabACL.style.display !== 'none') {
          if (typeof renderACLObjectFilters === 'function') renderACLObjectFilters();
          if (typeof renderACLs === 'function') renderACLs();
        }
      }
      enumCacheLoaded[ep.section] = true;
      addLog(`[Render] ${ep.name}: ${count} objects loaded from domain_data.db.`, 'ok');
    } else {
      enumCacheLoaded[ep.section] = false;
      addLog(`[Render] ${ep.name}: failed to read from domain_data.db (sqlite_reader unavailable).`, 'err');
    }

    if (ep.cntId) setMini(ep.cntId, count);
    const navEl = document.getElementById(ep.navId);
    if (navEl) navEl.textContent = count;
  }

  setDeepEnumProgress(100, 'Deep enumeration completed');
  _updateEnumTabProgress(100, 'Complete ✓');
  state.deepEnumRunning = false;
  setTimeout(_hideEnumTabProgress, 1200);
}

/* ── Connect ── */
function validate() {
  let ok = true;
  [{ id: 'f-domain', err: 'err-domain' }, { id: 'f-ip', err: 'err-ip' }, { id: 'f-user', err: 'err-user' }]
    .forEach(f => {
      const el = document.getElementById(f.id);
      const er = document.getElementById(f.err);
      if (!el.value.trim()) { el.classList.add('error'); er.classList.add('show'); ok = false; }
      else { el.classList.remove('error'); er.classList.remove('show'); }
    });

  const passEl  = document.getElementById('f-pass');
  const hashEl  = document.getElementById('f-hash');
  const passErr = document.getElementById('err-pass');
  const hashErr = document.getElementById('err-hash');
  const hasPass = !!passEl.value.trim();
  const hasHash = !!(hashEl?.value || '').trim();

  if (hasPass && hasHash) {
    passEl.classList.add('error'); hashEl?.classList.add('error');
    passErr.classList.add('show'); hashErr?.classList.add('show');
    return false;
  }
  if (!hasPass && !hasHash) {
    passEl.classList.add('error'); hashEl?.classList.add('error');
    passErr.classList.add('show'); hashErr?.classList.add('show');
    ok = false;
  } else {
    passEl.classList.remove('error'); hashEl?.classList.remove('error');
    passErr.classList.remove('show'); hashErr?.classList.remove('show');
  }
  return ok;
}

function setBtnLoading(loading, connectMode = 'deep') {
  const fastBtn = document.getElementById('btn-connect-fast');
  const deepBtn = document.getElementById('btn-connect-deep');
  const fastTxt = document.getElementById('btn-connect-fast-text');
  const deepTxt = document.getElementById('btn-connect-deep-text');

  if (loading) {
    if (fastBtn) fastBtn.disabled = true;
    if (deepBtn) deepBtn.disabled = true;
    if (connectMode === 'fast' && fastTxt) {
      fastTxt.innerHTML = '<span class="spinner"></span>&nbsp;FAST...';
      if (deepTxt) deepTxt.textContent = 'DEEP CONNECT';
    } else {
      if (deepTxt) deepTxt.innerHTML = '<span class="spinner"></span>&nbsp;DEEP...';
      if (fastTxt) fastTxt.textContent = 'FAST CONNECT';
    }
  } else {
    updateConnectButtonState();
  }
}

function updateConnectButtonState() {
  const fastBtn        = document.getElementById('btn-connect-fast');
  const deepBtn        = document.getElementById('btn-connect-deep');
  const disconnectBtn  = document.getElementById('btn-disconnect');
  const fastTxt        = document.getElementById('btn-connect-fast-text');
  const deepTxt        = document.getElementById('btn-connect-deep-text');
  const localDiscBtn   = document.getElementById('btn-local-disconnect');
  if (!fastBtn || !deepBtn || !fastTxt || !deepTxt || !disconnectBtn) return;

  if (state.connected) {
    fastBtn.style.display = 'none'; deepBtn.style.display = 'none';
    disconnectBtn.style.display = '';
    disconnectBtn.classList.add('btn-danger');
    disconnectBtn.classList.remove('btn-secondary');
  } else {
    fastBtn.style.display = ''; deepBtn.style.display = '';
    disconnectBtn.style.display = 'none';
    fastBtn.disabled = false; deepBtn.disabled = false;
    fastBtn.classList.remove('btn-danger'); deepBtn.classList.remove('btn-danger');
    fastBtn.classList.add('btn-secondary'); deepBtn.classList.add('btn-primary');
    fastTxt.textContent = 'FAST CONNECT'; deepTxt.textContent = 'DEEP CONNECT';
  }
  if (localDiscBtn) {
    const localActive = state.connected && state.protocol === 'local';
    localDiscBtn.disabled = !localActive;
    localDiscBtn.classList.toggle('btn-danger',   localActive);
    localDiscBtn.classList.toggle('btn-secondary', !localActive);
  }
}

function updateModeButtonState() {
  const remoteBtn = document.getElementById('mode-remote');
  const localBtn  = document.getElementById('mode-local');
  if (!remoteBtn || !localBtn) return;
  remoteBtn.disabled = false; remoteBtn.classList.remove('disabled');
  localBtn.disabled  = false; localBtn.classList.remove('disabled');
}

function handleConnectClick(event, connectMode = 'deep') {
  if (event?.preventDefault) event.preventDefault();
  if (event?.stopPropagation) event.stopPropagation();
  if (state.connecting) return;
  if (state.connected && Date.now() < (state.justConnectedUntil || 0)) return;
  if (state.connected) { doDisconnect(); return; }
  doConnect(connectMode);
}

async function doConnect(connectMode = 'deep') {
  if (state.connecting) return;
  if (state.connected) {
    showToast('An active session already exists. Disconnect first.', 'info');
    addLog('Connect blocked: session is already active.', 'warn');
    return;
  }
  if (!validate()) { addLog('Validation failed — fill all required fields', 'err'); return; }

  const domain   = document.getElementById('f-domain').value.trim();
  const ip       = document.getElementById('f-ip').value.trim();
  const dcHost   = (document.getElementById('f-dc')?.value || '').trim();
  const username = document.getElementById('f-user').value.trim();
  const password = (document.getElementById('f-pass').value || '').trim();
  const hash     = (document.getElementById('f-hash')?.value || '').trim();

  state.domain      = domain;
  state.user        = username;
  state.connecting  = true;

  setBtnLoading(true, connectMode);
  setConnState('connecting');
  addLog(`Initiating ${connectMode.toUpperCase()} ${state.protocol.toUpperCase()} connection to ${ip} (${domain})...`, 'info');

  try {
    const resp = await fetch(`${API_BASE}/api/connect`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        mode: 'remote', connect_mode: connectMode,
        skip_counts_probe: connectMode === 'deep',
        protocol: state.protocol,
        domain, ip, username, password, hash, dc: dcHost, ldap_host: dcHost,
      }),
    });
    const data = await resp.json();

    if (resp.ok && data.success) {
      resetSecurityCheckerCacheForSession();
      state.connected        = true;
      state.justConnectedUntil = Date.now() + 2000;
      state.mode    = 'remote';
      state.ip      = ip;
      state.domain  = data.domain || domain;
      state.dc      = dcHost || data.dc || ip;
      setConnState('connected');
      addLog(`Connected as ${username}@${state.domain} via ${state.protocol.toUpperCase()}`, 'ok');
      addLog(`Domain Controller: ${state.dc || 'N/A'}`, 'ok');
      updateStats(data);
      runQuickSecurityStatusProbe();
      probeProtocols();
      startSessionTimer();
      state._pass = password || '';
      state._hash = hash     || '';
      const savedEntry = { domain, ip, username, protocol: state.protocol };
      if (dcHost)   savedEntry.dc       = dcHost;
      if (password) savedEntry.password = password;
      if (hash)     savedEntry.hash     = hash;
      saveSuccessfulUser(savedEntry);
      document.getElementById('nav-users-count').textContent = data.counts?.users ?? '-';
      showToast(`Connected to ${state.domain}`, 'success');
      state.connectMode = connectMode;

      if (connectMode === 'deep') {
        addLog('Deep connect: running object discovery checks...', 'info');
        await runDeepDiscoveryCounts();
        addLog('Deep connect: object discovery completed.', 'ok');
      } else {
        hideDeepEnumProgress();
        addLog('Fast connect: enumeration deferred — click Enumeration tab to scan.', 'info');
      }
    } else {
      const error = new Error(data.error || data.message || 'LDAP Authentication Failed!');
      error.ports = data.ports;
      error.host_up = data.host_up;
      error.protocol = data.protocol || state.protocol;
      throw error;
    }
  } catch (err) {
    state.connected = false;
    setConnState('error');
    const friendly = formatLdapPortFailure(err, err?.message || 'LDAP connection failed');
    addLog(`Connection failed: ${friendly}`, 'err');
    showToast(friendly, 'error');
  } finally {
    state.connecting = false;
    setBtnLoading(false, connectMode);
  }
}

function doDisconnect() {
  if (!state.connected) return;
  addLog('Disconnecting active session...', 'warn');
  if (sessionTimerId) { clearInterval(sessionTimerId); sessionTimerId = null; }
  state.connected        = false;
  state.justConnectedUntil = 0;
  state.ip               = null;
  resetSecurityCheckerCacheForSession();
  hideDeepEnumProgress();
  resetDeepEnumProgress();
  setConnState('disconnected');
  showLoginScreen();
  showToast('Session disconnected', 'info');
}

async function doLocalConnect() {
  if (state.connecting) return;
  if (state.connected) {
    showToast('An active session already exists. Disconnect first.', 'info');
    addLog('Local connect blocked: session is already active.', 'warn');
    return;
  }
  state.connecting = true;
  setConnState('connecting');
  addLog('Attaching to local session via Python API...', 'info');
  try {
    const resp = await fetch(`${API_BASE}/api/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'local' }),
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      resetSecurityCheckerCacheForSession();
      state.connected        = true;
      state.justConnectedUntil = Date.now() + 2000;
      state.mode     = 'local';
      state.protocol = 'local';
      state.ip       = '127.0.0.1';
      state.user     = data.username || state.user;
      state.domain   = data.domain   || state.domain;
      state.dc       = data.dc       || state.dc;
      setConnState('connected');
      addLog(`Local session attached: ${data.username}`, 'ok');
      updateStats(data);
      runQuickSecurityStatusProbe();
      probeProtocols();
      startSessionTimer();
      document.getElementById('nav-users-count').textContent = data.counts?.users ?? '-';
      showToast('Local session attached', 'success');
    } else {
      throw new Error(data.error || data.message || 'Failed to attach session');
    }
  } catch (err) {
    state.connected = false;
    setConnState('error');
    addLog(`Local connect failed: ${err.message}`, 'err');
    showToast(err.message, 'error');
  } finally {
    state.connecting = false;
  }
}

async function testConn() {
  if (!validate()) return;
  const ip     = document.getElementById('f-ip').value.trim();
  const domain = document.getElementById('f-domain').value.trim();
  const proto  = state.protocol || 'ldap';

  addLog(`[TEST] ---- Connectivity test started for ${ip} ----`, 'info');
  addLog(`[TEST] Step 1: Probing host ${ip} via TCP multi-port scan...`, 'info');

  let data;
  try {
    const resp = await fetch(`${API_BASE}/api/test`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, protocol: proto, domain }),
    });
    data = await resp.json();
    if (!resp.ok && !Array.isArray(data.ports)) {
      addLog(`[TEST] Server error: ${data.error || 'Unknown'}`, 'err');
      showToast('Test failed', 'error');
      return;
    }
  } catch (err) {
    addLog(`[TEST] Cannot reach API backend: ${err.message}`, 'err');
    showToast('API backend not running', 'error');
    return;
  }

  if (data.host_up) {
    const via = data.detected_via ? ` (detected via TCP/${data.detected_via})` : '';
    addLog(`[TEST] Step 1: Host ${ip} is UP${via}`, 'ok');
  } else {
    if (Array.isArray(data.ports) && data.ports.length > 0) {
      const friendly = formatLdapPortFailure(data, 'LDAP ports are not reachable');
      addLog(`[TEST] ${friendly}`, 'err');
      addLog(`[TEST] ---- Test complete ----`, 'info');
      showToast(friendly, 'error');
      return;
    }
    addLog(`[TEST] Step 1: Host ${ip} is UNREACHABLE`, 'err');
    addLog(`[TEST] ---- Test complete ----`, 'info');
    showToast('Host unreachable', 'error');
    return;
  }

  if (Array.isArray(data.ports) && data.ports.length > 0) {
    const protoUpper = (data.protocol || proto).toUpperCase();
    let openCount = 0;
    data.ports.forEach(portInfo => {
      const portLabel = `${protoUpper} port ${portInfo.port}`;
      const stateLabel = portInfo.port_open ? 'OPEN' : (portInfo.result === 'closed' ? 'CLOSED (connection refused)' : 'CLOSED or filtered');
      addLog(`[TEST] Step 2: Checking ${portLabel}...`, 'info');
      if (portInfo.port_open) {
        openCount += 1;
        addLog(`[TEST] Step 2: ${portLabel} is OPEN`, 'ok');
      } else {
        addLog(`[TEST] Step 2: ${portLabel} is ${stateLabel}`, 'err');
      }
    });
    if (openCount > 0) {
      addLog(`[TEST] ---- Test complete: OK ----`, 'ok');
      showToast(`${openCount} LDAP port(s) open`, 'success');
    } else {
      const friendly = formatLdapPortFailure(data, 'LDAP ports are closed');
      addLog(`[TEST] ${friendly}`, 'err');
      addLog(`[TEST] ---- Test complete: port closed ----`, 'info');
      showToast(friendly, 'error');
    }
    return;
  }

  const protoUpper = (data.protocol || proto).toUpperCase();
  const portLabel  = `${protoUpper} port ${data.port}`;
  addLog(`[TEST] Step 2: Checking ${portLabel}...`, 'info');
  if (data.port_open) {
    addLog(`[TEST] Step 2: ${portLabel} is OPEN`, 'ok');
    addLog(`[TEST] ---- Test complete: OK ----`, 'ok');
    showToast(`${portLabel} is open`, 'success');
  } else {
    const friendly = formatLdapPortFailure(data, `${portLabel} is closed or refused`);
    addLog(`[TEST] ${friendly}`, 'err');
    addLog(`[TEST] ---- Test complete: port closed ----`, 'info');
    showToast(friendly, 'error');
  }
}

/* ── Saved users ── */
async function loadSavedUsers() {
  try {
    const resp = await fetch(`${API_BASE}/api/saved-users`, { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load saved users');
    savedUsersCache = Array.isArray(data.users) ? data.users : [];
    renderSavedUsers(savedUsersCache);
  } catch (err) {
    renderSavedUsers([]);
    addLog(`Saved users load failed: ${err.message}`, 'err');
  }
}

function renderSavedUsers(items) {
  const scroll = document.getElementById('saved-users-scroll');
  if (!scroll) return;
  if (!Array.isArray(items) || items.length === 0) {
    scroll.innerHTML = '<div class="saved-user-empty">No saved users yet.</div>';
    return;
  }
  scroll.innerHTML = items.map((u, idx) => `
    <div class="saved-user-item" onclick="applySavedUser(${idx}, event)">
      <div class="saved-user-top">
        <span class="saved-user-name">${u.username || '—'}</span>
        <span class="saved-user-proto">${(u.protocol || 'ldap').toUpperCase()}</span>
      </div>
      <div class="saved-user-meta">${u.domain || '—'} @ ${u.ip || '—'}</div>
      <div class="saved-user-meta">DC: ${u.dc || '—'}</div>
      <div class="saved-user-meta">Saved: ${u.saved_at || ''}</div>
    </div>`).join('');
}

function toggleSavedUsers() {
  const box = document.getElementById('saved-users-list');
  if (!box) return;
  const open = box.style.display === 'block';
  box.style.display = open ? 'none' : 'block';
  if (!open) loadSavedUsers();
}

function applySavedUser(index, event) {
  if (event?.preventDefault)   event.preventDefault();
  if (event?.stopPropagation)  event.stopPropagation();
  const u = savedUsersCache[index];
  if (!u) return;
  if (state.connected || state.connecting) { showToast('Disconnect current session first', 'info'); return; }
  switchMode('remote');
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) { el.value = val || ''; el.classList.remove('error'); }
  };
  setVal('f-domain', u.domain);   setVal('f-ip',   u.ip);
  setVal('f-dc',     u.dc);       setVal('f-user',  u.username);
  setVal('f-pass',   u.password); setVal('f-hash',  u.hash);
  ['err-domain','err-ip','err-user','err-pass','err-hash'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('show');
  });
  const protocolAliases = { winrm: 'ldap', psexec: 'rpc', smb: 'agent', ssh: 'beacon' };
  const savedProto = protocolAliases[String(u.protocol || '').toLowerCase()] || String(u.protocol || '').toLowerCase();
  if (savedProto && ['ldap','ldaps','rpc','agent','beacon','local'].includes(savedProto)) selectProto(savedProto);
  updateAuthInputLockState();
  const box = document.getElementById('saved-users-list');
  if (box) box.style.display = 'none';
  showToast(`Loaded saved user: ${u.username || 'unknown'}`, 'success');
}

async function saveSuccessfulUser(entry) {
  try {
    await fetch(`${API_BASE}/api/saved-users/save`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });
  } catch (err) {
    addLog(`Saved user write failed: ${err.message}`, 'warn');
  }
}

/* ── Security checker ── */
function resetSecurityCheckerCacheForSession() {
  securityCheckerSessionId++;
  securityCheckerLastResults = { kerberos: null, ntlm: null, smb: null };
}

function closeSecurityStatusPanel() {
  const modal = document.getElementById('status-modal-backdrop');
  if (modal) modal.style.display = 'none';
}

function levelToClass(level, fallbackValue = null) {
  const n = String(level || '').toLowerCase();
  if (n === 'good') return 'green';
  if (n === 'bad')  return 'red';
  if (n === 'warn') return 'amber';
  if (fallbackValue === true)  return 'green';
  if (fallbackValue === false) return 'red';
  return 'dim';
}

function buildCheckerItems(kind, data) {
  const normalize = (label, entry, extra = '') => ({
    label,
    status:  entry?.status  || 'Unknown',
    level:   entry?.level   || 'unknown',
    value:   entry?.value,
    details: entry?.details || '',
    extra,
  });

  if (kind === 'kerberos') return [
    normalize('KDC Port (TCP/88)',         data.kdc_port),
    normalize('Encryption Types',          data.encryption_types),
    normalize('Kerberos Armoring (FAST)',  data.kerberos_armoring_fast),
    normalize('PAC Validation',            data.pac_validation),
    normalize('Ticket Lifetime',           data.ticket_lifetime, data.ticket_lifetime?.hours ? `${data.ticket_lifetime.hours} hours` : ''),
  ];
  if (kind === 'ntlm') return [
    normalize('NTLM Authentication',  data.ntlm_auth,             data.ntlm_auth?.error || ''),
    normalize('SMB Port (TCP/445)',   data.smb_port),
    normalize('NTLM Restriction',     data.ntlm_restriction),
    normalize('Relay Protection (MIC)', data.relay_protection?.mic),
    normalize('Relay Protection (EPA)', data.relay_protection?.epa),
    normalize('LM Hash Storage',      data.lm_hash_storage),
  ];
  return [
    normalize('SMB Signing',    data.smb_signing),
    normalize('SMB Encryption', data.smb_encryption, data.smb_encryption?.supported === false ? 'SMB encryption unsupported by negotiated dialect' : ''),
    normalize('Guest Access',   data.guest_access, Array.isArray(data.guest_access?.readable_shares) && data.guest_access.readable_shares.length ? `Readable shares: ${data.guest_access.readable_shares.join(', ')}` : ''),
    normalize('SMBv1',          data.smbv1),
    normalize('Share Permissions', data.share_permissions, Array.isArray(data.share_permissions?.sample_shares) && data.share_permissions.sample_shares.length ? `Sample shares: ${data.share_permissions.sample_shares.join(', ')}` : ''),
  ];
}

function renderCheckerItems(checkItems = []) {
  const cards = checkItems.filter(item => item?.label).map(item => {
    const cls     = levelToClass(item.level, item.value);
    const details = item.details ? `<p class="checker-line">${escapeHtml(item.details)}</p>` : '<p class="checker-line dim">No additional details from checker.</p>';
    const extra   = item.extra   ? `<p class="checker-line"><strong>Info:</strong> ${escapeHtml(item.extra)}</p>` : '';
    return `
      <div class="status-info-card checker-metric-card">
        <div class="checker-metric-head">
          <h4>${escapeHtml(item.label)}</h4>
          <span class="checker-pill ${cls}">${escapeHtml(item.status || 'Unknown')}</span>
        </div>
        <div class="checker-metric-body">${details}${extra}</div>
      </div>`;
  });
  return `<div class="checker-grid checker-span-2">${cards.join('')}</div>`;
}

function renderCheckerSuccessPanel({ normalized, body, meta, stateText, stateClass, payload, endpoint, data }) {
  const riskLevel     = data.risk_summary?.level || 'unknown';
  const riskClass     = levelToClass(riskLevel);
  const checkItems    = buildCheckerItems(normalized, data);
  const checkerHtml   = renderCheckerItems(checkItems);
  const target        = data.target || payload.ip || '—';
  const totals        = checkItems.reduce((acc, item) => {
    const cls = levelToClass(item.level, item.value);
    if      (cls === 'green') acc.good++;
    else if (cls === 'amber') acc.warn++;
    else if (cls === 'red')   acc.bad++;
    else                      acc.unknown++;
    return acc;
  }, { good: 0, warn: 0, bad: 0, unknown: 0 });

  body.innerHTML = `
    <div class="status-info-card checker-overview-card checker-span-2">
      <h4>Security Overview</h4>
      <div class="checker-overview-grid">
        <div class="checker-overview-item"><span class="checker-overview-label">Target</span><span class="checker-overview-value">${escapeHtml(target)}</span></div>
        <div class="checker-overview-item"><span class="checker-overview-label">Protocol</span><span class="checker-overview-value">${escapeHtml(meta.protocol || '—')}</span></div>
        <div class="checker-overview-item"><span class="checker-overview-label">Risk</span><span class="checker-pill ${riskClass}">${escapeHtml(data.risk_summary?.status || 'Unknown')}</span></div>
        <div class="checker-overview-item"><span class="checker-overview-label">Source</span><span class="checker-overview-value">${escapeHtml(meta.source || 'Unknown')}</span></div>
      </div>
      <div class="checker-counts">
        <span class="checker-count-chip green">Good ${totals.good}</span>
        <span class="checker-count-chip amber">Warn ${totals.warn}</span>
        <span class="checker-count-chip red">Bad ${totals.bad}</span>
        <span class="checker-count-chip dim">Unknown ${totals.unknown}</span>
      </div>
    </div>
    <div class="status-info-card">
      <h4>Current State</h4>
      <p><strong>Status:</strong> <span class="checker-pill ${stateClass}">${escapeHtml(stateText)}</span></p>
      <p><strong>Protocol:</strong> ${escapeHtml(meta.protocol || '—')}</p>
      <p><strong>Detection Source:</strong> ${escapeHtml(meta.source || 'Unknown')}</p>
    </div>
    <div class="status-info-card">
      <h4>Checker Summary</h4>
      <p><strong>Target:</strong> ${escapeHtml(target)}</p>
      <p><strong>Risk:</strong> <span class="checker-pill ${riskClass}">${escapeHtml(data.risk_summary?.status || 'Unknown')}</span></p>
      <p><strong>Endpoint:</strong> ${escapeHtml(endpoint)}</p>
    </div>
    ${checkerHtml}
    <div class="status-info-card checker-span-2">
      <h4>Raw Output</h4>
      <details class="checker-raw-details">
        <summary>Show JSON response</summary>
        <pre class="checker-raw-pre">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>
    </div>`;

  if (normalized === 'kerberos') {
    const val = data.kdc_port?.value;
    const el  = document.getElementById('stat-kerb');
    if (el) { el.textContent = val === true ? 'Enabled' : val === false ? 'Disabled' : 'Unknown'; el.className = `stat-value ${val === true ? 'green' : val === false ? 'red' : 'dim'}`; }
  } else if (normalized === 'ntlm') {
    const val = data.ntlm_auth?.value;
    const el  = document.getElementById('stat-ntlm');
    if (el) { el.textContent = val === true ? 'Enabled' : val === false ? 'Disabled' : 'Unknown'; el.className = `stat-value ${val === true ? 'green' : val === false ? 'red' : 'dim'}`; }
  } else if (normalized === 'smb') {
    const val = data.smb_signing?.value;
    const el  = document.getElementById('stat-smb');
    if (el) { el.textContent = val === true ? 'Enabled' : val === false ? 'Disabled' : 'Unknown'; el.className = `stat-value ${val === true ? 'green' : val === false ? 'red' : 'dim'}`; }
  }
  refreshEnumerationProtocolPanel();
}

function checkerPanelConfig(kind) {
  return ({
    kerberos: { title: 'Kerberos Security Panel', intro: '' },
    ntlm:     { title: 'NTLM Security Panel',     intro: '' },
    smb:      { title: 'SMB Security Panel',      intro: '' },
  }[kind] || { title: 'Security Panel', intro: '' });
}

function securityCheckerEndpoint(kind) {
  return ({ kerberos: '/api/kerberos-check', ntlm: '/api/ntlm-check', smb: '/api/smb-check' }[kind] || '/api/kerberos-check');
}

async function openSecurityStatusPanel(kind) {
  const modal = document.getElementById('status-modal-backdrop');
  const title = document.getElementById('status-modal-title');
  const body  = document.getElementById('status-modal-body');
  if (!modal || !title || !body) return;

  const normalized  = (kind || '').toLowerCase();
  const cfg         = checkerPanelConfig(normalized);
  const meta        = securityStatusMeta[normalized] || { value: null, source: 'Unknown', protocol: '—' };
  const stateText   = meta.value === true ? 'Enabled' : meta.value === false ? 'Disabled' : 'Unknown';
  const stateClass  = meta.value === true ? 'green'   : meta.value === false ? 'red'       : 'dim';

  title.textContent = cfg.title;
  modal.style.display = 'flex';

  if (!state.connected) {
    body.innerHTML = `<div class="status-info-card"><h4>Connection Required</h4><p>Please establish a session first, then run this check again.</p></div>`;
    return;
  }

  body.innerHTML = `
    <div class="status-info-card">
      <h4>Current State</h4>
      <p><strong>Status:</strong> <span class="stat-value ${stateClass}" style="font-size:16px;">${escapeHtml(stateText)}</span></p>
      <p><strong>Protocol:</strong> ${escapeHtml(meta.protocol || '—')}</p>
      <p><strong>Detection Source:</strong> ${escapeHtml(meta.source || 'Unknown')}</p>
    </div>
    <div class="status-info-card">
      <h4>Live Check</h4>
      <p>${escapeHtml(cfg.intro)}</p>
      <p>Checker is running, please wait...</p>
    </div>`;

  const payload  = buildEnumerationPayload();
  const endpoint = securityCheckerEndpoint(normalized);
  const cached   = securityCheckerLastResults[normalized];
  if (cached && cached._sessionId === securityCheckerSessionId) {
    renderCheckerSuccessPanel({ normalized, body, meta, stateText, stateClass, payload, endpoint, data: cached });
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) {
      body.innerHTML = `<div class="status-info-card"><h4>Current State</h4><p><strong>Status:</strong> <span class="stat-value ${stateClass}" style="font-size:16px;">${escapeHtml(stateText)}</span></p></div><div class="status-info-card"><h4>Checker Failed</h4><p><strong>Error:</strong> ${escapeHtml(data.error || 'Checker request failed')}</p></div>`;
      return;
    }
    data._sessionId = securityCheckerSessionId;
    securityCheckerLastResults[normalized] = data;
    renderCheckerSuccessPanel({ normalized, body, meta, stateText, stateClass, payload, endpoint, data });
  } catch (err) {
    body.innerHTML = `<div class="status-info-card"><h4>Current State</h4><p><strong>Status:</strong> <span class="stat-value ${stateClass}" style="font-size:16px;">${escapeHtml(stateText)}</span></p></div><div class="status-info-card"><h4>Request Failed</h4><p><strong>Error:</strong> ${escapeHtml(err.message || 'Checker request failed')}</p></div>`;
  }
}

/* ── Quick security probe (on connect) ── */
async function runQuickSecurityStatusProbe() {
  if (!state.connected) return;
  const payload = buildEnumerationPayload();
  try {
    const resp = await fetch(`${API_BASE}/api/security-status-quick`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) return;

    if (typeof data.kerberos_enabled !== 'boolean') {
      const targetIp = payload.ip || state.dc;
      if (targetIp) {
        try {
          const kResp = await fetch(`${API_BASE}/api/test`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: targetIp, protocol: 'kerberos' }),
          });
          const kData = await kResp.json();
          if (kResp.ok && kData?.port_open === true)  data.kerberos_enabled = true;
          else if (kData?.port_open === false)         data.kerberos_enabled = false;
        } catch (_) {}
      }
    }

    updateStats({
      ...data, domain: state.domain, dc: state.dc, username: state.user,
      os_version: document.getElementById('stat-os')?.textContent || '—',
      domain_level: document.getElementById('stat-level')?.textContent || '—',
      counts: null,
      meta: { profile_source: data.source || 'quick-port-probe' },
    });
    addLog('Quick security status probe completed (connect-time).', 'ok');
  } catch (_) {
    addLog('Quick security status probe skipped (backend unavailable).', 'warn');
  }
}