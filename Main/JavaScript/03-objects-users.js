/* ═══════════════════════════════════════════════════
   03-users.js
   Users tab: load, render, filter, detail panel,
   context menu, attack hint modal.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ── State ── */
let usersFilter = 'all';
let usersSearch = '';
let usersContextMenuEl      = null;
let usersContextTarget      = null;
let usersAttackHintModalEl  = null;

/* ── Helpers ── */
function decodeEncryptionTypes(val) {
  if (typeof val === 'undefined' || val === null) return [];
  const v = parseInt(val, 10);
  if (isNaN(v)) return [];
  return [
    { bit: 0x01, label: 'DES-CBC-CRC',                          strength: 'very-weak', risk: 'red',   note: 'Legacy — very weak' },
    { bit: 0x02, label: 'DES-CBC-MD5',                          strength: 'very-weak', risk: 'red',   note: 'Legacy — very weak' },
    { bit: 0x04, label: 'RC4-HMAC-MD5',                         strength: 'weak',      risk: 'red',   note: 'Weak — kerberoastable' },
    { bit: 0x08, label: 'AES128-CTS-HMAC-SHA1-96',              strength: 'medium',    risk: 'amber', note: 'Medium' },
    { bit: 0x10, label: 'AES256-CTS-HMAC-SHA1-96',              strength: 'strong',    risk: 'green', note: 'Strong' },
    { bit: 0x20, label: 'AES256-CTS-HMAC-SHA1-96-SK (2019+)',   strength: 'strong',    risk: 'green', note: 'Strong' },
  ].filter(t => v & t.bit);
}

function weakestEncryptionStrength(val) {
  const types = decodeEncryptionTypes(val);
  if (types.length === 0) return null;
  const rank = { 'very-weak': 0, 'weak': 1, 'medium': 2, 'strong': 3 };
  let weakest = types[0].strength || 'strong';
  types.forEach(t => {
    const s = t.strength || 'strong';
    if ((rank[s] ?? 99) < (rank[weakest] ?? 99)) weakest = s;
  });
  return weakest;
}

function encryptionBadgeClass(val) {
  const weakest = weakestEncryptionStrength(val);
  if (!weakest) return null;
  return ({
    'very-weak': 'yes-encryption-vweak',
    weak: 'yes-encryption-weak',
    medium: 'yes-encryption-medium',
    strong: 'yes-encryption-strong',
  })[weakest] || 'yes-encryption-medium';
}

/* ── Load ── */
async function loadUsers() {
  if (!state.connected) { addLog('Users: domain connection required', 'warn'); return; }
  document.getElementById('users-loading').style.display = 'flex';
  document.getElementById('u-table-body').innerHTML = '';
  closeDetail();

  try {
    const resp = await fetch(`${API_BASE}/api/users`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load users');

    usersData = data.users;
    usersMeta = data.meta || {};
    enumCacheLoaded.users = true;
    setObjectCountStat('cnt-users', usersData.length);
    document.getElementById('nav-users-count').textContent = usersData.length;
    document.getElementById('users-meta').textContent =
      `${usersData.length} users · domain: ${(state.domain || '').toUpperCase()}`;
    renderUsers();
    updatePentestCounts();
    addLog(`Users loaded: ${usersData.length} accounts enumerated`, 'ok');
  } catch (err) {
    addLog(`Users: ${err.message}`, 'err');
    document.getElementById('u-table-body').innerHTML = `<div class="u-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('users-loading').style.display = 'none';
  }
}

/* ── Render ── */
function renderUsers() {
  const body = document.getElementById('u-table-body');
  body.innerHTML = '';

  let list = usersData;
  if (usersSearch) {
    list = list.filter(u =>
      u.username.toLowerCase().includes(usersSearch) ||
      (u.sid || '').toLowerCase().includes(usersSearch)
    );
  }
  if (usersFilter === 'admin')    list = list.filter(u => u.is_admin);
  if (usersFilter === 'spn')      list = list.filter(u => u.spn && u.spn.length > 0);
  if (usersFilter === 'asrep')    list = list.filter(u => u.asrep);
  if (usersFilter === 'disabled') list = list.filter(u => u.disabled);
  if (usersFilter === 'nopwd')    list = list.filter(u => u.pwd_not_required);
  if (usersFilter === 'dcsync')   list = list.filter(u => u.dcsync);
  if (usersFilter === 'delegation') {
    list = list.filter(u => {
      const unconstrained = (typeof u.unconstrained_delegation === 'boolean')
        ? u.unconstrained_delegation
        : !!u.trusted_for_delegation;
      const constrained = (typeof u.constrained_delegation === 'boolean')
        ? u.constrained_delegation
        : !!(u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0);
      return unconstrained || constrained;
    });
  }
  if (usersFilter === 'encryption') list = list.filter(u => typeof u.msds_supportedencryptiontypes !== 'undefined' && u.msds_supportedencryptiontypes !== null);

  if (list.length === 0) { body.innerHTML = '<div class="u-empty"><p>No matching users</p></div>'; return; }

  list.forEach(u => {
    const row = document.createElement('div');
    const descHits = getSensitiveDescriptionMatches(u.description || '');
    const hasRiskDesc = descHits.length > 0;
    row.className = 'u-row' +
      (u.pwd_not_required ? ' nopwd'     : '') +
      (u.dcsync           ? ' dcsync'    : '') +
      (hasRiskDesc        ? ' desc-risk' : '');
    row.dataset.sam = u.username;

    const avatarCls = u.is_admin ? 'u-avatar admin' : u.disabled ? 'u-avatar disabled' : 'u-avatar';
    const initial   = u.username.charAt(0).toUpperCase();
    const sidFull   = u.sid || '—';
    const adminRuleLevels = Array.isArray(u.admin_rules)
      ? u.admin_rules.map(r => Number(r?.level)).filter(Number.isFinite)
      : [];
    const isPadAdmin = u.is_admin && adminRuleLevels.length > 0 &&
      adminRuleLevels.every(l => l === 2 || l === 10) &&
      adminRuleLevels.some(l => l === 2 || l === 10);
    const adminBadge = !u.is_admin
      ? '<span class="flag no">—</span>'
      : isPadAdmin
        ? '<span class="flag yes-admin-pad">PAD</span>'
        : '<span class="flag yes-admin">ADM</span>';

    row.innerHTML = `
      <div class="u-name">
        <div class="${avatarCls}">${initial}</div>
        ${u.username}
      </div>
      <div class="u-sid" title="${sidFull}">${sidFull}</div>
      <div class="u-flag-cell">${adminBadge}</div>
      <div class="u-flag-cell">${u.spn?.length > 0    ? '<span class="flag yes-spn">SPN</span>'   : '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${u.asrep              ? '<span class="flag yes-asrep">ASP</span>'   : '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${u.disabled           ? '<span class="flag yes-dis">DIS</span>'   : '<span class="flag yes-ok">●</span>'}</div>
      <div class="u-flag-cell">${u.pwd_not_required   ? '<span class="flag yes-nopwd">NP</span>'  : '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${u.dcsync             ? '<span class="flag yes-dcsync">DCS</span>': '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${(() => {
        const unconstrained = (typeof u.unconstrained_delegation === 'boolean')
          ? u.unconstrained_delegation
          : !!u.trusted_for_delegation;
        const constrained = (typeof u.constrained_delegation === 'boolean')
          ? u.constrained_delegation
          : !!(u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0);
        if (unconstrained) return '<span class="flag yes-delegation">UN</span>';
        if (constrained) return '<span class="flag yes-delegation">CN</span>';
        return '<span class="flag no">—</span>';
      })()}</div>
      <div class="u-flag-cell">${(() => {
        const cls = encryptionBadgeClass(u.msds_supportedencryptiontypes);
        return cls ? `<span class="flag ${cls}">ENC</span>` : '<span class="flag no">—</span>';
      })()}</div>
    `;
    row.addEventListener('click', () => openDetail(u, row));
    row.addEventListener('contextmenu', (e) => { e.preventDefault(); showUsersContextMenu(e, u, row); });
    body.appendChild(row);
  });
}

/* ── Filters ── */
function setFilter(f, btn) {
  usersFilter = f;
  document.querySelectorAll('#filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderUsers();
}

function filterUsers() {
  usersSearch = document.getElementById('users-search').value.toLowerCase();
  hideUsersContextMenu();
  renderUsers();
}

/* ── Detail panel ── */
function openDetail(u, row) {
  document.querySelectorAll('.u-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('user-detail').style.display = 'flex';
  document.getElementById('d-avatar').textContent = u.username.charAt(0).toUpperCase();
  document.getElementById('d-name').textContent   = u.username;
  document.getElementById('d-dn').textContent     = u.dn || '—';

  const body = document.getElementById('detail-body');
  body.innerHTML = '';

  const descHits = getSensitiveDescriptionMatches(u.description || '');
  const descriptionValue = u.description ? highlightSensitiveDescriptionTerms(u.description) : '—';

  body.innerHTML += detailSection('Identity', [
    ['Username',     u.username,                   'accent'],
    ['Display Name', u.display_name || '—',         u.display_name ? '' : 'dim'],
    ['SID',          u.sid          || '—',         u.sid ? '' : 'dim'],
    ['RID',          u.sid ? u.sid.split('-').pop() : '—', ''],
    ['UPN',          u.upn          || '—',         u.upn ? '' : 'dim'],
    ['Description',  descriptionValue,              u.description ? '' : 'dim'],
  ]);

  if (descHits.length > 0) {
    const chips = descHits.map(t => `<span class="desc-risk-chip">${escapeHtml(t)}</span>`).join('');
    body.innerHTML += `
      <div class="detail-section desc-risk-wave-box">
        <div class="detail-section-title" style="color:var(--red);">Description Risk Signals (${descHits.length})</div>
        <div class="desc-risk-chip-list">${chips}</div>
      </div>`;
  }

  body.innerHTML += detailSection('Account Flags', [
    ['Status',           u.disabled ? 'Disabled' : 'Enabled',                u.disabled ? 'red' : 'green'],
    ['Admin',            u.is_admin  ? 'Yes' : 'No',                          u.is_admin ? 'amber' : ''],
    ['DCSync Rights',    u.dcsync    ? 'YES ⚠ CRITICAL' : 'No',               u.dcsync ? 'red' : ''],
    ['Pre-Auth Req.',    u.preauth_required === false ? 'NOT Required (⚠ AS-REP)' : 'Required', u.preauth_required === false ? 'red' : 'green'],
    ['Pwd Not Required', u.pwd_not_required ? 'YES ⚠' : 'No',                 u.pwd_not_required ? 'red' : ''],
    ['Password Expired', u.pwd_expired ? 'Yes' : 'No',                        u.pwd_expired ? 'amber' : ''],
    ['Locked Out',       u.locked_out  ? 'Yes' : 'No',                        u.locked_out ? 'red' : ''],
    ['Must Change Pwd',  u.must_change_pwd ? 'Yes' : 'No',                    u.must_change_pwd ? 'amber' : ''],
    ['Pwd Never Expires',u.pwd_never_expires ? 'Yes' : 'No',                  u.pwd_never_expires ? 'amber' : ''],
    ['Delegatable (Uncons.)', ((typeof u.unconstrained_delegation === 'boolean') ? u.unconstrained_delegation : !!u.trusted_for_delegation) ? 'YES ⚠ CRITICAL' : 'No', ((typeof u.unconstrained_delegation === 'boolean') ? u.unconstrained_delegation : !!u.trusted_for_delegation) ? 'red' : ''],
    ['Constrained Deleg.',   ((typeof u.constrained_delegation === 'boolean') ? u.constrained_delegation : !!(u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0)) ? `YES ⚠ (${(u.msds_allowedtodelegateto || []).length} targets)` : 'No', ((typeof u.constrained_delegation === 'boolean') ? u.constrained_delegation : !!(u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0)) ? 'amber' : ''],
    ['Enc. Types Raw',       (typeof u.msds_supportedencryptiontypes !== 'undefined' && u.msds_supportedencryptiontypes !== null) ? `0x${parseInt(u.msds_supportedencryptiontypes, 10).toString(16).toUpperCase()} (${u.msds_supportedencryptiontypes})` : '—', ''],
  ]);

  body.innerHTML += detailSection('Timestamps', [
    ['Created',       fmtDate(u.when_created), ''],
    ['Last Modified', fmtDate(u.when_changed),  ''],
    ['Last Logon',    fmtDate(u.last_logon),    u.last_logon   ? '' : 'dim'],
    ['Pwd Last Set',  fmtDate(u.pwd_last_set),  u.pwd_last_set ? '' : 'dim'],
  ]);

  const groupsHtml = (u.member_of && u.member_of.length > 0)
    ? u.member_of.map(g => `<div class="group-item">${g}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  body.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">Member Of (${(u.member_of || []).length})</div>
      <div class="spn-list">${groupsHtml}</div>
    </div>`;

  // ── Admin Reason ─────────────────────────────────────────────────────────
  if (u.is_admin && u.admin_rules && u.admin_rules.length > 0) {
    const SEVERITY_META = {
      absolute: { label: 'Absolute Admin',         color: '#FF4444', bg: 'rgba(255,68,68,0.10)',  border: 'rgba(255,68,68,0.35)'  },
      tier1:    { label: 'Potential Admin Lvl 1',  color: '#FF8C00', bg: 'rgba(255,140,0,0.10)',  border: 'rgba(255,140,0,0.35)'  },
      tier2:    { label: 'Potential Admin Lvl 2',  color: '#FFD700', bg: 'rgba(255,215,0,0.08)',  border: 'rgba(255,215,0,0.30)'  },
      tier3:    { label: 'Potential Admin Lvl 3',  color: '#00BFFF', bg: 'rgba(0,191,255,0.08)',  border: 'rgba(0,191,255,0.28)'  },
    };

    const rulesHtml = u.admin_rules.map(rule => {
      const meta  = SEVERITY_META[rule.severity] || SEVERITY_META.tier2;
      const ruleNum = `Rule ${rule.level}`;

      // Rule 1 / Rule 2 üçün detail — hansı qruplar match etdi
      let detailHtml = '';
      if (rule.detail && rule.detail.matched_groups && rule.detail.matched_groups.length > 0) {
        const groups = rule.detail.matched_groups.map(g =>
          `<span class="admin-reason-group">${g}</span>`
        ).join('');
        detailHtml = `<div class="admin-reason-groups">${groups}</div>`;
      }

      return `
        <div class="admin-reason-rule" style="
          border-left: 3px solid ${meta.color};
          background: ${meta.bg};
          border-top: 1px solid ${meta.border};
          border-right: 1px solid ${meta.border};
          border-bottom: 1px solid ${meta.border};
        ">
          <div class="admin-reason-rule-head">
            <span class="admin-reason-badge" style="color:${meta.color};border-color:${meta.border};background:${meta.bg};">${ruleNum}</span>
            <span class="admin-reason-severity" style="color:${meta.color};">${meta.label}</span>
          </div>
          <div class="admin-reason-label">${rule.label}</div>
          ${detailHtml}
        </div>`;
    }).join('');

    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title" style="color:var(--amber);">Admin Reason (${u.admin_rules.length})</div>
        <div class="admin-reason-list">${rulesHtml}</div>
      </div>`;
  } else if (!u.is_admin) {
    // Admin deyilsə göstərmə
  }

  if (u.spn && u.spn.length > 0) {
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Service Principal Names (${u.spn.length})</div>
        <div class="spn-list">${u.spn.map(s => `<div class="spn-item">${s}</div>`).join('')}</div>
      </div>`;
  }

  if (u.risk_controls && u.risk_controls.length > 0) {
    const riskHtml = u.risk_controls.map(r => `<div class="badge amber">${r}</div>`).join('');
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Risk Controls</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${riskHtml}</div>
      </div>`;
  }

  // ── DG: Constrained Delegation targets ──────────────────────────────────
  if (u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0) {
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Constrained Delegation Targets (${u.msds_allowedtodelegateto.length})</div>
        <div class="spn-list">${u.msds_allowedtodelegateto.map(s => `<div class="delegation-item">${s}</div>`).join('')}</div>
      </div>`;
  }

  // ── ENC: Supported Encryption Types ─────────────────────────────────────
  const encTypes = decodeEncryptionTypes(u.msds_supportedencryptiontypes);
  if (encTypes.length > 0) {
    const hasWeak = encTypes.some(t => t.risk === 'red' || t.risk === 'amber');
    const encHtml = encTypes.map(t => `
      <div class="enc-type-row">
        <span class="enc-type-label">${t.label}</span>
        <span class="enc-type-note d-val ${t.risk}">${t.note}</span>
      </div>`).join('');
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title" ${hasWeak ? 'style="color:var(--amber)"' : ''}>
          Supported Encryption Types
          <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:9px;margin-left:4px;">(0x${parseInt(u.msds_supportedencryptiontypes, 10).toString(16).toUpperCase()})</span>
        </div>
        <div class="enc-type-list">${encHtml}</div>
      </div>`;
  }

}

function closeDetail() {
  document.getElementById('user-detail').style.display = 'none';
  document.querySelectorAll('.u-row').forEach(r => r.classList.remove('selected'));
}

/* ── Context menu ── */
function ensureUsersContextMenu() {
  if (usersContextMenuEl) return usersContextMenuEl;
  const menu = document.createElement('div');
  menu.className = 'user-ctx-menu';
  menu.innerHTML = `
    <button class="user-ctx-item" data-action="open-detail">Open Parameters</button>
    <button class="user-ctx-item" data-action="copy-json">Copy as JSON</button>
    <button class="user-ctx-item" data-action="copy-txt">Copy as TXT</button>
    <button class="user-ctx-item" data-action="copy-username">Copy Username</button>
    <button class="user-ctx-item" data-action="copy-sid">Copy SID</button>
    <div class="user-ctx-divider"></div>
    <button class="user-ctx-item" data-action="send-kerberoast">Send to Kerberoasting</button>
    <button class="user-ctx-item" data-action="send-asrep">Send to AS-REP Roasting</button>
    <button class="user-ctx-item" data-action="send-silver">Send to Silver Ticket</button>
    <button class="user-ctx-item" data-action="send-bruteforce">Send to Brute Force</button>
    <button class="user-ctx-item" data-action="send-dcsync">Send to DCSync</button>
    <div class="user-ctx-divider"></div>
    <button class="user-ctx-item" data-action="attack-hint">Attack Hint & Path</button>
  `;
  menu.addEventListener('click', (e) => {
    const btn = e.target.closest('.user-ctx-item');
    if (!btn || btn.disabled || btn.classList.contains('disabled')) return;
    runUsersContextAction(btn.dataset.action || '');
  });
  document.body.appendChild(menu);
  usersContextMenuEl = menu;
  document.addEventListener('click', (e) => {
    if (!usersContextMenuEl?.classList.contains('show')) return;
    if (!usersContextMenuEl.contains(e.target)) hideUsersContextMenu();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideUsersContextMenu(); });
  window.addEventListener('resize', hideUsersContextMenu);
  window.addEventListener('scroll', hideUsersContextMenu, true);
  return usersContextMenuEl;
}

function hideUsersContextMenu() {
  if (!usersContextMenuEl) return;
  usersContextMenuEl.classList.remove('show');
  usersContextTarget = null;
}

function showUsersContextMenu(e, u, row) {
  const menu = ensureUsersContextMenu();
  usersContextTarget = { u, row };
  syncUsersContextMenuActions(u);
  menu.classList.add('show');
  const pad = 8, mw = menu.offsetWidth || 200, mh = menu.offsetHeight || 170;
  let x = Math.min(e.clientX, window.innerWidth  - mw - pad);
  let y = Math.min(e.clientY, window.innerHeight - mh - pad);
  menu.style.left = `${Math.max(pad, x)}px`;
  menu.style.top  = `${Math.max(pad, y)}px`;
}

function getEnabledSendActions(u) {
  const actions = new Set(['send-bruteforce']);
  if (u.asrep) actions.add('send-asrep');
  if (u.dcsync) actions.add('send-dcsync');
  if (u.spn && u.spn.length > 0) { actions.add('send-kerberoast'); actions.add('send-silver'); }
  return actions;
}

function syncUsersContextMenuActions(u) {
  if (!usersContextMenuEl) return;
  const enabled = getEnabledSendActions(u);
  usersContextMenuEl.querySelectorAll('.user-ctx-item[data-action^="send-"]').forEach(btn => {
    const on = enabled.has(btn.dataset.action || '');
    btn.disabled = !on;
    btn.classList.toggle('disabled', !on);
  });
}

function formatUserAsTxt(u) {
  return [
    `Username: ${u.username || '—'}`,
    `Display Name: ${u.display_name || '—'}`,
    `SID: ${u.sid || '—'}`,
    `UPN: ${u.upn || '—'}`,
    `Admin: ${u.is_admin ? 'Yes' : 'No'}`,
    `DCSync: ${u.dcsync ? 'Yes' : 'No'}`,
    `No Password Required: ${u.pwd_not_required ? 'Yes' : 'No'}`,
    `Disabled: ${u.disabled ? 'Yes' : 'No'}`,
    `SPN Count: ${(u.spn || []).length}`,
    `Groups: ${(u.member_of || []).join(', ') || '—'}`,
    `Delegation Targets (DG): ${(u.msds_allowedtodelegateto || []).join(', ') || '—'}`,
    `Encryption Types (ENC): ${(typeof u.msds_supportedencryptiontypes !== 'undefined' && u.msds_supportedencryptiontypes !== null) ? `0x${parseInt(u.msds_supportedencryptiontypes, 10).toString(16).toUpperCase()} — ${decodeEncryptionTypes(u.msds_supportedencryptiontypes).map(t => t.label).join(', ')}` : '—'}`,
  ].join('\n');
}

function runUsersContextAction(action) {
  if (!usersContextTarget) return;
  const { u, row } = usersContextTarget;
  const label = u.username || 'unknown';
  const enabled = getEnabledSendActions(u);
  if (action.startsWith('send-') && !enabled.has(action)) {
    showToast('This action is not available for selected user', 'info');
    return;
  }
  const map = {
    'open-detail':    () => { openDetail(u, row); },
    'copy-json':      () => copyTextValue(JSON.stringify(u, null, 2), 'JSON'),
    'copy-txt':       () => copyTextValue(formatUserAsTxt(u), 'TXT'),
    'copy-username':  () => copyTextValue(u.username || '', 'Username'),
    'copy-sid':       () => copyTextValue(u.sid || '', 'SID'),
    'send-kerberoast':() => { addLog(`Context dispatch: ${label} -> Kerberoasting`, 'info'); showToast(`Sent ${label} to Kerberoasting`, 'info'); runKerberoasting(); },
    'send-asrep':     () => { addLog(`Context dispatch: ${label} -> AS-REP Roasting`, 'info'); showToast(`Sent ${label} to AS-REP Roasting`, 'info'); runASREPRoasting(); },
    'send-silver':    () => { addLog(`Context dispatch: ${label} -> Silver Ticket`, 'info'); showToast(`Sent ${label} to Silver Ticket`, 'info'); runSilverTicket(); },
    'send-bruteforce':() => { addLog(`Context dispatch: ${label} -> Brute Force`, 'info'); showToast(`Sent ${label} to Brute Force`, 'info'); runBruteForce(); },
    'send-dcsync':    () => { addLog(`Context dispatch: ${label} -> DCSync`, 'info'); showToast(`Sent ${label} to DCSync`, 'info'); runDCSync(); },
    'attack-hint':    () => { showAttackHintModal(); addLog(`Attack Hint panel opened for ${label}`, 'info'); },
  };
  if (map[action]) map[action]();
  hideUsersContextMenu();
}

/* ── Attack Hint modal ── */
function ensureAttackHintModal() {
  if (usersAttackHintModalEl) return usersAttackHintModalEl;
  const modal = document.createElement('div');
  modal.className = 'attack-hint-modal';
  modal.innerHTML = `
    <div class="attack-hint-modal-panel" role="dialog" aria-modal="true" aria-label="Attack Hint & Path">
      <div class="attack-hint-modal-head">
        <div class="attack-hint-modal-title">Attack Hint & Path</div>
        <button class="attack-hint-modal-close" type="button" data-action="close-attack-hint">✕</button>
      </div>
      <div class="attack-hint-modal-body"></div>
    </div>`;
  modal.addEventListener('click', (e) => {
    if (e.target === modal || e.target.closest('[data-action="close-attack-hint"]')) hideAttackHintModal();
  });
  document.body.appendChild(modal);
  usersAttackHintModalEl = modal;
  return modal;
}

function showAttackHintModal() { ensureAttackHintModal().classList.add('show'); }
function hideAttackHintModal() { usersAttackHintModalEl?.classList.remove('show'); }