let usersFilter = 'all';
let usersSearch = '';
let usersContextMenuEl      = null;
let usersContextTarget      = null;
let usersAttackHintModalEl  = null;


let domainsListCache   = null;
let domainsSelected    = null;
let domainsDropdownOpen = false;


function parsePythonBytesLiteralToArray(str) {
  if (typeof str !== 'string') return null;
  const s = str.trim();
  const m = s.match(/^b(['"])([\s\S]*)\1$/);
  if (!m) return null;
  const body = m[2];
  const bytes = [];
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '\\' && i + 1 < body.length) {
      const next = body[i + 1];
      if (next === 'x' && i + 3 < body.length) {
        bytes.push(parseInt(body.substr(i + 2, 2), 16));
        i += 3;
      } else {
        const map = { n: 0x0a, r: 0x0d, t: 0x09, '\\': 0x5c, "'": 0x27, '"': 0x22, '0': 0x00, a: 0x07, b: 0x08, f: 0x0c, v: 0x0b };
        bytes.push(map[next] !== undefined ? map[next] : (next.charCodeAt(0) & 0xff));
        i += 1;
      }
    } else {
      bytes.push(ch.charCodeAt(0) & 0xff);
    }
  }
  return bytes;
}

function sidBytesToString(bytes) {
  if (!Array.isArray(bytes) || bytes.length < 8) return null;
  const revision = bytes[0];
  const subCount = bytes[1];
  let idAuth = 0n;
  for (let i = 2; i < 8; i++) idAuth = (idAuth << 8n) | BigInt(bytes[i]);
  const subs = [];
  for (let i = 0; i < subCount; i++) {
    const off = 8 + i * 4;
    if (off + 4 > bytes.length) break;
    const sub = (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] * 0x1000000)) >>> 0;
    subs.push(sub);
  }
  if (subs.length === 0) return null;
  return `S-${revision}-${idAuth.toString()}-${subs.join('-')}`;
}


function normalizeTrustSid(rawSid) {
  if (!rawSid) return null;
  const s = String(rawSid).trim();
  if (/^S-\d/i.test(s)) return s.toUpperCase();
  const bytes = parsePythonBytesLiteralToArray(s);
  if (!bytes) return null;
  return sidBytesToString(bytes);
}


function guessCurrentDomainSid() {
  if (!Array.isArray(usersData) || usersData.length === 0) return null;
  const counts = new Map();
  usersData.forEach(u => {
    const sid = (u.domain_sid || '').trim();
    if (!sid) return;
    counts.set(sid, (counts.get(sid) || 0) + 1);
  });
  let best = null, bestCount = 0;
  counts.forEach((count, sid) => { if (count > bestCount) { best = sid; bestCount = count; } });
  return best;
}

function domainNameToDcSuffix(name) {
  return (name || '')
    .toLowerCase()
    .split('.')
    .filter(Boolean)
    .map(p => `dc=${p}`)
    .join(',');
}

function userBelongsToDomain(u, domain) {

  if (domain.sid) {
    return (u.domain_sid || '').trim().toUpperCase() === domain.sid.toUpperCase();
  }

  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return (u.dn || '').toLowerCase().endsWith(suffix);
}

async function fetchTrustsForDomainsDropdown() {
  const url = `${DB_BASE}/api/list/trusts?limit=500`;
  const resp = await fetch(url, { method: 'GET' });
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data) {
    throw new Error((data && (data.error || data.detail)) || `Oxsium SQLite Engine error (HTTP ${resp.status})`);
  }
  const raw = Array.isArray(data.records) ? data.records : (Array.isArray(data.rows) ? data.rows : []);
  return raw
    .map(t => ({ name: t.name, sid: normalizeTrustSid(t.sid) }))
    .filter(t => !!t.name);
}

async function ensureDomainsListLoaded() {
  if (domainsListCache) return domainsListCache;

  const currentDomain = (state.domain || '').trim();
  const currentDomainSid = guessCurrentDomainSid();
  let trusts = [];
  try {
    trusts = await fetchTrustsForDomainsDropdown();
  } catch (err) {
    addLog(`Select Domains: ${err.message}`, 'err');
  }

  const seen = new Set();
  const list = [];
  if (currentDomain) {
    list.push({ name: currentDomain, isCurrent: true, sid: currentDomainSid });
    seen.add(currentDomain.toLowerCase());
  }
  trusts.forEach(t => {
    const key = (t.name || '').toLowerCase();
    if (!key || seen.has(key)) return;
    seen.add(key);
    list.push({ name: t.name, isCurrent: false, sid: t.sid });
  });

  domainsListCache = list;
  if (!domainsSelected) {
    domainsSelected = new Set(list.map(d => d.name.toLowerCase()));
  }
  return list;
}

function renderDomainsDropdownList() {
  const listEl = document.getElementById('domains-dropdown-list');
  if (!listEl) return;

  if (!domainsListCache || domainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = domainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = domainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleDomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateDomainsSelectCount();
}

function updateDomainsSelectCount() {
  const countEl = document.getElementById('domains-select-count');
  if (!countEl || !domainsListCache) return;
  const total = domainsListCache.length;
  const selected = domainsSelected ? domainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

async function toggleDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('domains-dropdown');
  if (!dd) return;

  if (domainsDropdownOpen) {
    closeDomainsDropdown();
    return;
  }

  domainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureDomainsListLoaded();
    renderDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleDomainsDropdownEscape);
}

function closeDomainsDropdown() {
  domainsDropdownOpen = false;
  const dd = document.getElementById('domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleDomainsDropdownEscape);
}

function handleDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeDomainsDropdown();
}

function handleDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeDomainsDropdown();
}

function toggleDomainSelected(domainKey, checked) {
  if (!domainsSelected) domainsSelected = new Set();
  if (checked) domainsSelected.add(domainKey);
  else domainsSelected.delete(domainKey);
  updateDomainsSelectCount();
  renderUsers();
}

function resetDomainsSelection() {
  if (!domainsListCache) return;
  domainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
  renderDomainsDropdownList();
  renderUsers();
}


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


async function loadUsers() {
  document.getElementById('users-loading').style.display = 'flex';
  document.getElementById('u-table-body').innerHTML = '';
  closeDetail();


  domainsListCache = null;
  domainsSelected  = null;

  try {


    let url = `${DB_BASE}/api/list/users?limit=100000`;
    if (usersSearch && usersSearch.trim()) {
      url += `&q=${encodeURIComponent(usersSearch.trim())}`;
    }

    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      throw new Error((data && (data.error || data.detail)) || `Oxsium SQLite Engine error (HTTP ${resp.status})`);
    }

    usersData = Array.isArray(data.records) ? data.records : (Array.isArray(data.rows) ? data.rows : []);
    enumCacheLoaded.users = true;


    const nonDeletedCount = usersData.filter(u => !u.deleted).length;
    const deletedCount    = usersData.length - nonDeletedCount;

    setObjectCountStat('cnt-users', nonDeletedCount);
    document.getElementById('nav-users-count').textContent = nonDeletedCount;
    document.getElementById('users-meta').textContent =
      `${nonDeletedCount} users` +
      (deletedCount > 0 ? ` · ${deletedCount} deleted (Recycle Bin)` : '') +
      ` · source: Oxsium SQLite Engine (.db)`;

    addLog(`Users loaded from sqlite_reader.py: ${nonDeletedCount} accounts` +
      (deletedCount > 0 ? ` (+${deletedCount} deleted)` : '') +
      ` (Oxsium SQLite Engine)`, 'ok');
    renderUsers();
    updatePentestCounts();
  } catch (err) {
    addLog(`Users: ${err.message}`, 'err');
    document.getElementById('u-table-body').innerHTML = `<div class="u-empty"><p>${escapeHtml(err.message)}</p></div>`;
  } finally {
    document.getElementById('users-loading').style.display = 'none';
  }
}


function renderUsers() {
  const body = document.getElementById('u-table-body');
  body.innerHTML = '';

  let list = usersData;
  if (domainsListCache && domainsSelected && domainsSelected.size < domainsListCache.length) {
    const activeDomains = domainsListCache.filter(d => domainsSelected.has(d.name.toLowerCase()));
    list = list.filter(u => activeDomains.some(d => userBelongsToDomain(u, d)));
  }
  if (usersSearch) {
    list = list.filter(u =>
      u.username.toLowerCase().includes(usersSearch) ||
      (u.sid || '').toLowerCase().includes(usersSearch)
    );
  }
  if (usersFilter === 'deleted') {

    list = list.filter(u => u.deleted);
  } else {


    list = list.filter(u => !u.deleted);
    if (usersFilter === 'admin')    list = list.filter(u => u.is_admin || !!u.potential_admin);
    if (usersFilter === 'spn')      list = list.filter(u => u.spn && u.spn.length > 0);
    if (usersFilter === 'asrep')    list = list.filter(u => u.asrep);
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
  }

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

    const isPadAdmin = u.potential_admin === 'PAD';
    const isAbsAdmin = !isPadAdmin && !!u.is_admin;
    const avatarCls  = u.deleted ? 'u-avatar deleted'
                     : isAbsAdmin  ? 'u-avatar admin'
                     : isPadAdmin  ? 'u-avatar pad'
                     : u.disabled  ? 'u-avatar disabled'
                     :               'u-avatar';
    const initial   = u.username.charAt(0).toUpperCase();
    const sidFull   = u.sid || '—';
    const adminBadge = isPadAdmin
      ? '<span class="flag yes-admin-pad">PAD</span>'
      : isAbsAdmin
        ? '<span class="flag yes-admin">ADM</span>'
        : '<span class="flag no">—</span>';

    row.innerHTML = `
      <div class="u-name">
        <div class="${avatarCls}">${initial}</div>
        ${u.username}
      </div>
      <div class="u-sid" title="${sidFull}">${sidFull}</div>
      <div class="u-flag-cell">${adminBadge}</div>
      <div class="u-flag-cell">${u.spn?.length > 0    ? '<span class="flag yes-spn">SPN</span>'   : '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${u.asrep              ? '<span class="flag yes-asrep">ASP</span>'   : '<span class="flag no">—</span>'}</div>
      <div class="u-flag-cell">${u.deleted ? '<span class="flag yes-deleted">DEL</span>' : (u.disabled ? '<span class="flag yes-dis">DIS</span>' : '<span class="flag yes-ok">●</span>')}</div>
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


function openDetail(u, row) {
  document.querySelectorAll('.u-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('user-detail').style.display = 'flex';
  document.getElementById('d-avatar').textContent = u.username.charAt(0).toUpperCase();
  document.getElementById('d-name').textContent   = u.username;
  document.getElementById('d-dn').textContent     = u.dn || '—';

  const isPadAdmin = u.potential_admin === 'PAD';
  const isAbsAdmin = !isPadAdmin && !!u.is_admin;

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
    ['Status',           u.deleted ? 'Deleted (Recycle Bin)' : (u.disabled ? 'Disabled' : 'Enabled'), (u.deleted || u.disabled) ? 'red' : 'green'],
    ['Admin',
      isAbsAdmin ? 'Yes — Absolute Admin'
      : isPadAdmin ? `Potential (${u.potential_admin})`
      : 'No',
      isAbsAdmin ? 'red' : isPadAdmin ? 'amber' : ''],
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


  if ((isAbsAdmin || isPadAdmin) && u.admin_rules && u.admin_rules.length > 0) {
    const SEVERITY_META = {
      absolute: { label: 'Absolute Admin',         color: '#FF4444', bg: 'rgba(255,68,68,0.10)',  border: 'rgba(255,68,68,0.35)'  },
      tier1:    { label: 'Potential Admin Lvl 1',  color: '#FF8C00', bg: 'rgba(255,140,0,0.10)',  border: 'rgba(255,140,0,0.35)'  },
      tier2:    { label: 'Potential Admin Lvl 2',  color: '#FFD700', bg: 'rgba(255,215,0,0.08)',  border: 'rgba(255,215,0,0.30)'  },
      tier3:    { label: 'Potential Admin Lvl 3',  color: '#00BFFF', bg: 'rgba(0,191,255,0.08)',  border: 'rgba(0,191,255,0.28)'  },
    };

    const rulesHtml = u.admin_rules.map(rule => {
      const meta  = SEVERITY_META[rule.severity] || SEVERITY_META.tier2;
      const ruleNum = `Rule ${rule.level}`;


      const ruleDetail = rule.detail_json || rule.detail;
      let detailHtml = '';
      if (ruleDetail && ruleDetail.matched_groups && ruleDetail.matched_groups.length > 0) {
        const groups = ruleDetail.matched_groups.map(g =>
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
        <div class="detail-section-title" style="color:${isAbsAdmin ? 'var(--red)' : 'var(--amber)'};">
          ${isAbsAdmin ? 'Absolute Admin Reason' : 'Potential Admin Reason'} (${u.admin_rules.length})
        </div>
        <div class="admin-reason-list">${rulesHtml}</div>
      </div>`;
  } else if (!isAbsAdmin) {

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


  if (u.msds_allowedtodelegateto && u.msds_allowedtodelegateto.length > 0) {
    body.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Constrained Delegation Targets (${u.msds_allowedtodelegateto.length})</div>
        <div class="spn-list">${u.msds_allowedtodelegateto.map(s => `<div class="delegation-item">${s}</div>`).join('')}</div>
      </div>`;
  }


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
    `Deleted (Recycle Bin): ${u.deleted ? 'Yes' : 'No'}`,
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
    'attack-hint':    () => { showAttackHintModal(); addLog(`Attack Hint panel opened for ${label}`, 'info'); },
  };
  if (map[action]) map[action]();
  hideUsersContextMenu();
}


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