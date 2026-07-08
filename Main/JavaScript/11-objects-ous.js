let ousFilter = 'all';
let ousSearch = '';

let ousDomainsSelected     = null;   
let ousDomainsDropdownOpen = false;

function ouBelongsToDomain(ou, domain) {
  const dn  = ou.dn || ou.path || '';
  const sid = ou.sid || '';
  if (domain.sid && sid) {
    const s  = String(sid).trim().toUpperCase();
    const ds = domain.sid.toUpperCase();
    if (s === ds || s.startsWith(ds + '-')) return true;
  }
  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return dn.toLowerCase().endsWith(suffix);
}

async function toggleOUsDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('ou-domains-dropdown');
  if (!dd) return;

  if (ousDomainsDropdownOpen) {
    closeOUsDomainsDropdown();
    return;
  }

  ousDomainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('ou-domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureDomainsListLoaded();
    if (!ousDomainsSelected) {
      ousDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
    }
    renderOUsDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleOUsDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleOUsDomainsDropdownEscape);
}

function closeOUsDomainsDropdown() {
  ousDomainsDropdownOpen = false;
  const dd = document.getElementById('ou-domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleOUsDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleOUsDomainsDropdownEscape);
}

function handleOUsDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('ou-domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeOUsDomainsDropdown();
}

function handleOUsDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeOUsDomainsDropdown();
}

function renderOUsDomainsDropdownList() {
  const listEl = document.getElementById('ou-domains-dropdown-list');
  if (!listEl) return;

  if (!domainsListCache || domainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = domainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = ousDomainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleOUDomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateOUsDomainsSelectCount();
}

function updateOUsDomainsSelectCount() {
  const countEl = document.getElementById('ou-domains-select-count');
  if (!countEl || !domainsListCache) return;
  const total = domainsListCache.length;
  const selected = ousDomainsSelected ? ousDomainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

function toggleOUDomainSelected(domainKey, checked) {
  if (!ousDomainsSelected) ousDomainsSelected = new Set();
  if (checked) ousDomainsSelected.add(domainKey);
  else ousDomainsSelected.delete(domainKey);
  updateOUsDomainsSelectCount();
  renderOUs();
}

function resetOUsDomainsSelection() {
  if (!domainsListCache) return;
  ousDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
  renderOUsDomainsDropdownList();
  renderOUs();
}

const ouObjectsCache   = new Map();
const ouObjectsLoading = new Set(); 

async function fetchOUObjects(ou) {
  const cacheKey = String(ou?.rowid ?? ou?.id ?? ou?.dn ?? '');
  if (!cacheKey) return { users: [], computers: [], groups: [] };

  if (ouObjectsCache.has(cacheKey)) return ouObjectsCache.get(cacheKey);
  if (ouObjectsLoading.has(cacheKey)) {
    await new Promise(res => {
      const wait = setInterval(() => {
        if (!ouObjectsLoading.has(cacheKey)) { clearInterval(wait); res(); }
      }, 50);
    });
    return ouObjectsCache.get(cacheKey) || { users: [], computers: [], groups: [] };
  }

  ouObjectsLoading.add(cacheKey);
  try {
    const ouDN = ou?.dn || ou?.path || '';
    if (!ouDN) throw new Error('OU DN not available');

    const safeDN = ouDN.replace(/'/g, "''");
    const pattern = `%,${safeDN}`;

    const queryURL = `${DB_BASE}/api/query`;

    const [uResp, cResp, gResp] = await Promise.all([
      fetch(queryURL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sql: `SELECT id, username AS name, dn, sid, disabled, is_admin FROM users WHERE dn LIKE '${pattern}'`
        }),
      }),
      fetch(queryURL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sql: `SELECT id, computer_name AS name, dn, sid, disabled, os FROM computers WHERE dn LIKE '${pattern}'`
        }),
      }),
      fetch(queryURL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sql: `SELECT id, group_name AS name, group_dn AS dn, group_sid AS sid, member_count, is_privileged FROM groups WHERE group_dn LIKE '${pattern}'`
        }),
      }),
    ]);

    const [uData, cData, gData] = await Promise.all([
      uResp.json().catch(() => ({ rows: [] })),
      cResp.json().catch(() => ({ rows: [] })),
      gResp.json().catch(() => ({ rows: [] })),
    ]);

    const result = {
      users: (uData.rows || []).map(r => ({
        name:    r.name     || r.username || '—',
        dn:      r.dn       || '',
        sid:     r.sid      || '—',
        disabled: !!r.disabled,
        isAdmin: !!r.is_admin,
        type:    'user',
      })),
      computers: (cData.rows || []).map(r => ({
        name:    r.name     || r.computer_name || '—',
        dn:      r.dn       || '',
        sid:     r.sid      || '—',
        disabled: !!r.disabled,
        os:      r.os       || '',
        type:    'computer',
      })),
      groups: (gData.rows || []).map(r => ({
        name:        r.name        || r.group_name  || '—',
        dn:          r.dn          || r.group_dn    || '',
        sid:         r.sid         || r.group_sid   || '—',
        memberCount: r.member_count ?? 0,
        isPrivileged: !!r.is_privileged,
        type:        'group',
      })),
    };

    ouObjectsCache.set(cacheKey, result);
    return result;
  } catch (err) {
    const empty = { users: [], computers: [], groups: [] };
    ouObjectsCache.set(cacheKey, empty);
    return empty;
  } finally {
    ouObjectsLoading.delete(cacheKey);
  }
}

function renderOUObjectsRow(row, objects) {
  if (!row) return;
  const { users = [], computers = [], groups = [] } = objects;
  const total = users.length + computers.length + groups.length;
  if (total === 0) {
    row.innerHTML = '<div class="ou-obj-empty">No objects found in this OU.</div>';
    return;
  }
  let html = '';

  const _icon = (src, alt) =>
    `<img class="ou-obj-icon" src="assets/Icons/${src}" alt="${alt}" onerror="this.onerror=null;this.src='assets/favicon.png'">`;

  if (users.length > 0) {
    html += `<div class="ou-obj-section-title">${_icon('user.png','User')} Users (${users.length})</div>`;
    html += `<div class="ou-obj-head"><span>Name</span><span>SID</span></div>`;
    html += users.map(u => `
      <div class="ou-obj-item">
        <span class="ou-obj-name${u.isAdmin ? ' ou-obj-admin' : ''}${u.disabled ? ' ou-obj-disabled' : ''}">
          ${_icon('user.png', 'User')}${escapeHtml(u.name)}${u.isAdmin ? ' <span class="ou-obj-badge red">Admin</span>' : ''}${u.disabled ? ' <span class="ou-obj-badge dim">Disabled</span>' : ''}
        </span>
        <span class="ou-obj-sid">${escapeHtml(u.sid)}</span>
      </div>`).join('');
  }

  if (computers.length > 0) {
    html += `<div class="ou-obj-section-title">${_icon('computer.png','Computer')} Computers (${computers.length})</div>`;
    html += `<div class="ou-obj-head"><span>Name</span><span>SID</span></div>`;
    html += computers.map(c => `
      <div class="ou-obj-item">
        <span class="ou-obj-name${c.disabled ? ' ou-obj-disabled' : ''}">
          ${_icon('computer.png','Computer')}${escapeHtml(c.name)}${c.os ? ` <span class="ou-obj-os">${escapeHtml(c.os)}</span>` : ''}${c.disabled ? ' <span class="ou-obj-badge dim">Disabled</span>' : ''}
        </span>
        <span class="ou-obj-sid">${escapeHtml(c.sid)}</span>
      </div>`).join('');
  }

  if (groups.length > 0) {
    html += `<div class="ou-obj-section-title">${_icon('group.png','Group')} Groups (${groups.length})</div>`;
    html += `<div class="ou-obj-head"><span>Name</span><span>Members</span></div>`;
    html += groups.map(g => `
      <div class="ou-obj-item">
        <span class="ou-obj-name">
          ${_icon('group.png','Group')}${escapeHtml(g.name)}${g.isPrivileged ? ' <span class="ou-obj-badge amber">Privileged</span>' : ''}
        </span>
        <span class="ou-obj-sid">${g.memberCount ?? 0}</span>
      </div>`).join('');
  }

  row.innerHTML = html;
}

async function toggleOUObjects(btn, objRowId, ou) {
  const row = document.getElementById(objRowId);
  if (!row) return;
  const isOpen = row.style.display === 'block';
  row.style.display = isOpen ? 'none' : 'block';
  btn.classList.toggle('open', !isOpen);

  if (!isOpen) {
    const cacheKey = String(ou?.rowid ?? ou?.id ?? ou?.dn ?? '');
    if (cacheKey && ouObjectsCache.has(cacheKey)) {
      renderOUObjectsRow(row, ouObjectsCache.get(cacheKey));
      return;
    }
    row.innerHTML = '<div class="ou-obj-empty">Loading objects...</div>';
    try {
      const objects = await fetchOUObjects(ou);
      renderOUObjectsRow(row, objects);
      const countSpan = btn.querySelector('span:last-child');
      if (countSpan) {
        const total = (objects.users?.length || 0) + (objects.computers?.length || 0) + (objects.groups?.length || 0);
        countSpan.textContent = String(total);
      }
    } catch (err) {
      row.innerHTML = `<div class="ou-obj-empty">${escapeHtml(err.message || 'Failed to load objects')}</div>`;
    }
  }
}

async function loadOUs() {
  document.getElementById('ous-loading').style.display = 'flex';
  document.getElementById('o-table-body').innerHTML = '';
  closeOUDetail();

  ousDomainsSelected = null;

  const snap = await tryLoadSnapshotSection('ous');
  if (snap) {
    ousData = snap.records;
    enumCacheLoaded.ous = true;
    setObjectCountStat('cnt-ous', ousData.length);
    document.getElementById('nav-ous-count').textContent = ousData.length;
    document.getElementById('ous-meta').textContent =
      `${ousData.length} OUs · source: Domain Object snapshot`;
    renderOUs();
    addLog(`OUs loaded from Domain Object snapshot: ${ousData.length} organizational units`, 'ok');
    document.getElementById('ous-loading').style.display = 'none';
    return;
  }

  if (!state.connected) {
    addLog('OUs: no snapshot found, domain connection required', 'warn');
    document.getElementById('o-table-body').innerHTML = '<div class="o-empty"><p>Connect to a domain first or Import collector ZIP</p></div>';
    document.getElementById('ous-loading').style.display = 'none';
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/ous`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load OUs');
    ousData = data.ous || data.organizational_units || [];
    enumCacheLoaded.ous = true;
    setObjectCountStat('cnt-ous', ousData.length);
    document.getElementById('nav-ous-count').textContent = ousData.length;
    document.getElementById('ous-meta').textContent = `${ousData.length} OUs · domain: ${(state.domain || '').toUpperCase()}`;
    renderOUs();
    addLog(`OUs loaded: ${ousData.length} organizational units enumerated`, 'ok');
  } catch (err) {
    addLog(`OUs: ${err.message}`, 'err');
    document.getElementById('o-table-body').innerHTML = `<div class="o-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('ous-loading').style.display = 'none';
  }
}

function renderOUs() {
  const body = document.getElementById('o-table-body');
  let list = ousData;
  if (domainsListCache && ousDomainsSelected && ousDomainsSelected.size < domainsListCache.length) {
    const activeDomains = domainsListCache.filter(d => ousDomainsSelected.has(d.name.toLowerCase()));
    list = list.filter(ou => activeDomains.some(d => ouBelongsToDomain(ou, d)));
  }
  if (ousSearch) list = list.filter(ou =>
    (ou.name || '').toLowerCase().includes(ousSearch) ||
    (ou.path || '').toLowerCase().includes(ousSearch) ||
    (ou.description || '').toLowerCase().includes(ousSearch)
  );
  if (ousFilter === 'linked-gpo')   list = list.filter(ou => !!ou.has_gpo_links);
  if (ousFilter === 'inheritance')  list = list.filter(ou => !!ou.inheritance_blocked);
  if (ousFilter === 'permissions')  list = list.filter(ou => !!ou.delegated_permissions);
  filteredOUs = list;
  body.innerHTML = '';
  if (filteredOUs.length === 0) { body.innerHTML = '<div class="o-empty"><p>No matching OUs</p></div>'; return; }

  filteredOUs.forEach(ou => {
    const row = document.createElement('div');
    row.className = 'o-row';
    row.addEventListener('click', () => showOUDetail(ou, row));

    const objCount   = ou.object_count ?? ou.objectCount ?? ou.count ?? '—';
    const inheritVal = ou.inheritance_blocked ? 'Blocked' : 'Enabled';
    const inheritCls = ou.inheritance_blocked ? 'blocked' : 'enabled';
    const objRowId   = `ou-objects-${Math.random().toString(36).slice(2)}`;

    const cellName = document.createElement('div');
    cellName.className = 'o-cell o-cell-name';
    cellName.textContent = ou.name || '—';

    const cellPath = document.createElement('div');
    cellPath.className = 'o-cell o-cell-path';
    cellPath.title = ou.path || '';
    cellPath.textContent = ou.path || '—';

    const cellObjCount = document.createElement('div');
    cellObjCount.className = 'o-cell o-cell-objcount';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'gr-members-toggle';   /* Groups-dan eyni stil sinifi */
    toggleBtn.type = 'button';
    toggleBtn.title = 'Show OU objects';

    const arrowSpan = document.createElement('span');
    arrowSpan.className = 'gr-arrow';
    arrowSpan.textContent = '▾';

    const countSpan = document.createElement('span');
    countSpan.textContent = String(objCount);

    toggleBtn.appendChild(arrowSpan);
    toggleBtn.appendChild(countSpan);
    toggleBtn.addEventListener('click', e => {
      e.stopPropagation();
      toggleOUObjects(toggleBtn, objRowId, ou);
    });
    cellObjCount.appendChild(toggleBtn);

    const cellInherit = document.createElement('div');
    cellInherit.className = `o-cell o-cell-inherit ${inheritCls}`;
    cellInherit.textContent = inheritVal;

    const cellManaged = document.createElement('div');
    cellManaged.className = 'o-cell o-cell-managed';
    cellManaged.title = ou.managed_by || '';
    cellManaged.textContent = ou.managed_by || '—';

    row.appendChild(cellName);
    row.appendChild(cellPath);
    row.appendChild(cellObjCount);
    row.appendChild(cellInherit);
    row.appendChild(cellManaged);

    body.appendChild(row);

    const objRow = document.createElement('div');
    objRow.id = objRowId;
    objRow.className = 'ou-objects-row';
    objRow.style.display = 'none';
    objRow.innerHTML = '<div class="ou-obj-empty">Click ▾ to load objects.</div>';
    body.appendChild(objRow);
  });
}

function filterOUs() { ousSearch = (document.getElementById('ous-search').value || '').toLowerCase(); renderOUs(); }
function setOUFilter(filter, btn) {
  ousFilter = filter;
  document.querySelectorAll('#ou-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderOUs();
}

function showOUDetail(ou, row) {
  document.querySelectorAll('.o-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  const gpoLinks = Array.isArray(ou.gpo_links) ? ou.gpo_links : [];
  const sb = document.getElementById('ou-status-bar');
  if (sb) {
    sb.style.display = 'flex';
    const _sbSet = (id, val, cls) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = val || '—';
      if (cls) el.className = `ou-sb-value ${cls}`;
    };
    _sbSet('ou-sb-name', ou.name);
    _sbSet('ou-sb-path', ou.path, 'ou-sb-path');
    _sbSet('ou-sb-desc', ou.description || '—');
    _sbSet('ou-sb-objcount', String(ou.object_count ?? ou.objectCount ?? ou.count ?? '—'), 'accent');
    _sbSet('ou-sb-inherit', ou.inheritance_blocked ? 'Blocked' : 'Enabled', ou.inheritance_blocked ? 'amber' : 'green');
    _sbSet('ou-sb-managed', ou.managed_by || '—');
  }
  document.getElementById('od-avatar').textContent = (ou.name || 'OU').slice(0, 2).toUpperCase();
  document.getElementById('od-name').textContent   = ou.name || 'OU';
  document.getElementById('od-dn').textContent     = ou.path || '—';
  const detailBody = document.getElementById('ou-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('OU Identity', [
    ['Name',        ou.name        || '—', 'accent'],
    ['Type',        ou.type        || 'organizationalUnit', ''],
    ['Path',        ou.path        || '—', ou.path        ? '' : 'dim'],
    ['Description', ou.description || '—', ou.description ? '' : 'dim'],
    ['Managed By',  ou.managed_by  || '—', ou.managed_by  ? '' : 'dim'],
  ]);
  detailBody.innerHTML += detailSection('Security & Policy', [
    ['GPO Linked',            ou.has_gpo_links          ? 'Yes' : 'No', ou.has_gpo_links          ? 'accent' : 'dim'],
    ['Inheritance Blocked',   ou.inheritance_blocked    ? 'Yes' : 'No', ou.inheritance_blocked    ? 'amber'  : 'green'],
    ['Delegated Permissions', ou.delegated_permissions  ? 'Yes' : 'No', ou.delegated_permissions  ? 'red'    : 'dim'],
  ]);
  detailBody.innerHTML += detailSection('Timestamps', [
    ['Created',  fmtDate(ou.created),  ou.created  ? '' : 'dim'],
    ['Modified', fmtDate(ou.modified), ou.modified ? '' : 'dim'],
  ]);
  const gpoLinksHtml = gpoLinks.length > 0
    ? gpoLinks.map(g => `<div class="group-item">${g}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Linked GPOs (${gpoLinks.length})</div><div class="spn-list">${gpoLinksHtml}</div></div>`;
  if (ou.risk_controls?.length > 0) {
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Risk Controls</div><div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${ou.risk_controls.map(r => `<div class="badge amber">${r}</div>`).join('')}</div></div>`;
  }
  document.getElementById('ou-detail').style.display = 'flex';
}

function closeOUDetail() {
  document.getElementById('ou-detail').style.display = 'none';
  document.querySelectorAll('.o-row').forEach(r => r.classList.remove('selected'));
  const sb = document.getElementById('ou-status-bar');
  if (sb) sb.style.display = 'none';
}