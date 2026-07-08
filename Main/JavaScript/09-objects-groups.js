const PRIVILEGED_SIDS = new Set([
  'S-1-5-32-544',
  'S-1-5-32-548',
  'S-1-5-32-549',
  'S-1-5-32-550',
  'S-1-5-32-551',
  'S-1-5-32-552',
  'S-1-5-32-569',
  'S-1-5-32-578',
  'S-1-5-32-582',
]);


const PRIVILEGED_RID_SUFFIXES = [
  '-512',
  '-519',
  '-518',
  '-516',
  '-521',
  '-520',
  '-525',
  '-526',
  '-527',
  '-498',
  '-517',
  '-553',
  '-548',
  '-549',
  '-550',
  '-551',
  '-557',
  '-578',
  '-582',
];


const PRIVILEGED_NAME_PATTERNS = [
  /^domain admins$/i,
  /^enterprise admins$/i,
  /^schema admins$/i,
  /^administrators$/i,
  /^account operators$/i,
  /^backup operators$/i,
  /^server operators$/i,
  /^print operators$/i,
  /^group policy creator owners$/i,
  /^cryptographic operators$/i,
  /^hyper-v administrators$/i,
  /^storage replica administrators$/i,
  /^key admins$/i,
  /^enterprise key admins$/i,
  /^domain controllers$/i,
  /^enterprise read-only domain controllers$/i,
  /^read-only domain controllers$/i,
  /^ras and ias servers$/i,
  /^cert publishers$/i,
  /^remote management users$/i,
  /^protected users$/i,
  /^dnsadmins$/i,
];

function isPrivilegedGroup(sid, name) {
  const s = (sid  || '').trim();
  const n = (name || '').trim();
  if (s && PRIVILEGED_SIDS.has(s)) return true;
  if (s && PRIVILEGED_RID_SUFFIXES.some(r => s.endsWith(r))) return true;
  if (n && PRIVILEGED_NAME_PATTERNS.some(r => r.test(n))) return true;
  return false;
}


let groupsFilter = 'all';
let groupsSearch = '';


let groupsDomainsSelected     = null;
let groupsDomainsDropdownOpen = false;

function groupBelongsToDomain(group, domain) {
  const dn = group.dn || group.group_dn || '';
  const sid = group.sid || group.group_sid || '';
  if (domain.sid && sid) {
    const s  = String(sid).trim().toUpperCase();
    const ds = domain.sid.toUpperCase();
    if (s === ds || s.startsWith(ds + '-')) return true;
  }
  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return dn.toLowerCase().endsWith(suffix);
}

async function toggleGroupsDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('groups-domains-dropdown');
  if (!dd) return;

  if (groupsDomainsDropdownOpen) {
    closeGroupsDomainsDropdown();
    return;
  }

  groupsDomainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('groups-domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureDomainsListLoaded();
    if (!groupsDomainsSelected) {
      groupsDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
    }
    renderGroupsDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleGroupsDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleGroupsDomainsDropdownEscape);
}

function closeGroupsDomainsDropdown() {
  groupsDomainsDropdownOpen = false;
  const dd = document.getElementById('groups-domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleGroupsDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleGroupsDomainsDropdownEscape);
}

function handleGroupsDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('groups-domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeGroupsDomainsDropdown();
}

function handleGroupsDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeGroupsDomainsDropdown();
}

function renderGroupsDomainsDropdownList() {
  const listEl = document.getElementById('groups-domains-dropdown-list');
  if (!listEl) return;

  if (!domainsListCache || domainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = domainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = groupsDomainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleGroupDomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateGroupsDomainsSelectCount();
}

function updateGroupsDomainsSelectCount() {
  const countEl = document.getElementById('groups-domains-select-count');
  if (!countEl || !domainsListCache) return;
  const total = domainsListCache.length;
  const selected = groupsDomainsSelected ? groupsDomainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

function toggleGroupDomainSelected(domainKey, checked) {
  if (!groupsDomainsSelected) groupsDomainsSelected = new Set();
  if (checked) groupsDomainsSelected.add(domainKey);
  else groupsDomainsSelected.delete(domainKey);
  updateGroupsDomainsSelectCount();
  renderGroups();
}

function resetGroupsDomainsSelection() {
  if (!domainsListCache) return;
  groupsDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
  renderGroupsDomainsDropdownList();
  renderGroups();
}


async function loadGroups() {
  setGroupsLoading(true, 'Loading groups from DB...');
  document.getElementById('gr-table-body').innerHTML = '';
  closeGroupDetail();


  groupsDomainsSelected = null;

  try {
    const url = `${DB_BASE}/api/list/groups?limit=2000`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json().catch(() => null);

    if (!resp.ok || !data) {
      throw new Error(
        (data && (data.error || data.detail)) ||
        `SQLite Engine error (HTTP ${resp.status})`
      );
    }


    const raw = Array.isArray(data.records) ? data.records
              : Array.isArray(data.rows)    ? data.rows
              : [];


    groupsData = raw.map(normalizeGroupRecord);
    enumCacheLoaded.groups = true;

    const total = (typeof data.total === 'number') ? data.total : groupsData.length;
    setObjectCountStat('cnt-groups', total);
    document.getElementById('nav-groups-count').textContent = total;
    document.getElementById('groups-meta').textContent =
      `${total} groups · source: Oxsium SQLite Engine (.db)`;

    addLog(`Groups loaded from sqlite_reader.py: ${total} groups`, 'ok');
    renderGroups();
  } catch (err) {
    addLog(`Groups: ${err.message}`, 'err');
    document.getElementById('gr-table-body').innerHTML =
      `<div class="gr-empty"><p>${escapeHtml(err.message)}</p></div>`;
  } finally {
    setGroupsLoading(false);
  }
}


function normalizeGroupRecord(g) {
  if (!g || typeof g !== 'object') return g;
  const out = Object.assign({}, g);


  out.name = out.group_name || out.name || '';


  out.sid = out.group_sid || out.sid || '';


  out.dn = out.group_dn || (out.rowid != null ? `groups:${out.rowid}` : out.id != null ? `groups:${out.id}` : '');


  out.is_empty = Boolean(out.is_empty);


  out.is_privileged = isPrivilegedGroup(out.group_sid || out.sid || '', out.group_name || out.name || '');


  if (typeof out.member_count !== 'number') out.member_count = undefined;
  if (typeof out.member_users_count !== 'number') out.member_users_count = undefined;

  if (!out.name) console.warn("[normalizeGroupRecord] name bos, raw:", JSON.stringify(g));
  return out;
}


async function loadAllGroupMembers() {
  if (!groupsData.length) await loadGroups();
  if (!groupsData.length) { showToast('No groups found', 'info'); return; }

  setGroupsLoading(true, 'Loading all group members from DB...');
  addLog(`Groups: loading members for ${groupsData.length} groups (DB)...`, 'info');

  let loaded = 0;
  for (const group of groupsData) {
    if (group._membersLoaded) { loaded++; continue; }
    try {
      await ensureGroupMembersLoaded(group);
      loaded++;
    } catch (_) {  }
  }

  renderGroups();
  addLog(`Groups: all members loaded (${loaded}/${groupsData.length}).`, 'ok');
  showToast('All group members loaded', 'success');
  setGroupsLoading(false);
}


async function fetchGroupMembersFromDB(group) {

  const rowid = group?.rowid ?? group?.id;
  if (rowid == null) return [];

  const resp = await fetch(`${DB_BASE}/api/object/groups/${rowid}`, { method: 'GET' });
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data) return [];


  const rows = data?.children?.group_direct_members?.rows || [];
  return rows.map(r => ({
    name:     r.member_name || r.name   || r.member_dn || '—',
    sid:      r.member_sid  || r.sid    || '—',
    dn:       r.member_dn   || r.dn     || '',
    is_group: Boolean(r.is_group),
    is_user:  Boolean(r.is_user),
  }));
}


async function fetchGroupMembersTree(group, _visited, _depth, _maxDepth) {

  const key = String(group?.dn || group?.id || '').trim();
  if (!key) return [];
  if (nestedGroupMembersCache.has(key)) return nestedGroupMembersCache.get(key) || [];
  if (nestedGroupMembersLoading.has(key)) return await nestedGroupMembersLoading.get(key);

  const promise = (async () => {
    const members = await fetchGroupMembersFromDB(group);
    nestedGroupMembersCache.set(key, members);
    return members;
  })();

  nestedGroupMembersLoading.set(key, promise);
  try {
    return await promise;
  } finally {
    nestedGroupMembersLoading.delete(key);
  }
}

async function ensureGroupMembersLoaded(group) {
  if (!group || group._membersLoaded || groupMembersLoading.has(group.dn || group.id)) return;
  const lockKey = group.dn || group.id;
  groupMembersLoading.add(lockKey);
  try {
    group.members = await fetchGroupMembersFromDB(group);
    group.member_users        = (group.members || []).filter(m => m?.is_user);
    group.has_group_members   = (group.members || []).some(m => m?.is_group);
    group.member_count        = (group.members || []).length;
    group.member_users_count  = group.member_users.length;
    group.is_empty            = group.member_count === 0;

    group.is_privileged       = isPrivilegedGroup(group.group_sid || group.sid || '', group.group_name || group.name || '');
    group._membersLoaded      = true;
  } finally {
    groupMembersLoading.delete(lockKey);
  }
}


function setGroupFilter(filter, btn) {
  groupsFilter = filter;
  document.querySelectorAll('#groups-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (filter === 'privileged') { renderGroups(); return; }
  if (filter === 'nested') { loadAllGroupMembers(); return; }
  renderGroups();
}

function filterGroups() {
  groupsSearch = (document.getElementById('groups-search').value || '').toLowerCase();
  renderGroups();
}


function renderMemberItems(members, depth = 0) {
  return (Array.isArray(members) ? members : []).map(m => {
    const name    = escapeHtml(m?.name || m?.dn || '—');
    const sid     = escapeHtml(m?.sid  || '—');
    const isGroup = Boolean(m?.is_group && m?.dn);
    const indent  = Math.min(depth, 5) * 22;
    const nested  = isGroup && Array.isArray(m?.nested_members) && m.nested_members.length > 0
      ? `<div class="gr-nested-members">${renderMemberItems(m.nested_members, depth + 1)}</div>` : '';
    return `
      <div class="gr-members-item ${isGroup ? 'group-parent' : ''}" style="padding-left:${indent}px;">
        <span class="gr-member-name">${name}</span>
        <span class="gr-member-meta">${isGroup ? '<span class="gr-member-kind">GROUP</span>' : ''}<span class="gr-member-sid">${sid}</span></span>
      </div>${nested}`;
  }).join('');
}

function renderGroupMembersRow(row, members) {
  if (!row) return;
  const list = Array.isArray(members) ? members : [];
  row.innerHTML = list.length === 0
    ? '<div class="gr-members-empty">No members found in this group.</div>'
    : `<div class="gr-members-head"><span>Member</span><span>SID</span></div>${renderMemberItems(list, 0)}`;
}

async function toggleGroupMembers(btn, membersRowId) {
  const row = document.getElementById(membersRowId);
  if (!row) return;
  const isOpen = row.style.display === 'block';
  row.style.display = isOpen ? 'none' : 'block';
  btn.classList.toggle('open', !isOpen);

  if (!isOpen) {

    const dn = row.dataset.groupDn || '';
    const group = groupsData.find(g => (g.dn || g.group_dn || '') === dn)
               || groupsData.find(g => String(g.id) === row.dataset.groupId);

    if (!group) return;

    if (group._membersLoaded) {

      renderGroupMembersRow(row, group.members || []);
      return;
    }


    row.innerHTML = '<div class="gr-members-empty">Loading members...</div>';
    try {
      await ensureGroupMembersLoaded(group);
      renderGroupMembersRow(row, group.members || []);
      const countSpan = btn?.querySelector('span:last-child');
      if (countSpan) countSpan.textContent = String(group.member_count ?? 0);
    } catch (err) {
      row.innerHTML = `<div class="gr-members-empty">${escapeHtml(err.message || 'Failed to load members')}</div>`;
    }
  }
}

function renderGroups() {
  const body = document.getElementById('gr-table-body');
  body.innerHTML = '';
  let list = groupsData;

  if (domainsListCache && groupsDomainsSelected && groupsDomainsSelected.size < domainsListCache.length) {
    const activeDomains = domainsListCache.filter(d => groupsDomainsSelected.has(d.name.toLowerCase()));
    list = list.filter(g => activeDomains.some(d => groupBelongsToDomain(g, d)));
  }

  if (groupsSearch) list = list.filter(g =>
    (g.name     || '').toLowerCase().includes(groupsSearch) ||
    (g.sid      || '').toLowerCase().includes(groupsSearch) ||
    (g.group_dn || '').toLowerCase().includes(groupsSearch)
  );
  if (groupsFilter === 'empty')      list = list.filter(g => g.is_empty);
  if (groupsFilter === 'privileged') list = list.filter(g => g.is_privileged);
  if (groupsFilter === 'nested') list = list.filter(g => g.has_group_members === true);

  list = [...list].sort((a, b) => {
    const ac = Number.isFinite(a.member_count) ? a.member_count : 0;
    const bc = Number.isFinite(b.member_count) ? b.member_count : 0;
    return bc !== ac ? bc - ac : String(a.name || '').localeCompare(String(b.name || ''));
  });

  if (list.length === 0) {
    body.innerHTML = '<div class="gr-empty"><p>No matching groups</p></div>';
    return;
  }

  list.forEach(group => {
    const row = document.createElement('div');
    row.className = 'gr-row' + (group.is_privileged ? ' privileged' : '');

    const membersCount = Number.isFinite(group.member_count) ? group.member_count : '—';
    const membersRowId = `gr-members-${Math.random().toString(36).slice(2)}`;


    const cellName = document.createElement('div');
    cellName.className = 'gr-cell gr-cell-name';
    cellName.textContent = group.name || group.group_name || '—';


    const cellSid = document.createElement('div');
    cellSid.className = 'gr-cell gr-cell-sid';
    cellSid.textContent = group.sid || group.group_sid || '—';


    const cellMembers = document.createElement('div');
    cellMembers.className = 'gr-cell gr-cell-members';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'gr-members-toggle';
    toggleBtn.type      = 'button';
    toggleBtn.title     = 'Show members';

    const arrowSpan = document.createElement('span');
    arrowSpan.className = 'gr-arrow';
    arrowSpan.textContent = '▾';

    const countSpan = document.createElement('span');
    countSpan.textContent = String(membersCount);

    toggleBtn.appendChild(arrowSpan);
    toggleBtn.appendChild(countSpan);
    toggleBtn.addEventListener('click', e => {
      e.stopPropagation();
      toggleGroupMembers(toggleBtn, membersRowId);
    });
    cellMembers.appendChild(toggleBtn);


    const cellEmpty = document.createElement('div');
    cellEmpty.className = 'gr-cell gr-cell-empty';
    const flagSpan = document.createElement('span');
    flagSpan.className = group.is_privileged ? 'flag hi' : 'flag no';
    flagSpan.textContent = group.is_privileged ? 'Privileged' : '—';
    cellEmpty.appendChild(flagSpan);

    row.appendChild(cellName);
    row.appendChild(cellSid);
    row.appendChild(cellMembers);
    row.appendChild(cellEmpty);


    row.addEventListener('click', () => showGroupDetail(group, row));

    body.appendChild(row);

    const membersRow = document.createElement('div');
    membersRow.id               = membersRowId;
    membersRow.className        = 'gr-members-row';
    membersRow.dataset.groupDn  = group.dn || group.group_dn || '';
    membersRow.dataset.groupId  = String(group.id ?? '');
    membersRow.style.display    = 'none';

    if (group._membersLoaded) renderGroupMembersRow(membersRow, group.members || []);
    else membersRow.innerHTML   = '<div class="gr-members-empty">Click to load members.</div>';

    body.appendChild(membersRow);
  });
}


function showGroupDetail(group, row) {
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');

  document.getElementById('grd-avatar').textContent = (group.name || group.group_name || 'GR').slice(0, 2).toUpperCase();
  document.getElementById('grd-name').textContent   = group.name || group.group_name || '—';
  document.getElementById('grd-dn').textContent     = group.group_dn || group.dn || '—';

  const detailBody = document.getElementById('group-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('Group', [
    ['Name', group.name || group.group_name || '—', 'accent'],
    ['SID', group.sid || group.group_sid || '—', (group.sid || group.group_sid) ? '' : 'dim'],
    ['DN',           group.group_dn        || '—', group.group_dn ? '' : 'dim'],
    ['Members',      group.member_count    ?? '—', ''],
    ['User Members', group.member_users_count ?? '—', ''],
  ]);
  detailBody.innerHTML += detailSection('Status', [
    ['Empty',      group.is_empty      ? 'Yes' : 'No', group.is_empty      ? 'dim' : ''],
    ['Privileged', group.is_privileged ? 'Yes' : 'No', group.is_privileged ? 'accent' : ''],
  ]);

  document.getElementById('group-detail').style.display = 'flex';
}

function closeGroupDetail() {
  document.getElementById('group-detail').style.display = 'none';
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
}


function setGroupsLoading(visible, text = 'Loading groups...') {
  const wrap = document.getElementById('groups-loading');
  if (!wrap) return;
  const label = wrap.querySelector('span');
  if (label && text) label.textContent = text;
  wrap.style.display = visible ? 'flex' : 'none';
}