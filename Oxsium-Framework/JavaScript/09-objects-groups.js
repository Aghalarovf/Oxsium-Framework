/* ═══════════════════════════════════════════════════
   09-objects-groups.js
   Groups tab: load, render, filter, members tree, detail panel.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ═══════ Groups ═══════ */
let groupsFilter = 'all';
let groupsSearch = '';

async function loadGroups() {
  if (!state.connected) { addLog('Groups: domain connection required', 'warn'); return; }
  setGroupsLoading(true, 'Enumerating groups...');
  document.getElementById('gr-table-body').innerHTML = '';
  closeGroupDetail();
  try {
    const resp = await fetch(`${API_BASE}/api/groups`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load groups');
    groupsData = data.groups || [];
    enumCacheLoaded.groups = true;
    setObjectCountStat('cnt-groups', groupsData.length);
    document.getElementById('nav-groups-count').textContent = groupsData.length;
    document.getElementById('groups-meta').textContent = `${groupsData.length} groups · domain: ${(state.domain || '').toUpperCase()}`;
    renderGroups();
    addLog(`Groups loaded: ${groupsData.length} groups enumerated`, 'ok');
  } catch (err) {
    addLog(`Groups: ${err.message}`, 'err');
    document.getElementById('gr-table-body').innerHTML = `<div class="gr-empty"><p>${err.message}</p></div>`;
  } finally {
    setGroupsLoading(false);
  }
}

function setGroupsLoading(visible, text = 'Enumerating groups...') {
  const wrap = document.getElementById('groups-loading');
  if (!wrap) return;
  const label = wrap.querySelector('span');
  if (label && text) label.textContent = text;
  wrap.style.display = visible ? 'flex' : 'none';
}

async function loadAllGroupMembers() {
  if (!state.connected) { addLog('All members: domain connection required', 'warn'); return; }
  if (!groupsData.length) await loadGroups();
  if (!groupsData.length) { showToast('No groups found to expand members', 'info'); return; }
  // Request all group members in one API call and merge results locally
  setGroupsLoading(true, 'Loading all group members...');
  addLog(`Groups: loading members for ${groupsData.length} groups...`, 'info');
  try {
    const resp = await fetch(`${API_BASE}/api/group-members`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load all group members');

    // Expecting batch response with `groups` array containing group objects with dn, members, member_users, counts
    const returned = Array.isArray(data.groups) ? data.groups : [];
    // map returned groups by dn (lowercase) or name
    const retMap = new Map();
    for (const g of returned) {
      const dn = String(g.group_dn || g.groupDn || g.dn || '').trim().toLowerCase();
      const name = String(g.group_name || g.groupName || g.name || '').trim().toLowerCase();
      if (dn) retMap.set(dn, g);
      else if (name) retMap.set(name, g);
    }

    let merged = 0;
    for (const local of groupsData) {
      const keyDn = String(local.dn || '').trim().toLowerCase();
      const keyName = String(local.name || local.sam_name || '').trim().toLowerCase();
      const match = keyDn ? retMap.get(keyDn) : retMap.get(keyName);
      if (match) {
        local.members = match.members || [];
        local.member_users = match.member_users || [];
        local.member_count = Number.isFinite(match.member_count) ? match.member_count : (local.members || []).length;
        local.member_users_count = Number.isFinite(match.member_users_count) ? match.member_users_count : (local.member_users || []).length;
        local.has_group_members = (local.members || []).some(m => m?.is_group);
        local.is_empty = (local.member_count || 0) === 0;
        local._membersLoaded = true;
        merged++;
      }
    }

    renderGroups();
    addLog(`Groups: all members loaded (${merged}/${groupsData.length}).`, 'ok');
    showToast('All group members loaded', 'success');
  } catch (err) {
    addLog(`Groups: ${err.message}`, 'err');
  } finally {
    setGroupsLoading(false);
  }
}

function setGroupFilter(filter, btn) {
  groupsFilter = filter;
  document.querySelectorAll('#groups-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (filter === 'nested') { loadAllGroupMembers(); return; }
  renderGroups();
}

function filterGroups() { groupsSearch = (document.getElementById('groups-search').value || '').toLowerCase(); renderGroups(); }

async function fetchGroupMembersTree(groupDn, visited = new Set(), depth = 0, maxDepth = 5) {
  const dn = String(groupDn || '').trim();
  if (!dn || visited.has(dn)) return [];
  if (nestedGroupMembersCache.has(dn)) return nestedGroupMembersCache.get(dn) || [];
  if (nestedGroupMembersLoading.has(dn)) return await nestedGroupMembersLoading.get(dn);

  const promise = (async () => {
    const resp = await fetch(`${API_BASE}/api/group-members`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...buildEnumerationPayload(), group_dn: dn }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load group members');
    const members = Array.isArray(data.members) ? data.members : [];
    if (depth < maxDepth) {
      const next = new Set(visited); next.add(dn);
      for (const m of members) {
        if (m?.is_group && m?.dn && !next.has(String(m.dn))) {
          try { m.nested_members = await fetchGroupMembersTree(String(m.dn), next, depth + 1, maxDepth); }
          catch (_) { m.nested_members = []; }
        }
      }
    }
    nestedGroupMembersCache.set(dn, members);
    return members;
  })();

  nestedGroupMembersLoading.set(dn, promise);
  try { return await promise; }
  finally { nestedGroupMembersLoading.delete(dn); }
}

async function ensureGroupMembersLoaded(group) {
  if (!group?.dn || group._membersLoaded || groupMembersLoading.has(group.dn)) return;
  groupMembersLoading.add(group.dn);
  try {
    group.members = await fetchGroupMembersTree(group.dn);
    group.member_users = (group.members || []).filter(m => m?.is_user);
    group.has_group_members = (group.members || []).some(m => m?.is_group);
    group.member_count = (group.members || []).length;
    group.member_users_count = group.member_users.length;
    group.is_empty = group.member_count === 0;
    group._membersLoaded = true;
  } finally { groupMembersLoading.delete(group.dn); }
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
  if (!isOpen && row.dataset.groupDn) {
    const group = groupsData.find(g => (g.dn || '') === row.dataset.groupDn);
    if (group && !group._membersLoaded) {
      row.innerHTML = '<div class="gr-members-empty">Loading members...</div>';
      try {
        await ensureGroupMembersLoaded(group);
        renderGroupMembersRow(row, group.members);
        const countSpan = btn?.querySelector('span:last-child');
        if (countSpan) countSpan.textContent = String(group.member_count ?? 0);
      } catch (err) {
        row.innerHTML = `<div class="gr-members-empty">${escapeHtml(err.message || 'Failed to load members')}</div>`;
      }
    }
  }
}

function renderGroups() {
  const body = document.getElementById('gr-table-body');
  body.innerHTML = '';
  let list = groupsData;
  if (groupsSearch) list = list.filter(g =>
    (g.name        || '').toLowerCase().includes(groupsSearch) ||
    (g.sam_name    || '').toLowerCase().includes(groupsSearch) ||
    (g.description || '').toLowerCase().includes(groupsSearch)
  );
  if (groupsFilter === 'privileged') list = list.filter(g => g.is_privileged || g.is_protected);
  if (groupsFilter === 'empty')      list = list.filter(g => g.is_empty);
  if (groupsFilter === 'nested')     list = list.filter(g => g.has_group_members === true);

  const allLoaded = list.length > 0 && list.every(g => Number.isFinite(g.member_count));
  list = [...list].sort((a, b) => {
    if (!allLoaded) {
      if (Boolean(a.is_protected) !== Boolean(b.is_protected)) return a.is_protected ? -1 : 1;
      return String(a.name || '').localeCompare(String(b.name || ''));
    }
    const ac = Number.isFinite(a.member_count) ? a.member_count : 0;
    const bc = Number.isFinite(b.member_count) ? b.member_count : 0;
    return bc !== ac ? bc - ac : String(a.name || '').localeCompare(String(b.name || ''));
  });

  if (list.length === 0) { body.innerHTML = '<div class="gr-empty"><p>No matching groups</p></div>'; return; }

  list.forEach(group => {
    const row = document.createElement('div');
    row.className = 'gr-row';
    row.onclick = () => showGroupDetail(group, row);
    const membersCount  = Number.isFinite(group.member_count) ? group.member_count : '—';
    const membersRowId  = `gr-members-${Math.random().toString(36).slice(2)}`;
    row.innerHTML = `
      <div class="gr-cell gr-cell-name">${group.name || '—'}</div>
      <div class="gr-cell gr-cell-type">${group.group_type || '—'}</div>
      <div class="gr-cell gr-cell-members">
        <button class="gr-members-toggle" type="button" onclick="event.stopPropagation();toggleGroupMembers(this, '${membersRowId}')" title="Show members">
          <span class="gr-arrow">▾</span><span>${membersCount}</span>
        </button>
      </div>
      <div class="gr-cell gr-cell-protected">${group.is_protected ? '<span class="flag yes-admin">YES</span>' : '<span class="flag no">—</span>'}</div>
    `;
    body.appendChild(row);
    const membersRow = document.createElement('div');
    membersRow.id            = membersRowId;
    membersRow.className     = 'gr-members-row';
    membersRow.dataset.groupDn = group.dn || '';
    membersRow.style.display = 'none';
    if (group._membersLoaded) renderGroupMembersRow(membersRow, group.members || []);
    else membersRow.innerHTML = '<div class="gr-members-empty">Click to load members.</div>';
    body.appendChild(membersRow);
  });
}

function showGroupDetail(group, row) {
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('grd-avatar').textContent = (group.name || 'GR').slice(0, 2).toUpperCase();
  document.getElementById('grd-name').textContent   = group.name || '—';
  document.getElementById('grd-dn').textContent     = group.dn   || '—';
  const detailBody = document.getElementById('group-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('Group', [
    ['Name',           group.name     || '—', 'accent'],
    ['sAMAccountName', group.sam_name || '—', group.sam_name ? '' : 'dim'],
    ['Type',           group.group_type || '—', ''],
    ['Members',        group.member_count ?? 0, ''],
  ]);
  detailBody.innerHTML += detailSection('Security', [
    ['Privileged',  group.is_privileged ? 'Yes' : 'No', group.is_privileged ? 'red'   : ''],
    ['Protected',   group.is_protected  ? 'Yes' : 'No', group.is_protected  ? 'amber' : ''],
    ['Empty',       group.is_empty      ? 'Yes' : 'No', group.is_empty      ? 'dim'   : ''],
    ['Nested',      group.is_nested     ? 'Yes' : 'No', group.is_nested     ? 'accent': ''],
    ['Managed By',  group.managed_by    || '—',         group.managed_by    ? '' : 'dim'],
    ['SID',         group.sid           || '—',         group.sid           ? '' : 'dim'],
    ['Description', group.description   || '—',         group.description   ? '' : 'dim'],
  ]);
  if (group.risk_controls?.length > 0) {
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Risk Controls</div><div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${group.risk_controls.map(r => `<div class="badge amber">${r}</div>`).join('')}</div></div>`;
  }
  document.getElementById('group-detail').style.display = 'flex';
}

function closeGroupDetail() {
  document.getElementById('group-detail').style.display = 'none';
  document.querySelectorAll('.gr-row').forEach(r => r.classList.remove('selected'));
}