/* ═══════════════════════════════════════════════════
   11-objects-ous.js
   OUs tab: load, render, filter, detail panel.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ═══════ OUs ═══════ */
let ousFilter = 'all';
let ousSearch = '';

async function loadOUs() {
  if (!state.connected) { addLog('OUs: domain connection required', 'warn'); return; }
  document.getElementById('ous-loading').style.display = 'flex';
  document.getElementById('o-table-body').innerHTML = '';
  closeOUDetail();
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
    row.onclick = () => showOUDetail(ou, row);
    const objCount    = ou.object_count ?? ou.objectCount ?? ou.count ?? '—';
    const inheritVal  = ou.inheritance_blocked ? 'Blocked' : 'Enabled';
    const inheritCls  = ou.inheritance_blocked ? 'blocked' : 'enabled';
    row.innerHTML = `
      <div class="o-cell o-cell-name">${ou.name}</div>
      <div class="o-cell o-cell-path" title="${ou.path}">${ou.path}</div>
      <div class="o-cell o-cell-desc" title="${ou.description}">${ou.description || '—'}</div>
      <div class="o-cell o-cell-objcount">${objCount}</div>
      <div class="o-cell o-cell-inherit ${inheritCls}">${inheritVal}</div>
      <div class="o-cell o-cell-managed" title="${ou.managed_by}">${ou.managed_by || '—'}</div>
    `;
    body.appendChild(row);
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
