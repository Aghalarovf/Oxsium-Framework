/* ═══════════════════════════════════════════════════
   08-objects-gpos.js
   GPOs tab: load, render, filter, detail panel.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ═══════ GPOs ═══════ */
let gposFilter = 'all';
let gposSearch = '';

async function loadGPOs() {
  if (!state.connected) { addLog('GPOs: domain connection required', 'warn'); return; }
  document.getElementById('gpos-loading').style.display = 'flex';
  document.getElementById('g-table-body').innerHTML = '';
  closeGPODetail();
  try {
    const resp = await fetch(`${API_BASE}/api/gpo`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load GPOs');
    gposData = data.gpos || [];
    enumCacheLoaded.gpos = true;
    setObjectCountStat('cnt-gpos', gposData.length);
    document.getElementById('nav-gpo-count').textContent = gposData.length;
    document.getElementById('gpos-meta').textContent = `${gposData.length} GPOs · domain: ${(state.domain || '').toUpperCase()}`;
    renderGPOs();
    addLog(`GPOs loaded: ${gposData.length} group policy objects enumerated`, 'ok');
  } catch (err) {
    addLog(`GPOs: ${err.message}`, 'err');
    document.getElementById('g-table-body').innerHTML = `<div class="g-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('gpos-loading').style.display = 'none';
  }
}

function renderGPOs() {
  const body = document.getElementById('g-table-body');
  let list = gposData;
  if (gposSearch) list = list.filter(gpo =>
    (gpo.name || '').toLowerCase().includes(gposSearch) ||
    (gpo.display_name || '').toLowerCase().includes(gposSearch)
  );
  if (gposFilter === 'vulnerable') list = list.filter(gpo => !!gpo.vulnerable);
  if (gposFilter === 'links')      list = list.filter(gpo => (gpo.linked_count || 0) > 0);
  if (gposFilter === 'settings')   list = list.filter(gpo => !!gpo.has_settings_markers);
  filteredGPOs = list;
  body.innerHTML = '';
  if (filteredGPOs.length === 0) { body.innerHTML = '<div class="g-empty"><p>No matching GPOs</p></div>'; return; }
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

function filterGPOs() { gposSearch = (document.getElementById('gpo-search').value || '').toLowerCase(); renderGPOs(); }
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
  const linked  = Array.isArray(gpo.linked_containers) ? gpo.linked_containers : [];
  document.getElementById('gd-avatar').textContent = gpoName.slice(0, 2).toUpperCase();
  document.getElementById('gd-name').textContent   = gpo.display_name || gpoName;
  document.getElementById('gd-dn').textContent     = gpo.guid || '—';
  const detailBody = document.getElementById('gpo-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('GPO Identity', [
    ['Name',         gpoName,            'accent'],
    ['Display Name', gpo.display_name || gpoName, ''],
    ['GUID',         gpo.guid  || '—',  gpo.guid  ? '' : 'dim'],
    ['Path',         gpo.path  || '—',  gpo.path  ? '' : 'dim'],
  ]);
  detailBody.innerHTML += detailSection('Risk & Linkage', [
    ['Vulnerable',         gpo.vulnerable            ? 'Yes' : 'No', gpo.vulnerable            ? 'red'    : 'green'],
    ['Linked Containers',  gpo.linked_count          || 0,           (gpo.linked_count || 0) > 0 ? 'accent' : 'dim'],
    ['Settings Markers',   gpo.has_settings_markers  ? 'Yes' : 'No', gpo.has_settings_markers  ? 'amber'  : 'dim'],
  ]);
  detailBody.innerHTML += detailSection('Version & Timestamps', [
    ['Version',          gpo.version          || 0, ''],
    ['User Version',     gpo.user_version     || 0, ''],
    ['Computer Version', gpo.computer_version || 0, ''],
    ['Created',          fmtDate(gpo.created),    gpo.created  ? '' : 'dim'],
    ['Modified',         fmtDate(gpo.modified),   gpo.modified ? '' : 'dim'],
  ]);
  const linksHtml = linked.length > 0
    ? linked.map(l => `<div class="group-item">${l}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Linked Containers (${linked.length})</div><div class="spn-list">${linksHtml}</div></div>`;
  if (gpo.risk_controls?.length > 0) {
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Risk Controls</div><div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${gpo.risk_controls.map(r => `<div class="badge amber">${r}</div>`).join('')}</div></div>`;
  }
  document.getElementById('gpo-detail').style.display = 'flex';
}

function closeGPODetail() {
  document.getElementById('gpo-detail').style.display = 'none';
  document.querySelectorAll('.g-row').forEach(r => r.classList.remove('selected'));
}