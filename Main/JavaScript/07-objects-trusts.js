/* ═══════════════════════════════════════════════════
   07-objects-trusts.js
   Trusts tab: load, render, filter, detail panel.
   Depends on: 00-globals.js, 01-core.js
   ═══════════════════════════════════════════════════ */

/* ═══════ Trusts ═══════ */
let trustsFilter = 'all';
let trustsSearch = '';

async function loadTrusts() {
  if (!state.connected) { addLog('Trusts: domain connection required', 'warn'); return; }
  document.getElementById('trusts-loading').style.display = 'flex';
  document.getElementById('tr-table-body').innerHTML = '';
  closeTrustDetail();
  try {
    const resp = await fetch(`${API_BASE}/api/trusts`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildEnumerationPayload()),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load trusts');
    trustsData = data.trusts || [];
    enumCacheLoaded.trusts = true;
    setObjectCountStat('cnt-trusts', trustsData.length);
    document.getElementById('nav-trusts-count').textContent = trustsData.length;
    document.getElementById('trusts-meta').textContent = `${trustsData.length} trusts · domain: ${(state.domain || '').toUpperCase()}`;
    renderTrusts();
    addLog(`Trusts loaded: ${trustsData.length} trust relationships enumerated`, 'ok');
  } catch (err) {
    addLog(`Trusts: ${err.message}`, 'err');
    document.getElementById('tr-table-body').innerHTML = `<div class="tr-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('trusts-loading').style.display = 'none';
  }
}

function filterTrusts() { trustsSearch = (document.getElementById('trusts-search').value || '').toLowerCase(); renderTrusts(); }
function setTrustFilter(filter, btn) {
  trustsFilter = filter;
  document.querySelectorAll('#trusts-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderTrusts();
}

function renderTrusts() {
  const body = document.getElementById('tr-table-body');
  body.innerHTML = '';
  let list = trustsData;
  if (trustsSearch) list = list.filter(t =>
    (t.name      || '').toLowerCase().includes(trustsSearch) ||
    (t.partner   || '').toLowerCase().includes(trustsSearch) ||
    (t.direction || '').toLowerCase().includes(trustsSearch)
  );
  if (trustsFilter === 'inbound')    list = list.filter(t => !!t.inbound);
  if (trustsFilter === 'outbound')   list = list.filter(t => !!t.outbound);
  if (trustsFilter === 'transitive') list = list.filter(t => !!t.transitive);
  if (trustsFilter === 'forest')     list = list.filter(t => !!t.forest);
  if (list.length === 0) { body.innerHTML = '<div class="tr-empty"><p>No matching trusts</p></div>'; return; }
  list.forEach(trust => {
    const row = document.createElement('div');
    row.className = 'tr-row';
    row.onclick = () => showTrustDetail(trust, row);
    row.innerHTML = `
      <div class="tr-cell tr-cell-name">${trust.name      || '—'}</div>
      <div class="tr-cell tr-cell-partner">${trust.partner   || '—'}</div>
      <div class="tr-cell tr-cell-direction">${trust.direction || '—'}</div>
      <div class="tr-cell tr-cell-type">${trust.trust_type || '—'}</div>
    `;
    body.appendChild(row);
  });
}

function showTrustDetail(trust, row) {
  document.querySelectorAll('.tr-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('trd-avatar').textContent = (trust.name || 'TR').slice(0, 2).toUpperCase();
  document.getElementById('trd-name').textContent   = trust.name || '—';
  document.getElementById('trd-dn').textContent     = trust.dn   || '—';
  const detailBody = document.getElementById('trust-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('Trust', [
    ['Name',    trust.name       || '—', 'accent'],
    ['Partner', trust.partner    || '—', trust.partner ? '' : 'dim'],
    ['Direction', trust.direction || '—', ''],
    ['Type',    trust.trust_type || '—', ''],
  ]);
  detailBody.innerHTML += detailSection('Attributes', [
    ['Flat Name',  trust.flat_name  || '—', trust.flat_name ? '' : 'dim'],
    ['Inbound',    trust.inbound    ? 'Yes' : 'No', trust.inbound    ? 'green' : ''],
    ['Outbound',   trust.outbound   ? 'Yes' : 'No', trust.outbound   ? 'accent': ''],
    ['Transitive', trust.transitive ? 'Yes' : 'No', trust.transitive ? 'amber' : ''],
    ['Forest',     trust.forest     ? 'Yes' : 'No', trust.forest     ? 'red'   : ''],
    ['Attributes', trust.attributes ?? 0,            ''],
    ['SID',        trust.sid        || '—',          trust.sid ? '' : 'dim'],
  ]);
  if (trust.risk_controls?.length > 0) {
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Risk Controls</div><div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${trust.risk_controls.map(r => `<div class="badge amber">${r}</div>`).join('')}</div></div>`;
  }
  document.getElementById('trust-detail').style.display = 'flex';
}

function closeTrustDetail() {
  document.getElementById('trust-detail').style.display = 'none';
  document.querySelectorAll('.tr-row').forEach(r => r.classList.remove('selected'));
}