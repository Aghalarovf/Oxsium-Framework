let computersFilter = 'all';
let computersSearch = '';


let computersDomainsListCache    = null;
let computersDomainsSelected     = null;
let computersDomainsDropdownOpen = false;

function guessCurrentDomainSidFromComputers() {
  if (!Array.isArray(computersData) || computersData.length === 0) return null;
  const counts = new Map();
  computersData.forEach(c => {
    const sid = (c.domainsid || '').trim();
    if (!sid) return;
    counts.set(sid, (counts.get(sid) || 0) + 1);
  });
  let best = null, bestCount = 0;
  counts.forEach((count, sid) => { if (count > bestCount) { best = sid; bestCount = count; } });
  return best;
}

function computerBelongsToDomain(c, domain) {
  if (domain.sid) {
    return (c.domainsid || '').trim().toUpperCase() === domain.sid.toUpperCase();
  }
  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return (c.dn || '').toLowerCase().endsWith(suffix);
}

async function ensureComputersDomainsListLoaded() {
  if (computersDomainsListCache) return computersDomainsListCache;

  const currentDomain = (state.domain || '').trim();
  const currentDomainSid = guessCurrentDomainSidFromComputers();
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

  computersDomainsListCache = list;
  if (!computersDomainsSelected) {
    computersDomainsSelected = new Set(list.map(d => d.name.toLowerCase()));
  }
  return list;
}

function renderComputersDomainsDropdownList() {
  const listEl = document.getElementById('comp-domains-dropdown-list');
  if (!listEl) return;

  if (!computersDomainsListCache || computersDomainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = computersDomainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = computersDomainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleComputersDomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateComputersDomainsSelectCount();
}

function updateComputersDomainsSelectCount() {
  const countEl = document.getElementById('comp-domains-select-count');
  if (!countEl || !computersDomainsListCache) return;
  const total = computersDomainsListCache.length;
  const selected = computersDomainsSelected ? computersDomainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

async function toggleComputersDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('comp-domains-dropdown');
  if (!dd) return;

  if (computersDomainsDropdownOpen) {
    closeComputersDomainsDropdown();
    return;
  }

  computersDomainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('comp-domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureComputersDomainsListLoaded();
    renderComputersDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleComputersDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleComputersDomainsDropdownEscape);
}

function closeComputersDomainsDropdown() {
  computersDomainsDropdownOpen = false;
  const dd = document.getElementById('comp-domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleComputersDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleComputersDomainsDropdownEscape);
}

function handleComputersDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('comp-domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeComputersDomainsDropdown();
}

function handleComputersDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeComputersDomainsDropdown();
}

function toggleComputersDomainSelected(domainKey, checked) {
  if (!computersDomainsSelected) computersDomainsSelected = new Set();
  if (checked) computersDomainsSelected.add(domainKey);
  else computersDomainsSelected.delete(domainKey);
  updateComputersDomainsSelectCount();
  renderComputers();
}

function resetComputersDomainsSelection() {
  if (!computersDomainsListCache) return;
  computersDomainsSelected = new Set(computersDomainsListCache.map(d => d.name.toLowerCase()));
  renderComputersDomainsDropdownList();
  renderComputers();
}

async function loadComputers() {
  document.getElementById('computers-loading').style.display = 'flex';
  document.getElementById('c-table-body').innerHTML = '';
  closeComputerDetail();


  computersDomainsListCache = null;
  computersDomainsSelected  = null;

  try {
    let url = `${DB_BASE}/api/list/computers?limit=500`;
    if (computersSearch && computersSearch.trim()) {
      url += `&q=${encodeURIComponent(computersSearch.trim())}`;
    }

    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      throw new Error((data && (data.error || data.detail)) || `Oxsium SQLite Engine error (HTTP ${resp.status})`);
    }

    computersData = Array.isArray(data.records) ? data.records : (Array.isArray(data.rows) ? data.rows : []);
    enumCacheLoaded.computers = true;

    const total = (typeof data.total === 'number') ? data.total : computersData.length;
    setObjectCountStat('cnt-comp', total);
    document.getElementById('nav-computers-count').textContent = total;
    document.getElementById('computers-meta').textContent =
      `${total} computers · source: Oxsium SQLite Engine (.db)`;

    const dcComputer = computersData.find(c => c.is_domain_controller);
    const dcDns = dcComputer?.dns_name || dcComputer?.computer_name || '';
    if (typeof window.setEnvironmentDomainController === 'function') {
      window.setEnvironmentDomainController(dcDns, dcDns ? 'accent' : 'dim');
    }

    renderComputers();
    addLog(`Computers loaded from sqlite_reader.py: ${total} systems (Oxsium SQLite Engine)`, 'ok');
  } catch (err) {
    addLog(`Computers: ${err.message}`, 'err');
    document.getElementById('c-table-body').innerHTML = `<div class="c-empty"><p>${escapeHtml(err.message)}</p></div>`;
  } finally {
    document.getElementById('computers-loading').style.display = 'none';
  }
}

function setComputerFilter(f, btn) {
  computersFilter = f;
  document.querySelectorAll('#comp-filter-chips .chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderComputers();
}

function filterComputers() {
  computersSearch = document.getElementById('computers-search').value.toLowerCase();
  renderComputers();
}

function renderComputers() {
  const body = document.getElementById('c-table-body');
  body.innerHTML = '';

  let list = computersData;
  if (computersDomainsListCache && computersDomainsSelected && computersDomainsSelected.size < computersDomainsListCache.length) {
    const activeDomains = computersDomainsListCache.filter(d => computersDomainsSelected.has(d.name.toLowerCase()));
    list = list.filter(c => activeDomains.some(d => computerBelongsToDomain(c, d)));
  }
  if (computersSearch) {
    list = list.filter(c =>
      (c.computer_name || '').toLowerCase().includes(computersSearch) ||
      (c.dns_name      || '').toLowerCase().includes(computersSearch)
    );
  }
  if (computersFilter === 'delegation')    list = list.filter(c => c.unconstrained_delegation || c.constrained_delegation);
  if (computersFilter === 'rbcd')          list = list.filter(c => c.rbcd_enabled);
  if (computersFilter === 'dc')            list = list.filter(c => c.is_domain_controller);
  if (computersFilter === 'legacy_os') {
    list = list.filter(c => isLegacyOS(c.os));
  }
  if (computersFilter === 'laps') list = list.filter(c => c.has_laps);

  if (list.length === 0) { body.innerHTML = '<div class="c-empty"><p>No matching computers</p></div>'; return; }

  list.forEach(c => {
    const row = document.createElement('div');
    const hasRiskDesc = getSensitiveDescriptionMatches(c.description || '').length > 0;
    const dcBadge     = c.is_domain_controller ? '<span class="dc-badge">DC</span>' : '';

    row.className = 'c-row' +
      (c.is_domain_controller ? ' dc-row' : '') +
      (!c.is_domain_controller && c.unconstrained_delegation ? ' unconstrained-row' : '') +
      (c.rbcd_enabled ? ' dcsync' : '') +
      (hasRiskDesc ? ' desc-risk' : '');

    row.onclick = () => showComputerDetail(c, row);
    row.innerHTML = `
      <div class="c-name">${dcBadge}${c.computer_name || '—'}</div>
      <div class="c-os">${c.os || '—'}</div>
      <div class="c-flag-cell">${c.is_server      ? '<span class="flag yes-ok">SRV</span>' : c.is_workstation ? '<span class="flag yes-ok">WS</span>' : '<span class="flag no">—</span>'}</div>
      <div class="c-flag-cell">${c.has_spn        ? '<span class="flag yes-spn">SPN</span>' : '<span class="flag no">—</span>'}</div>
      <div class="c-flag-cell">${c.unconstrained_delegation ? '<span class="flag yes-un">UN</span>' : c.constrained_delegation ? '<span class="flag yes-cn">CN</span>' : '<span class="flag no">—</span>'}</div>
      <div class="c-flag-cell">${c.disabled       ? '<span class="flag yes-dis">DIS</span>' : '<span class="flag yes-ok">EN</span>'}</div>
      <div class="c-flag-cell">${c.rbcd_enabled   ? '<span class="flag yes-rbcd">RD</span>' : '<span class="flag no">—</span>'}</div>
    `;
    body.appendChild(row);
  });
}

function isLegacyOS(os) {
  const o = (os || '').toLowerCase();
  return o.includes('2000') || o.includes('2003') || o.includes('2008') || o.includes('2012') ||
         o.includes('2016') || o.includes('xp')   || o.includes('vista')|| o.includes('windows 7') ||
         o.includes('windows 8') || o.includes('windows nt');
}

function showComputerDetail(c, row) {
  document.querySelectorAll('.c-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('computer-detail').style.display = 'flex';

  const dcBadge = c.is_domain_controller ? '<span class="dc-badge">DC</span>' : '';
  document.getElementById('cd-avatar').textContent = (c.computer_name || '?').charAt(0).toUpperCase();
  document.getElementById('cd-name').innerHTML = dcBadge + (c.computer_name || '—');
  document.getElementById('cd-dn').textContent = c.dn || '—';

  const body = document.getElementById('computer-detail-body');
  body.innerHTML = '';

  const descHits = getSensitiveDescriptionMatches(c.description || '');
  const descValue = c.description ? highlightSensitiveDescriptionTerms(c.description) : '—';

  body.innerHTML += detailSection('Computer', [
    ['Name',       dcBadge + (c.computer_name || '—'), 'accent'],
    ['DNS',        c.dns_name   || '—', c.dns_name   ? '' : 'dim'],
    ['OS',         c.os         || '—', c.os         ? '' : 'dim'],
    ['OS Version', c.os_version || '—', c.os_version ? '' : 'dim'],
    ['Description',descValue,           c.description ? '' : 'dim'],
  ]);

  if (descHits.length > 0) {
    const chips = descHits.map(t => `<span class="desc-risk-chip">${escapeHtml(t)}</span>`).join('');
    body.innerHTML += `
      <div class="detail-section desc-risk-wave-box">
        <div class="detail-section-title" style="color:var(--red);">Description Risk Signals (${descHits.length})</div>
        <div class="desc-risk-chip-list">${chips}</div>
      </div>`;
  }

  body.innerHTML += detailSection('Flags', [
    ['Server',               c.is_server              ? '✓' : '✕', c.is_server ? 'green' : 'dim'],
    ['Workstation',          c.is_workstation         ? '✓' : '✕', c.is_workstation ? 'green' : 'dim'],
    ['Unconstrained Deleg.', c.unconstrained_delegation ? '✓' : '✕', c.unconstrained_delegation ? 'red' : 'dim'],
    ['Constrained Deleg.',   c.constrained_delegation   ? '✓' : '✕', c.constrained_delegation   ? 'amber' : 'dim'],
    ['RBCD Enabled',         c.rbcd_enabled             ? '✓' : '✕', c.rbcd_enabled ? 'red' : 'dim'],
    ['LAPS Enabled',         c.has_laps                 ? '✓' : '✕', c.has_laps ? 'green' : 'dim'],
    ['Domain Controller',    c.is_domain_controller   ? '✓' : '✕', c.is_domain_controller ? 'accent' : 'dim'],
    ['Stale',                c.is_stale               ? '✓' : '✕', c.is_stale ? 'amber' : 'green'],
    ['Disabled',             c.disabled               ? '✓' : '✕', c.disabled ? 'red'   : 'green'],
    ['SPN Count',            (Array.isArray(c.spn) ? c.spn.length : 0) > 0 ? (Array.isArray(c.spn) ? c.spn.length : 0) : '0',
                             (Array.isArray(c.spn) ? c.spn.length : 0) > 0 ? 'accent' : 'dim'],
  ]);

  const lapsRaw = (c.laps_attributes && typeof c.laps_attributes === 'object') ? c.laps_attributes : {};
  const lapsRows = Object.entries(lapsRaw)
    .map(([k, v]) => {
      const vals = Array.isArray(v) ? v.filter(Boolean) : (v ? [String(v)] : []);
      return { key: k, vals };
    })
    .filter(x => x.vals.length > 0);

  if (c.has_laps || lapsRows.length > 0) {
    const lapsItems = lapsRows.length > 0
      ? lapsRows.map(x => `<div class="spn-item"><b>${escapeHtml(x.key)}:</b> ${x.vals.map(v => escapeHtml(v)).join('<br>')}</div>`).join('')
      : '<div class="spn-item">LAPS is configured, but no readable attribute value was returned.</div>';

    body.innerHTML += `<div class="detail-section">
      <div class="detail-section-title">LAPS</div>
      <div class="spn-list">${lapsItems}</div>
    </div>`;
  }

  if (c.rbcd_enabled) {
    const rbcdSids = Array.isArray(c.rbcd_principals) ? c.rbcd_principals.filter(Boolean) : [];
    const rbcdSidItems = rbcdSids.length > 0
      ? rbcdSids.map(s => `<div class="spn-item">${escapeHtml(s)}</div>`).join('')
      : '<div class="spn-item">No SID entries parsed</div>';
    const rbcdSddl = c.rbcd_sddl ? `<div class="spn-item"><b>SDDL:</b> ${escapeHtml(c.rbcd_sddl)}</div>` : '';

    body.innerHTML += `<div class="detail-section">
      <div class="detail-section-title">Resource Based Constrained Delegation</div>
      <div class="spn-list">${rbcdSidItems}${rbcdSddl}</div>
    </div>`;
  }

  if (c.is_domain_controller) {
    body.innerHTML += detailSection('Domain Controller', [
      ['DC Name',  c.computer_name || '—', 'accent'],
      ['DNS Name', c.dns_name      || '—', c.dns_name ? '' : 'dim'],
    ]);
  }

  const spnList = Array.isArray(c.spn) ? c.spn : [];
  if (spnList.length > 0) {
    body.innerHTML += `<div class="detail-section">
      <div class="detail-section-title">Service Principals</div>
      <div class="spn-list">${spnList.map(s => `<div class="spn-item">${escapeHtml(s)}</div>`).join('')}</div>
    </div>`;
  }

  const riskControls = Array.isArray(c.risk_controls) ? c.risk_controls : [];
  if (riskControls.length > 0) {
    body.innerHTML += `<div class="detail-section">
      <div class="detail-section-title">Risk Controls</div>
      <div class="spn-list">${riskControls.map(r => `<div class="spn-item">${escapeHtml(r)}</div>`).join('')}</div>
    </div>`;
  }
}

function closeComputerDetail() {
  document.getElementById('computer-detail').style.display = 'none';
  document.querySelectorAll('.c-row').forEach(r => r.classList.remove('selected'));
}