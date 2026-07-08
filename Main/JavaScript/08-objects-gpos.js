let gposFilter = 'all';
let gposSearch = '';


let gposDomainsSelected     = null;
let gposDomainsDropdownOpen = false;

function gpoBelongsToDomain(gpo, domain) {
  const dn = gpo.path || gpo.dn || '';
  if (domain.sid && gpo.sid) {
    const s  = String(gpo.sid).trim().toUpperCase();
    const ds = domain.sid.toUpperCase();
    if (s === ds || s.startsWith(ds + '-')) return true;
  }
  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return dn.toLowerCase().endsWith(suffix);
}

async function toggleGPOsDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('gpo-domains-dropdown');
  if (!dd) return;

  if (gposDomainsDropdownOpen) {
    closeGPOsDomainsDropdown();
    return;
  }

  gposDomainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('gpo-domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureDomainsListLoaded();
    if (!gposDomainsSelected) {
      gposDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
    }
    renderGPOsDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleGPOsDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleGPOsDomainsDropdownEscape);
}

function closeGPOsDomainsDropdown() {
  gposDomainsDropdownOpen = false;
  const dd = document.getElementById('gpo-domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleGPOsDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleGPOsDomainsDropdownEscape);
}

function handleGPOsDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('gpo-domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeGPOsDomainsDropdown();
}

function handleGPOsDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeGPOsDomainsDropdown();
}

function renderGPOsDomainsDropdownList() {
  const listEl = document.getElementById('gpo-domains-dropdown-list');
  if (!listEl) return;

  if (!domainsListCache || domainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = domainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = gposDomainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleGPODomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateGPOsDomainsSelectCount();
}

function updateGPOsDomainsSelectCount() {
  const countEl = document.getElementById('gpo-domains-select-count');
  if (!countEl || !domainsListCache) return;
  const total = domainsListCache.length;
  const selected = gposDomainsSelected ? gposDomainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

function toggleGPODomainSelected(domainKey, checked) {
  if (!gposDomainsSelected) gposDomainsSelected = new Set();
  if (checked) gposDomainsSelected.add(domainKey);
  else gposDomainsSelected.delete(domainKey);
  updateGPOsDomainsSelectCount();
  renderGPOs();
}

function resetGPOsDomainsSelection() {
  if (!domainsListCache) return;
  gposDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
  renderGPOsDomainsDropdownList();
  renderGPOs();
}

async function loadGPOs() {
  document.getElementById('gpos-loading').style.display = 'flex';
  document.getElementById('g-table-body').innerHTML = '';
  closeGPODetail();


  gposDomainsSelected = null;

  try {
    let url = `${DB_BASE}/api/list/gpos?limit=500`;
    if (gposSearch && gposSearch.trim()) {
      url += `&q=${encodeURIComponent(gposSearch.trim())}`;
    }

    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data) {
      throw new Error((data && (data.error || data.detail)) || `Oxsium SQLite Engine error (HTTP ${resp.status})`);
    }

    const raw = Array.isArray(data.records) ? data.records : (Array.isArray(data.rows) ? data.rows : []);
    gposData = raw.map(g => ({
      ...g,

      linked_containers: Array.isArray(g.linked_containers)
        ? g.linked_containers
        : (typeof g.linked_containers === 'string'
            ? (() => { try { return JSON.parse(g.linked_containers); } catch { return []; } })()
            : []),
      risk_controls: Array.isArray(g.risk_controls)
        ? g.risk_controls
        : (typeof g.risk_controls === 'string'
            ? (() => { try { return JSON.parse(g.risk_controls); } catch { return []; } })()
            : []),

      has_settings_markers: g.has_settings_markers ??
        ((() => {
          const me = Array.isArray(g.machine_extensions) ? g.machine_extensions
            : (typeof g.machine_extensions === 'string'
                ? (() => { try { return JSON.parse(g.machine_extensions); } catch { return []; } })()
                : []);
          const ue = Array.isArray(g.user_extensions) ? g.user_extensions
            : (typeof g.user_extensions === 'string'
                ? (() => { try { return JSON.parse(g.user_extensions); } catch { return []; } })()
                : []);
          return me.length > 0 || ue.length > 0;
        })()),

      vulnerable: g.vulnerable ?? (g.highvalue || g.high_risk || false),

      has_cpasswords: (() => {
        const cp = Array.isArray(g.all_cpasswords) ? g.all_cpasswords
          : (typeof g.all_cpasswords === 'string'
              ? (() => { try { return JSON.parse(g.all_cpasswords); } catch { return []; } })()
              : []);
        return cp.length > 0;
      })(),
    }));

    enumCacheLoaded.gpos = true;
    const total = (typeof data.total === 'number') ? data.total : gposData.length;
    setObjectCountStat('cnt-gpos', total);
    document.getElementById('nav-gpo-count').textContent = total;
    document.getElementById('gpos-meta').textContent =
      `${total} GPOs · source: Oxsium SQLite Engine (.db)`;

    renderGPOs();
    addLog(`GPOs loaded from sqlite_reader.py: ${total} GPO (Oxsium SQLite Engine)`, 'ok');
  } catch (err) {
    addLog(`GPOs: ${err.message}`, 'err');
    document.getElementById('g-table-body').innerHTML = `<div class="g-empty"><p>${escapeHtml(err.message)}</p></div>`;
  } finally {
    document.getElementById('gpos-loading').style.display = 'none';
  }
}

function renderGPOs() {
  const body = document.getElementById('g-table-body');
  let list = gposData.filter(gpo => gpo.name != null || gpo.guid != null || gpo.display_name != null);
  if (domainsListCache && gposDomainsSelected && gposDomainsSelected.size < domainsListCache.length) {
    const activeDomains = domainsListCache.filter(d => gposDomainsSelected.has(d.name.toLowerCase()));
    list = list.filter(gpo => activeDomains.some(d => gpoBelongsToDomain(gpo, d)));
  }
  if (gposSearch) list = list.filter(gpo =>
    (gpo.name || '').toLowerCase().includes(gposSearch) ||
    (gpo.display_name || '').toLowerCase().includes(gposSearch)
  );
  if (gposFilter === 'vulnerable') list = list.filter(gpo => !!gpo.vulnerable);
  if (gposFilter === 'links')      list = list.filter(gpo => (gpo.linked_count || 0) > 0);
  if (gposFilter === 'settings')   list = list.filter(gpo => !!gpo.has_settings_markers);
  if (gposFilter === 'cpassword')  list = list.filter(gpo => !!gpo.has_cpasswords);
  filteredGPOs = list;
  body.innerHTML = '';
  if (filteredGPOs.length === 0) { body.innerHTML = '<div class="g-empty"><p>No matching GPOs</p></div>'; return; }
  filteredGPOs.forEach(gpo => {
    const row = document.createElement('div');
    row.className = 'g-row';
    row.onclick = () => showGPODetail(gpo, row);
    row.innerHTML = `
      <div class="g-cell g-cell-name">${escapeHtml(gpo.name || '—')}</div>
      <div class="g-cell g-cell-display" title="${escapeHtml(gpo.display_name || '')}">${escapeHtml(gpo.display_name || '—')}</div>
      <div class="g-cell g-cell-status">${gpo.version || '0'}</div>
      <div class="g-cell g-cell-owner" title="${escapeHtml(gpo.modified || '')}">${escapeHtml(gpo.modified || '—')}</div>
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
    ? linked.map(l => `<div class="group-item">${escapeHtml(l)}</div>`).join('')
    : '<span class="d-val dim">—</span>';
  detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Linked Containers (${linked.length})</div><div class="spn-list">${linksHtml}</div></div>`;
  const riskControls = Array.isArray(gpo.risk_controls) ? gpo.risk_controls : [];
  if (riskControls.length > 0) {
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Risk Controls</div><div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${riskControls.map(r => `<div class="badge amber">${escapeHtml(r)}</div>`).join('')}</div></div>`;
  }


  const cpasswords = parseJsonField(gpo.all_cpasswords);
  if (cpasswords.length > 0) {
    const cpHtml = cpasswords.map(cp => `
      <div class="group-item" style="display:flex;flex-direction:column;gap:4px;padding:8px 0;border-bottom:1px solid var(--border);">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-weight:600;color:var(--red);">⚠ ${escapeHtml(cp.username || cp.name || '—')}</span>
          <span class="badge amber" style="font-size:10px;">${escapeHtml(cp.context || '—')}</span>
        </div>
        <div style="display:grid;grid-template-columns:90px 1fr;gap:2px 8px;font-size:11px;">
          <span style="color:var(--text-muted);">Plaintext</span>
          <span style="font-family:monospace;color:var(--red);word-break:break-all;">${escapeHtml(cp.plaintext || '—')}</span>
          <span style="color:var(--text-muted);">Cpassword</span>
          <span style="font-family:monospace;font-size:10px;color:var(--text-muted);word-break:break-all;">${escapeHtml(cp.cpassword || '—')}</span>
          <span style="color:var(--text-muted);">GPO</span>
          <span>${escapeHtml(cp.gpo_name || cp.gpo_guid || '—')}</span>
        </div>
      </div>`).join('');
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title" style="color:var(--red);">⚠ Cpasswords — Cleartext Credentials (${cpasswords.length})</div><div class="spn-list" style="padding:0;">${cpHtml}</div></div>`;
  }


  const parseJsonField = v => {
    if (Array.isArray(v)) return v;
    if (typeof v === 'string') { try { return JSON.parse(v); } catch { return []; } }
    return [];
  };
  const parseObjField = v => {
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
    if (typeof v === 'string') { try { return JSON.parse(v); } catch { return null; } }
    return null;
  };

  const machineExts = parseJsonField(gpo.machine_extensions);
  const userExts    = parseJsonField(gpo.user_extensions);
  if (machineExts.length > 0 || userExts.length > 0) {
    const extRows = [...machineExts.map(e => ['Machine', e.name || e.guid || '—', e.guid || '']),
                     ...userExts.map(e => ['User', e.name || e.guid || '—', e.guid || ''])];
    const extHtml = extRows.map(([scope, name, guid]) =>
      `<div class="group-item" style="display:flex;justify-content:space-between;gap:8px;">
        <span><span class="badge ${scope === 'Machine' ? 'blue' : 'amber'}" style="margin-right:6px;font-size:10px;">${scope}</span>${escapeHtml(name)}</span>
        ${guid ? `<span class="gr-member-sid" style="font-size:10px;">${escapeHtml(guid)}</span>` : ''}
       </div>`
    ).join('');
    detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">CSE Extensions (${extRows.length})</div><div class="spn-list">${extHtml}</div></div>`;
  }


  const sysvol = parseObjField(gpo.sysvol);
  if (sysvol) {

    const scripts = parseJsonField(sysvol.scripts);
    if (scripts.length > 0) {
      const sHtml = scripts.map(s =>
        `<div class="group-item"><span class="badge amber" style="margin-right:6px;font-size:10px;">${escapeHtml(s.type || s.stage || '?')}</span>${escapeHtml(s.script || s.path || JSON.stringify(s))}</div>`
      ).join('');
      detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Scripts (${scripts.length})</div><div class="spn-list">${sHtml}</div></div>`;
    }


    const sec = parseObjField(sysvol.security_settings);
    if (sec) {
      const secRows = [];
      const pwPol = parseObjField(sec.password_policy);
      if (pwPol && Object.keys(pwPol).length > 0) {
        Object.entries(pwPol).forEach(([k, v]) => secRows.push([k.replace(/_/g,' '), String(v), '']));
      }
      const userRights = parseJsonField(sec.user_rights);
      userRights.forEach(ur => secRows.push(['User Right: ' + (ur.right || ur.name || '?'), (ur.accounts || []).join(', ') || '—', '']));
      const restrictedGroups = parseJsonField(sec.restricted_groups);
      restrictedGroups.forEach(rg => secRows.push(['Restricted Group', rg.group || rg.name || JSON.stringify(rg), 'amber']));
      if (secRows.length > 0) {
        detailBody.innerHTML += detailSection('Security Settings', secRows);
      }
    }


    const pkgs = parseJsonField(sysvol.software_packages);
    if (pkgs.length > 0) {
      const pkgHtml = pkgs.map(p =>
        `<div class="group-item">${escapeHtml(p.name || p.display_name || JSON.stringify(p))}</div>`
      ).join('');
      detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Software Packages (${pkgs.length})</div><div class="spn-list">${pkgHtml}</div></div>`;
    }


    const xmlFiles = parseJsonField(sysvol.xml_files);
    if (xmlFiles.length > 0) {
      const xmlHtml = xmlFiles.map(f => {
        const fname = typeof f === 'string' ? f : (f.path || f.name || JSON.stringify(f));
        return `<div class="group-item" style="font-size:11px;word-break:break-all;">${escapeHtml(fname)}</div>`;
      }).join('');
      detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">XML / Preference Files (${xmlFiles.length})</div><div class="spn-list">${xmlHtml}</div></div>`;
    }


    const allFiles = parseJsonField(sysvol.all_files);
    if (allFiles.length > 0) {
      const fHtml = allFiles.map(f =>
        `<div class="group-item" style="font-size:11px;word-break:break-all;">${escapeHtml(typeof f === 'string' ? f : JSON.stringify(f))}</div>`
      ).join('');
      detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title">Sysvol Files (${allFiles.length})</div><div class="spn-list">${fHtml}</div></div>`;
    }


    const parseErrors = parseJsonField(sysvol.parse_errors);
    if (parseErrors.length > 0) {
      detailBody.innerHTML += `<div class="detail-section"><div class="detail-section-title" style="color:var(--red);">Sysvol Parse Errors (${parseErrors.length})</div><div class="spn-list">${parseErrors.map(e => `<div class="group-item" style="color:var(--red);">${escapeHtml(String(e))}</div>`).join('')}</div></div>`;
    }
  }

  document.getElementById('gpo-detail').style.display = 'flex';
}

function closeGPODetail() {
  document.getElementById('gpo-detail').style.display = 'none';
  document.querySelectorAll('.g-row').forEach(r => r.classList.remove('selected'));
}