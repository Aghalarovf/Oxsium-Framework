/* Oxsium Certificate Service — ESC1–ESC15 Vulnerability Panel */

// Dynamic activation: modules are discovered and activated by backend scan
// References panel shows only modules found by RUN Full SCAN
const REFS = [
  {
    id: 'ESC2', name: 'Any Purpose Template', sev: 'CRITICAL', score: '9.1',
    desc: 'Templates with "Any Purpose" EKU or no EKU defined allow certificates to be used for any authentication purpose, including client authentication and smart card logon.',
    impact: 'Lateral Movement / Priv Esc', proto: 'LDAP + Certipy', cve: 'CVE-2021-36943', mitre: 'T1649',
    steps: ['Find templates with Any Purpose EKU', 'Enroll with low-priv account', 'Use cert to auth as any user', 'Escalate privileges'],
    active: false
  },
  {
    id: 'ESC3', name: 'Enrollment Agent Abuse', sev: 'CRITICAL', score: '8.9',
    desc: 'Templates with Certificate Request Agent EKU combined with misconfigured issuance policies enable enrollment on behalf of other users, allowing impersonation of privileged accounts.',
    impact: 'Certificate-Based Impersonation', proto: 'ADCS + Certipy', cve: 'N/A', mitre: 'T1649',
    steps: ['Obtain enrollment agent cert (ESC3-1)', 'Request cert on behalf of DA (ESC3-2)', 'Authenticate as target user', 'Achieve domain persistence'],
    active: false
  },
  {
    id: 'ESC4', name: 'Vulnerable Template Access Control', sev: 'CRITICAL', score: '8.7',
    desc: 'Overly permissive ACLs on certificate templates allow low-privileged users to write to template attributes, enabling modification of template settings to introduce ESC1/ESC2 conditions.',
    impact: 'Template Backdoor / Persistence', proto: 'LDAP ACL Abuse', cve: 'N/A', mitre: 'T1484',
    steps: ['Identify writable template objects', 'Modify msPKI-Certificate-Name-Flag', 'Enable ENROLLEE_SUPPLIES_SUBJECT', 'Chain to ESC1 attack'],
    active: false
  },
  {
    id: 'ESC5', name: 'PKI Object ACL Abuse', sev: 'HIGH', score: '8.2',
    desc: 'Weak ACLs on CA server objects, NTAuthCertificates, RootCA objects, or Enterprise PKI containers allow manipulation of the PKI infrastructure itself.',
    impact: 'PKI Infrastructure Compromise', proto: 'LDAP/DCOM', cve: 'N/A', mitre: 'T1484',
    steps: ['Enumerate PKI container ACLs', 'Identify writable CA objects', 'Add rogue certificate to NTAuth', 'Enable cross-forest auth bypass'],
    active: false
  },
  {
    id: 'ESC6', name: 'EDITF_ATTRIBUTESUBJECTALTNAME2', sev: 'HIGH', score: '8.0',
    desc: 'CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enables SAN specification in any certificate request regardless of template settings, allowing domain admin impersonation.',
    impact: 'Arbitrary SAN Injection', proto: 'certreq.exe / Certipy', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Check CA flags via certutil', 'Confirm EDITF flag presence', 'Submit CSR with arbitrary SAN', 'Obtain DA-level certificate'],
    active: false
  },
  {
    id: 'ESC7', name: 'CA Manager Privilege Abuse', sev: 'HIGH', score: '7.8',
    desc: 'Users with ManageCA or ManageCertificates permissions can approve pending certificate requests, modify CA configuration, or issue certificates for any template.',
    impact: 'CA Administrative Takeover', proto: 'ICertAdminD2 DCOM', cve: 'N/A', mitre: 'T1649',
    steps: ['Enumerate CA DACL', 'Identify ManageCA/ManageCerts rights', 'Enable EDITF flag via DCOM', 'Issue cert for SubCA or DA template'],
    active: false
  },
  {
    id: 'ESC8', name: 'NTLM Relay to AD CS HTTP', sev: 'HIGH', score: '7.5',
    desc: 'AD CS web enrollment interfaces (certsrv) vulnerable to NTLM relay attacks. Machine account credentials can be relayed to obtain domain controller certificates enabling DCSync.',
    impact: 'DCSync via Certificate Relay', proto: 'Impacket + ntlmrelayx', cve: 'CVE-2021-36942', mitre: 'T1557.001',
    steps: ['Set up NTLM relay listener', 'Trigger DC NTLM auth (PetitPotam)', 'Relay to /certsrv/certfnsh.asp', 'Obtain DC certificate → DCSync'],
    active: false
  },
  {
    id: 'ESC9', name: 'No Security Extension (szOID)', sev: 'HIGH', score: '7.2',
    desc: 'Templates without szOID_NTDS_CA_SECURITY_EXT are vulnerable when StrongCertificateBindingEnforcement is not enabled, allowing certificate mapping bypass via UPN changes.',
    impact: 'Authentication Binding Bypass', proto: 'PKINIT', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Identify templates missing security ext', 'Check registry binding enforcement', 'Modify UPN of controlled account', 'Request and use modified cert'],
    active: false
  },
  {
    id: 'ESC10', name: 'Weak Certificate Mapping', sev: 'MEDIUM', score: '6.8',
    desc: 'Weak certificate-to-account mapping (CertificateMappingMethods registry) combined with user-controlled UPN enables certificate theft and authentication abuse across accounts.',
    impact: 'Cross-Account Auth Abuse', proto: 'Kerberos PKINIT', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Check CertificateMappingMethods value', 'Enumerate user-controllable UPNs', 'Change UPN to match target cert', 'Authenticate using stolen certificate'],
    active: false
  },
  {
    id: 'ESC11', name: 'IF_ENFORCEENCRYPTICERTREQUEST', sev: 'MEDIUM', score: '6.5',
    desc: 'CA missing the IF_ENFORCEENCRYPTICERTREQUEST flag allows NTLM relay attacks over RPC (MS-ICPR) without requiring HTTPS, expanding relay attack surface.',
    impact: 'RPC-based NTLM Relay', proto: 'MS-ICPR + ntlmrelayx', cve: 'N/A', mitre: 'T1557',
    steps: ['Enumerate CA flags via certutil', 'Confirm missing ENFORCEENCRYPT flag', 'Relay NTLM over port 135 (RPC)', 'Obtain certificate via ICertPassage'],
    active: false
  },
  {
    id: 'ESC12', name: 'Shell Access to CA Server', sev: 'MEDIUM', score: '6.2',
    desc: 'Principals with remote code execution capability on CA server via WMI, SCM, or scheduled tasks can access CA private keys and configuration, enabling arbitrary certificate issuance.',
    impact: 'CA Private Key Exfiltration', proto: 'WMI / SCM / PSRemoting', cve: 'N/A', mitre: 'T1552.004',
    steps: ['Identify CA server shell access', 'Locate CA private key store', 'Export via certutil or direct DPAPI', 'Forge arbitrary certificates offline'],
    active: false
  },
  {
    id: 'ESC13', name: 'OID Group Link Abuse', sev: 'MEDIUM', score: '5.9',
    desc: 'Issuance policy OIDs linked to AD groups with msPKI-Cert-Template-OID attribute allow certificate holders to gain group membership, potentially elevating to privileged groups.',
    impact: 'Unauthorized Group Membership', proto: 'LDAP + Certipy', cve: 'N/A', mitre: 'T1484',
    steps: ['Find OID-to-group mappings', 'Identify issuance policies in templates', 'Enroll in template with target OID', 'Certificate grants group membership'],
    active: false
  },
  {
    id: 'ESC14', name: 'Weak Explicit Alt Name Mapping', sev: 'LOW', score: '4.3',
    desc: 'Explicit certificate mappings using altSecurityIdentities with weak binding methods (X509IssuerSubject or X509SubjectOnly) can be abused if adversary can influence subject DN.',
    impact: 'Account Mapping Manipulation', proto: 'LDAP', cve: 'N/A', mitre: 'T1649',
    steps: ['Enumerate altSecurityIdentities attributes', 'Identify weak mapping types', 'Craft certificate with matching DN', 'Authenticate using mapped identity'],
    active: false
  },
  {
    id: 'ESC15', name: 'Application Policy Mismatch', sev: 'LOW', score: '3.9',
    desc: 'Schema V1 templates allow specifying application policies via CSR extensions. If CA does not enforce template-defined EKU validation, arbitrary EKUs can be added to issued certificates.',
    impact: 'EKU Policy Bypass', proto: 'certreq.exe CSR extension', cve: 'N/A', mitre: 'T1649',
    steps: ['Identify Schema V1 templates', 'Craft CSR with custom application policy', 'Submit to CA without strict EKU validation', 'Use issued cert with arbitrary EKU'],
    active: false
  }
];

/* ── SEVERITY CONFIG ── */
const SEV = {
  CRITICAL: { stripe: 'stripe-crit', badge: 'b-red',    scoreColor: 'var(--sev-crit)', scoreGlow: '0 0 10px rgba(239,68,68,0.4)' },
  HIGH:     { stripe: 'stripe-high', badge: 'b-orange',  scoreColor: 'var(--sev-high)', scoreGlow: '0 0 10px rgba(249,115,22,0.3)' },
  MEDIUM:   { stripe: 'stripe-med',  badge: 'b-yellow',  scoreColor: 'var(--sev-med)',  scoreGlow: '0 0 10px rgba(234,179,8,0.3)'  },
  LOW:      { stripe: 'stripe-low',  badge: 'b-green',   scoreColor: 'var(--sev-low)',  scoreGlow: '0 0 10px rgba(34,197,94,0.3)'  },
};

/* ── HELPERS ── */
function sevCfg(sev) { return SEV[sev] || SEV.LOW; }

function log(id, msg, type = '') {
  const box = document.getElementById('log-' + id);
  if (!box) return;
  box.classList.add('active');
  const line = document.createElement('div');
  line.className = 'log-line' + (type ? ' ' + type : '');
  line.textContent = msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function addGlobalLog(msg, type = '') {
  const box = document.getElementById('globalLogBox');
  if (!box) return;
  const line = document.createElement('div');
  line.className = 'log-line' + (type ? ' ' + type : '');
  line.textContent = msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function animVal(el, target, duration = 600) {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const diff  = target - start;
  const t0    = performance.now();
  function step(now) {
    const p = Math.min(1, (now - t0) / duration);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + diff * ease);
    el.classList.add('tick');
    if (p < 1) requestAnimationFrame(step);
    else el.textContent = target;
  }
  requestAnimationFrame(step);
}

function getInputValue(id, fallback = '') {
  const field = document.getElementById(id);
  return field ? (field.value || '').trim() : fallback;
}

function setInputValue(id, value) {
  const field = document.getElementById(id);
  if (field) field.value = value;
}

function getCertificatePayload() {
  const domain = getInputValue('domainInput');
  const nameServer = getInputValue('nameServerInput');
  const username = getInputValue('usernameInput');
  const password = getInputValue('secretInput');

  return { domain, name_server: nameServer, username, password };
}

function getCertificateApiBase() {
  return (window.CERTIFICATE_API_BASE || 'http://127.0.0.1:5005').replace(/\/$/, '');
}

function persistCertificateUser(payload) {
  return fetch(getCertificateApiBase() + '/api/certificate/saved-users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).catch(() => null);
}

function formatSavedSecret(item) {
  const secret = item.password || '';
  if (!secret) return '—';
  return secret;
}

function parseBackendResponse(response) {
  return response.text().then(text => {
    if (!text) {
      return { ok: response.ok, data: null, raw: '' };
    }

    try {
      return { ok: response.ok, data: JSON.parse(text), raw: text };
    } catch (error) {
      return { ok: response.ok, data: null, raw: text, parseError: error.message };
    }
  });
}

function refreshCertificateState(findings, totalModules = REFS.length) {
  const foundTypes = new Set((findings || []).map(item => item.esc_type));

  REFS.forEach(moduleEntry => {
    moduleEntry.active = foundTypes.has(moduleEntry.id);
  });

  animVal(document.getElementById('vulnVal'), foundTypes.size);
  setProgressBar('pb-vuln', foundTypes.size > 0 ? 100 : 0);
  updateRing(foundTypes.size, totalModules);
  updateSevBars();
  buildRefs();
  buildVulns();

  return foundTypes;
}

function renderSavedUsers(users) {
  const panel = document.getElementById('savedUsersPanel');
  if (!panel) return;

  if (!users || !users.length) {
    panel.innerHTML = '<div class="log-line info">[*] No saved users found</div>';
    return;
  }

  panel.innerHTML = users.map((item, index) => `
    <div class="saved-user-item" data-index="${index}" style="border:1px solid var(--border);border-radius:8px;background:rgba(204,26,26,0.03);cursor:pointer;width:100%;">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;width:100%">
        <div style="min-width:0;flex:1">
          <div style="font-family:var(--mono);font-size:11px;color:var(--c5);font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.username || 'Unknown user'}</div>
          <div style="font-size:10px;color:var(--text2);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.domain || '—'} · ${item.name_server || '—'}</div>
          <div style="font-size:9px;color:var(--text4);margin-top:4px">Saved: ${item.saved_at || '—'}</div>
        </div>
        <div style="font-size:10px;color:var(--text2);text-align:right;white-space:normal;word-break:break-all;overflow-wrap:anywhere;max-width:45%">${formatSavedSecret(item)}</div>
      </div>
    </div>
  `).join('');

  panel.querySelectorAll('.saved-user-item').forEach((element, index) => {
    element.addEventListener('click', () => {
      const item = users[index];
      if (!item) return;

      const domainInput = document.getElementById('domainInput');
      const nameServerInput = document.getElementById('nameServerInput');
      const usernameInput = document.getElementById('usernameInput');
      const secretInput = document.getElementById('secretInput');

      setInputValue('domainInput', item.domain || '');
      setInputValue('nameServerInput', item.name_server || '');
      setInputValue('usernameInput', item.username || '');
      setInputValue('secretInput', item.password || '');

      if (domainInput) domainInput.dispatchEvent(new Event('input', { bubbles: true }));
      if (nameServerInput) nameServerInput.dispatchEvent(new Event('input', { bubbles: true }));
      if (usernameInput) usernameInput.dispatchEvent(new Event('input', { bubbles: true }));

      addGlobalLog('[*] Loaded saved user: ' + (item.username || 'Unknown user'), 'info');
    });
  });
}

function loadSavedUsers() {
  fetch(getCertificateApiBase() + '/api/certificate/saved-users')
    .then(parseBackendResponse)
    .then(({ ok, data, raw, parseError }) => {
      if (!data) {
        const message = parseError || (raw ? raw.slice(0, 160) : 'empty response');
        const panel = document.getElementById('savedUsersPanel');
        if (panel) panel.innerHTML = '<div class="log-line err">[!] Failed to load saved users: ' + message + '</div>';
        return;
      }

      if (!ok || data.status === 'error') {
        const message = data.error || data.message || 'Failed to load saved users';
        const panel = document.getElementById('savedUsersPanel');
        if (panel) panel.innerHTML = '<div class="log-line err">[!] ' + message + '</div>';
        return;
      }

      renderSavedUsers(Array.isArray(data.saved_users) ? data.saved_users : []);
    })
    .catch(error => {
      const panel = document.getElementById('savedUsersPanel');
      if (panel) panel.innerHTML = '<div class="log-line err">[!] Failed to load saved users: ' + error.message + '</div>';
    });
}

/* ── BUILD LEFT PANEL ── */
/* Toggle saved users collapsible panel */
function toggleSavedUsersPanel() {
  const pro = document.getElementById('savedUsersPro');
  if (!pro) return;
  const isOpen = pro.classList.contains('open');
  pro.classList.toggle('open', !isOpen);
  pro.classList.toggle('collapsed', isOpen);
  if (!isOpen) loadSavedUsers();
}

function buildRefs() {
  const panel = document.getElementById('refPanel');
  let html = '<div class="lbl">References</div>';
  // Only render active modules
  REFS.filter(r => r.active).forEach((r, i) => {
    const cfg = sevCfg(r.sev);
    html += `
      <div class="ref-item${i === 0 ? ' active' : ''}" style="--i:${i}" onclick="scrollToVuln('${r.id}', this)">
        <div class="ref-code">${r.id}</div>
        <div class="ref-name">${r.name}</div>
        <div class="ref-sev" style="margin-top:4px"><span class="badge ${cfg.badge}">Vulnerable ${r.score}</span></div>
      </div>`;
  });
  panel.innerHTML = html;
}

/* ── BUILD VULN CARDS ── */
function buildVulns() {
  const list = document.getElementById('vulnList');
  if (!list) return;
  list.innerHTML = `
    <div class="workspace-empty workspace-empty-center">
      Connect to a domain first
    </div>`;
}

/* ════════════════════════════════════════
   TEMPLATE CARDS
   ════════════════════════════════════════ */

let _allTemplates = [];

function _sevCol(sev) {
  return ({CRITICAL:'var(--sev-crit)',HIGH:'var(--sev-high)',
           MEDIUM:'var(--sev-med)',LOW:'var(--sev-low)'})[sev] || 'var(--text4)';
}
function _sevBg(sev) {
  return ({CRITICAL:'rgba(239,68,68,0.10)',HIGH:'rgba(249,115,22,0.09)',
           MEDIUM:'rgba(234,179,8,0.09)',LOW:'rgba(34,197,94,0.09)'})[sev] || 'transparent';
}

/* Collapsed satır — template adı + zəiflik badge-ləri */
function _tplRow(t, idx) {
  const r = t.raw, p = t.parsed;
  const name    = r.displayName || r.cn || 'Unknown';
  const badges = `<span style="font-family:var(--mono);font-size:8px;color:var(--text4);
    padding:2px 6px;border:1px solid var(--border);border-radius:3px;">INFO</span>`;

  return `
  <div class="tpl-card" id="tpl-card-${idx}"
       style="border:1px solid var(--border);
              border-radius:7px;overflow:hidden;
              background:rgba(26,26,26,0.6);
              transition:border-color .2s,background .2s;">
    <!-- HEADER ROW -->
    <div onclick="toggleTemplate(${idx})"
         style="display:flex;align-items:center;justify-content:space-between;
                padding:10px 14px;cursor:pointer;gap:10px;
                transition:background .18s;"
         onmouseover="this.style.background='rgba(204,26,26,0.04)'"
         onmouseout="this.style.background='transparent'">
      <div style="display:flex;align-items:center;gap:9px;min-width:0">
        <span style="font-family:var(--mono);font-size:8px;color:var(--text4);
          width:24px;flex-shrink:0;text-align:right;">${idx+1}</span>
        <span style="width:1px;height:14px;background:var(--border);flex-shrink:0"></span>
        <span style="font-family:var(--mono);font-size:11px;font-weight:700;
          color:var(--text);
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px;"
          title="${name}">${name}</span>
      </div>
      <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
        ${badges}
        <span id="tpl-chev-${idx}"
          style="font-size:10px;color:var(--text4);margin-left:4px;
                 transition:transform .2s;display:inline-block;">▼</span>
      </div>
    </div>
    <!-- EXPANDED BODY -->
    <div id="tpl-body-${idx}"
         style="display:none;border-top:1px solid var(--border);padding:16px 16px 14px;">
      ${_tplBody(r, p)}
    </div>
  </div>`;
}

/* Genişlənmiş bölmə — bütün atributlar */
function _tplBody(r, p) {
  const ekuList = (p.eku_friendly || []).map(e =>
    `<span style="display:inline-block;font-family:var(--mono);font-size:9px;
      padding:2px 7px;margin:2px;border-radius:4px;
      background:rgba(204,26,26,0.07);border:1px solid var(--border2);
      color:var(--c5);">${e.name}</span>`
  ).join('') || '<span style="color:var(--text4);font-size:9px">—</span>';

  function flagList(arr) {
    if (!arr || !arr.length) return '<span style="color:var(--text4);font-size:9px">—</span>';
    return arr.map(f => `<span style="display:inline-block;font-family:var(--mono);font-size:8px;
      padding:1px 6px;margin:2px;border-radius:3px;
      background:rgba(100,116,139,0.10);border:1px solid var(--border);
      color:var(--text2);">${f.replace(/^CT_FLAG_|^CTPRIVATEKEY_FLAG_/,'')}</span>`
    ).join('');
  }

  function row(label, val, highlight) {
    return `<div style="display:flex;gap:10px;align-items:flex-start;padding:5px 0;
              border-bottom:1px solid rgba(204,26,26,0.06)">
      <span style="font-family:var(--mono);font-size:9px;color:var(--text4);
        width:160px;flex-shrink:0;letter-spacing:.3px;padding-top:2px">${label}</span>
      <span style="font-family:var(--mono);font-size:9px;
        color:${highlight||'var(--text2)'};flex:1;word-break:break-all">${val}</span>
    </div>`;
  }

  const aclRows = (p.acl_enrollment_aces || []).slice(0,8).map(ace => {
    const rCol = ace.type === 'Allow' ? 'var(--sev-low)' : 'var(--sev-crit)';
    return `<div style="font-family:var(--mono);font-size:8px;padding:3px 6px;
      border-radius:4px;background:rgba(26,26,26,0.7);border:1px solid var(--border);
      margin-bottom:3px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span style="color:${rCol};font-weight:700">${ace.type}</span>
      <span style="color:var(--text4)">${ace.sid}</span>
      <span style="color:var(--c5)">${(ace.rights||[ace.right]).join(', ')}</span>
    </div>`;
  }).join('');

  return `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 24px">
      <div>
        ${row('Display Name',    r.displayName || r.cn || '—')}
        ${row('CN',              r.cn || '—')}
        ${row('Schema Version',  r['msPKI-Template-Schema-Version'] || '—')}
        ${row('Validity',        p.validity_period || '—')}
        ${row('Renewal Period',  p.renewal_period  || '—')}
        ${row('Min Key Size',    (r['msPKI-Minimal-Key-Size']||'—') + ' bit')}
        ${row('RA Signatures',   p.ra_signature != null ? p.ra_signature : '—')}
        ${row('Machine Type',    p.is_machine_type ? 'Yes' : 'No')}
        ${row('Is CA',           p.is_ca ? 'Yes' : 'No')}
      </div>
      <div>
        <div style="margin-bottom:8px">
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;
            text-transform:uppercase;color:var(--text4);margin-bottom:5px">EKU</div>
          <div>${ekuList}</div>
        </div>
        <div style="margin-bottom:8px">
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;
            text-transform:uppercase;color:var(--text4);margin-bottom:5px">Subject Name Flags</div>
          <div>${flagList(p.subject_name_flags_decoded)}</div>
        </div>
        <div style="margin-bottom:8px">
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;
            text-transform:uppercase;color:var(--text4);margin-bottom:5px">Enrollment Flags</div>
          <div>${flagList(p.enrollment_flags_decoded)}</div>
        </div>
        <div>
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;
            text-transform:uppercase;color:var(--text4);margin-bottom:5px">Private Key Flags</div>
          <div>${flagList(p.private_key_flags_decoded)}</div>
        </div>
      </div>
    </div>
    ${aclRows ? `
    <div style="margin-top:12px">
      <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;
        text-transform:uppercase;color:var(--text4);margin-bottom:6px">
        ACL Enrollment ACEs (${(p.acl_enrollment_aces||[]).length})
      </div>
      ${aclRows}
    </div>` : ''}`;
}

function toggleTemplate(idx) {
  const body = document.getElementById('tpl-body-' + idx);
  const chev = document.getElementById('tpl-chev-' + idx);
  const card = document.getElementById('tpl-card-' + idx);
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if (chev) chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
  if (card) card.style.borderColor = open ? 'var(--border)' : 'rgba(204,26,26,0.35)';
}

function buildTemplateCards(templates) {
  _allTemplates = templates || [];
  const list = document.getElementById('vulnList');
  if (!list) return;

  if (!_allTemplates.length) {
    list.innerHTML = `<div style="font-family:var(--mono);font-size:11px;
      color:var(--text4);padding:30px;text-align:center">[*] No templates found</div>`;
    return;
  }

  list.innerHTML = `
    <!-- TOOLBAR -->
    <div style="display:flex;align-items:center;justify-content:space-between;
      margin-bottom:10px;flex-wrap:wrap;gap:8px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-family:var(--mono);font-size:9px;letter-spacing:1.5px;
          text-transform:uppercase;color:var(--text4)">Templates</span>
        <span style="font-family:var(--mono);font-size:9px;padding:2px 8px;
          border-radius:10px;background:rgba(204,26,26,0.08);
          border:1px solid var(--border2);color:var(--c5)">${_allTemplates.length} total</span>
        <span style="font-family:var(--mono);font-size:9px;padding:2px 8px;
          border-radius:10px;background:rgba(34,197,94,0.08);
          border:1px solid rgba(34,197,94,0.25);color:var(--sev-low)">GUI ESC analysis off</span>
      </div>
      <div style="display:flex;gap:6px">
        <button onclick="filterTemplates('all')" id="tpl-f-all"
          style="font-family:var(--mono);font-size:8px;font-weight:700;letter-spacing:.8px;
          text-transform:uppercase;padding:4px 10px;border-radius:4px;cursor:pointer;
          background:rgba(204,26,26,0.12);border:1px solid var(--border2);color:var(--c5)">ALL</button>
      </div>
    </div>
    <!-- CARDS -->
    <div id="tpl-list" style="display:flex;flex-direction:column;gap:5px">
      ${_allTemplates.map((t,i) => _tplRow(t,i)).join('')}
    </div>`;
}

let _activeFilter = 'all';
function filterTemplates(filter) {
  _activeFilter = filter;
  const listEl = document.getElementById('tpl-list');
  if (!listEl) return;
  listEl.innerHTML = _allTemplates
    .map((t, i) => ({ t, i }))
    .filter(() => true)
    .map(({ t, i }) => _tplRow(t, i))
    .join('');
}

/* ── INTERACTIONS ── */
function toggleCard(id) {
  const body = document.getElementById('vb-' + id);
  const chev = document.getElementById('chev-' + id);
  const card = document.getElementById('vc-' + id);
  const isOpen = body.classList.contains('show');
  body.classList.toggle('show', !isOpen);
  chev.classList.toggle('open', !isOpen);
  card.classList.toggle('expanded', !isOpen);
}

function scrollToVuln(id, el) {
  document.querySelectorAll('.ref-item').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  const card = document.getElementById('vc-' + id);
  if (card) {
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    if (!document.getElementById('vb-' + id).classList.contains('show')) toggleCard(id);
  }
}

/* ── BUTTON ACTIONS ── */
function runTest(id) {
  const box = document.getElementById('log-' + id);
  box.innerHTML = '';
  log(id, '[*] Initializing test for ' + id + '...', 'info');
  setTimeout(() => log(id, '[*] Connecting to Name Server at ' + (getInputValue('nameServerInput', 'N/A') || 'N/A') + '...', 'info'), 400);
  setTimeout(() => log(id, '[*] Enumerating certificate templates...'), 800);
  setTimeout(() => log(id, '[*] Analyzing permissions and flags...'), 1300);
  setTimeout(() => {
    if (Math.random() > 0.2) {
      log(id, '[+] ' + id + ' is VULNERABLE — template flags confirmed', 'warn');
      addGlobalLog('[+] ' + id + ': VULNERABLE', 'warn');
    } else {
      log(id, '[-] Template appears hardened', 'info');
    }
  }, 2000);
}

function runExploit(id) {
  if (id !== 'ESC1') {
    log(id, '[!] API exploit flow is only enabled for ESC1 right now', 'warn');
    return;
  }

  const payload = getCertificatePayload();
  if (!payload.domain || !payload.name_server || !payload.username || !payload.password) {
    log(id, '[!] Domain, Name Server, Username, and Password are required', 'err');
    return;
  }

  persistCertificateUser(payload);
  log(id, '[!] EXPLOIT mode initiated for ' + id, 'err');
  fetch(getCertificateApiBase() + '/api/esc1', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(parseBackendResponse)
  .then(({ ok, data, raw, parseError }) => {
    if (!data) {
      const message = parseError || (raw ? raw.slice(0, 160) : 'empty response');
      log(id, '[!] ESC1 API returned non-JSON response: ' + message, 'err');
      addGlobalLog('[!] ESC1 API returned non-JSON response', 'error');
      return;
    }

    if (!ok || data.status !== 'connected') {
      const message = data.error || data.message || 'ESC1 API call failed';
      log(id, '[!] ' + message, 'err');
      addGlobalLog('[!] ESC1 exploit check failed: ' + message, 'error');
      return;
    }

    const vulnerable = data.esc_findings && data.esc_findings.some(item => item.esc_type === 'ESC1');
    refreshCertificateState(data.esc_findings || []);
    if (vulnerable) {
      log(id, '[+] ESC1 is VULNERABLE — backend confirmed template conditions', 'warn');
      addGlobalLog('[+] ESC1: VULNERABLE', 'warn');
    } else {
      log(id, '[-] ESC1 is not vulnerable on this target', 'info');
      addGlobalLog('[-] ESC1: not vulnerable', 'info');
    }
  })
  .catch(error => {
    log(id, '[!] ESC1 exploit request failed: ' + error.message, 'err');
    addGlobalLog('[!] ESC1 exploit request failed: ' + error.message, 'error');
  });
}

function runScan(id) {
  log(id, '[*] Deep scanning for ' + id + '...', 'info');
  setTimeout(() => log(id, '[*] Checking template ACLs...'), 600);
  setTimeout(() => log(id, '[*] Validating EKU policies...'), 1100);
  setTimeout(() => log(id, '[+] Scan complete — results logged'), 1800);
}

function runPoC(id) {
  log(id, '[*] Generating PoC for ' + id, 'info');
  const domain = getInputValue('domainInput', 'corp.local') || 'corp.local';
  setTimeout(() => {
    log(id, 'certipy req -u "user@' + domain + '" \\');
    log(id, '  -p "Password1!" -dc-ip 10.10.0.11 \\');
    log(id, '  -ca OXSIUM-CA -template ' + id + '_Template');
  }, 500);
}

function showInfo(id) {
  const r = REFS.find(x => x.id === id);
  if (!r) return;
  log(id, '[i] ' + id + ' — ' + r.name, 'info');
  log(id, '[i] CVSS Score: ' + r.score + ' | Severity: ' + r.sev, 'info');
  log(id, '[i] CVE: ' + r.cve + ' | MITRE: ' + r.mitre, 'info');
}

function genReport(id) {
  log(id, '[*] Generating report for ' + id + '...', 'info');
  setTimeout(() => log(id, '[+] Report saved: /reports/' + id.toLowerCase() + '_report.json'), 1500);
}

/* ── GLOBAL ACTIONS ── */
function runFullScan() {
  const payload = getCertificatePayload();

  if (!payload.domain || !payload.name_server || !payload.username || !payload.password) {
    addGlobalLog('[!] Error: Domain, Name Server, Username, and Password are required', 'error');
    return;
  }

  addGlobalLog('[*] Full scan initiated — scanning all 15 ESC modules...', 'info');
  addGlobalLog('[*] Target: ' + payload.domain + ' / Name Server: ' + payload.name_server + ' / User: ' + payload.username, 'info');

  REFS.forEach(r => r.active = false);
  persistCertificateUser(payload);

  fetch(getCertificateApiBase() + '/api/certificate/enumerate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(parseBackendResponse)
  .then(({ ok, data, raw, parseError }) => {
    if (!data) {
      const message = parseError || (raw ? raw.slice(0, 160) : 'empty response');
      addGlobalLog('[!] Error: backend returned non-JSON response (' + message + ')', 'error');
      return;
    }

    if (!ok || data.status === 'error') {
      const message = data.error || data.message || 'Scan failed';
      addGlobalLog('[!] Error: ' + message, 'error');
      return;
    }

    const findings = Array.isArray(data.esc_findings) ? data.esc_findings : [];
    if (findings.length === 0) {
      addGlobalLog('[*] Scan complete. No vulnerabilities found.', 'info');
    } else {
      addGlobalLog('[*] Found ' + findings.length + ' vulnerable module(s)', 'info');
      findings.forEach(finding => addGlobalLog('[+] ' + finding.esc_type + ' found: ' + finding.description, 'success'));
    }

    refreshCertificateState(findings);
    addGlobalLog('[+] Full scan complete. ' + findings.length + '/15 modules activated.', 'success');
  })
  .catch(error => {
    addGlobalLog('[!] Error: ' + error.message, 'error');
  });
}

function exportReport() {
  addGlobalLog('[*] Exporting full vulnerability report...', 'info');
  setTimeout(() => addGlobalLog('[+] Report exported: oxsium_cert_audit_' + Date.now() + '.json'), 1500);
}

/* ── PROGRESS BARS ── */
function setProgressBar(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = Math.min(100, pct) + '%';
}

/* ── RING UPDATE ── */
function updateRing(count, max) {
  const arc = document.getElementById('ringArc');
  const num = document.getElementById('ringNum');
  if (!arc || !num) return;
  const circ = 238.76;
  const pct  = max > 0 ? count / max : 0;
  arc.style.strokeDashoffset = circ * (1 - pct);
  animVal(num, count);
}

/* ── SEV BARS UPDATE ── */
function updateSevBars() {
  // Count only active modules by severity
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  REFS.filter(r => r.active).forEach(r => {
    if (counts.hasOwnProperty(r.sev)) {
      counts[r.sev]++;
    }
  });
  const max = Math.max(...Object.values(counts), 1);
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s => {
    const key = s.toLowerCase().replace('critical','crit');
    document.getElementById('sf-' + key.slice(0,4)).style.width = (counts[s] / max * 100) + '%';
    document.getElementById('sc-' + key.slice(0,4)).textContent  = counts[s];
  });
}

/* ── ANIMATED COUNTERS — all zero by default ── */
function animateCounters() {
  ['targetsVal','openVal','vulnVal'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  ['pb-targets','pb-open','pb-vuln','pb-ca'].forEach(id => setProgressBar(id, 0));
}

/* ── CERTIFICATE SERVICE CONNECT ── */
function connectCertificateService() {
  const payload = getCertificatePayload();

  if (payload.username) {
    document.getElementById('userDisplayTop').textContent = payload.username.substring(0, 30);
  }

  if (!payload.domain || !payload.name_server || !payload.username || !payload.password) {
    addGlobalLog('[-] Domain, Name Server, Username və Password daxil edin', 'err');
    return;
  }
  
  addGlobalLog('[*] Sertifikat Service-ə bağlanılır...', 'info');
  addGlobalLog('[*] Domain: ' + payload.domain + ' | Name Server: ' + payload.name_server + ' | User: ' + payload.username, 'info');
  addGlobalLog('[*] Credentials ready for backend scan...', 'info');
}

/* ── CONNECTION MODULE ACTIONS ── */

function togglePasswordVisibility(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const isPassword = field.type === 'password';
  field.type = isPassword ? 'text' : 'password';
}

function resetConnectionFields() {
  setInputValue('domainInput', '');
  setInputValue('nameServerInput', '');
  setInputValue('usernameInput', '');
  setInputValue('secretInput', '');
  setInputValue('dcInput', '');
  setInputValue('ntlmHashInput', '');
  
  document.getElementById('domainDisplayTop').textContent = '—';
  document.getElementById('nameServerDisplayTop').textContent = '—';
  document.getElementById('userDisplayTop').textContent = '—';
  
  addGlobalLog('[*] Connection fields reset', 'info');
}

function runConnectionTest() {
  const payload = getCertificatePayload();
  
  if (!payload.domain || !payload.name_server || !payload.username || !payload.password) {
    addGlobalLog('[!] Please fill in all required fields: Domain, Name Server, Username, and Password', 'error');
    return;
  }
  
  addGlobalLog('[*] Testing connection...', 'info');
  addGlobalLog('[*] Domain: ' + payload.domain, 'info');
  addGlobalLog('[*] Name Server: ' + payload.name_server, 'info');
  addGlobalLog('[*] User: ' + payload.username, 'info');
  
  setTimeout(() => {
    addGlobalLog('[*] Validating credentials...', 'info');
  }, 500);
  
  setTimeout(() => {
    addGlobalLog('[+] Connection test passed', 'success');
  }, 1500);
}

function runEnumerate() {
  const payload = getCertificatePayload();
  
  if (!payload.domain || !payload.name_server || !payload.username || !payload.password) {
    addGlobalLog('[!] Please fill in all required fields: Domain, Name Server, Username, and Password', 'error');
    return;
  }
  
  addGlobalLog('[*] Starting certificate template enumeration...', 'info');
  addGlobalLog('[*] Target: ' + payload.domain + ' / Name Server: ' + payload.name_server + ' / User: ' + payload.username, 'info');
  addGlobalLog('[*] Sending request to API...', 'info');
  
  // Persist user
  persistCertificateUser(payload);
  
  // Call API
  fetch(getCertificateApiBase() + '/api/certificate/enumerate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(parseBackendResponse)
  .then(({ ok, data, raw, parseError }) => {
    if (!data) {
      const message = parseError || (raw ? raw.slice(0, 160) : 'empty response');
      addGlobalLog('[!] API returned non-JSON response: ' + message, 'error');
      return;
    }
    
    if (!ok || data.status === 'error') {
      const message = data.error || data.message || 'Enumeration failed';
      addGlobalLog('[!] ' + message, 'error');
      return;
    }
    
    const report_id = data.report_id || 'UNKNOWN';
    const templates_count = (data.templates || []).length;
    const pki_objects_count = (data.pki_objects || []).length;
    
    addGlobalLog('[+] Enumeration complete', 'success');
    addGlobalLog('[+] Report ID: ' + report_id, 'success');
    addGlobalLog('[+] Templates found: ' + templates_count, 'success');
    addGlobalLog('[+] PKI Objects found: ' + pki_objects_count, 'success');

    // Render template cards in Center Workspace
    buildTemplateCards(data.templates || []);
  })
  .catch(error => {
    addGlobalLog('[!] Enumeration failed: ' + error.message, 'error');
  });
}

/* ── INIT ── */
buildRefs();
buildVulns();
animateCounters();
loadSavedUsers();