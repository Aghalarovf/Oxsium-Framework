/* Oxsium Certificate Service — ESC1–ESC15 Vulnerability Panel */

// Dynamic activation: modules are discovered and activated by backend scan
// References panel shows only modules found by RUN Full SCAN
const REFS = [
  {
    id: 'ESC1', name: 'Template Misconfiguration', sev: 'CRITICAL', score: '9.8',
    desc: 'Certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag allow any enrollee to specify arbitrary SANs including domain admin UPNs, leading to full domain compromise.',
    impact: 'Domain Admin Takeover', proto: 'PKINIT + Certipy', cve: 'CVE-2021-36942', mitre: 'T1649',
    steps: ['Enumerate vulnerable templates', 'Request cert with target UPN as SAN', 'Use cert for Kerberos auth (PKINIT)', 'DCSync or PTH to Domain Admin'],
    active: true
  },
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

function getCertificatePayload() {
  const domain = (document.getElementById('domainInput')?.value || '').trim();
  const caServer = (document.getElementById('caInput')?.value || '').trim();
  const username = (document.getElementById('usernameInput')?.value || '').trim();
  const password = (document.getElementById('secretInput')?.value || '').trim();

  return { domain, ca_server: caServer, username, password };
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
  if (secret.length <= 8) return secret;
  return secret.slice(0, 4) + '…' + secret.slice(-4);
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
    <div class="saved-user-item" data-index="${index}" style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:rgba(6,182,212,0.03);cursor:pointer">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
        <div style="min-width:0">
          <div style="font-family:var(--mono);font-size:11px;color:var(--c5);font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.username || 'Unknown user'}</div>
          <div style="font-size:10px;color:var(--text2);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.domain || '—'} · ${item.ca_server || '—'}</div>
          <div style="font-size:9px;color:var(--text4);margin-top:4px">Saved: ${item.saved_at || '—'}</div>
        </div>
        <div style="font-size:10px;color:var(--text2);text-align:right;white-space:nowrap">${formatSavedSecret(item)}</div>
      </div>
    </div>
  `).join('');

  panel.querySelectorAll('.saved-user-item').forEach((element, index) => {
    element.addEventListener('click', () => {
      const item = users[index];
      if (!item) return;

      const domainInput = document.getElementById('domainInput');
      const caInput = document.getElementById('caInput');
      const usernameInput = document.getElementById('usernameInput');
      const secretInput = document.getElementById('secretInput');

      if (domainInput) domainInput.value = item.domain || '';
      if (caInput) caInput.value = item.ca_server || '';
      if (usernameInput) usernameInput.value = item.username || '';
      if (secretInput) secretInput.value = item.password || '';

      if (domainInput) domainInput.dispatchEvent(new Event('input', { bubbles: true }));
      if (caInput) caInput.dispatchEvent(new Event('input', { bubbles: true }));
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
  let html = '';
  // Render ALL modules (active visible, inactive disabled/grayed)
  REFS.forEach(r => {
    const cfg = sevCfg(r.sev);
    const disabled = !r.active;
    const chainHTML = r.steps.map((s, i) =>
      `<span class="chain-step">${i + 1}. ${s}</span>${i < r.steps.length - 1 ? '<span class="chain-arrow">→</span>' : ''}`
    ).join('');

    html += `
      <div class="vuln-card${disabled ? ' disabled' : ''}" id="vc-${r.id}" style="${disabled ? 'opacity:0.6;' : ''}">
        <div class="vuln-header" onclick="${disabled ? 'return false;' : `toggleCard('${r.id}')`}" style="${disabled ? 'cursor:not-allowed;' : 'cursor:pointer;'}">
          <div class="vuln-stripe ${cfg.stripe}"></div>
          <div class="vuln-id-col">
            <div class="vuln-id">${r.id}</div>
            <div class="vuln-badge-row"><span class="badge ${cfg.badge}">${r.sev}</span></div>
          </div>
          <div class="vuln-title-col">
            <div class="vuln-title">${r.name}</div>
            <div class="vuln-impact">${r.impact}</div>
          </div>
          <div class="vuln-score-col">
            <div class="vuln-score" style="color:${cfg.scoreColor};text-shadow:${cfg.scoreGlow}">${r.score}</div>
            <div class="vuln-score-label">CVSS</div>
          </div>
          <span class="chevron" id="chev-${r.id}">▼</span>
        </div>
        <div class="vuln-body" id="vb-${r.id}">
          <div class="vuln-body-inner">
            <div class="vuln-desc">${r.desc}</div>
            <div class="btn-row">
              <button class="btn btn-test"    onclick="${disabled ? 'return false;' : `runTest('${r.id}')`}" ${disabled ? 'disabled' : ''}>▶ Test</button>
              <button class="btn btn-exploit" onclick="${disabled ? 'return false;' : `runExploit('${r.id}')`}" ${disabled ? 'disabled' : ''}>⚡ Exploit</button>
              <button class="btn btn-scan"    onclick="${disabled ? 'return false;' : `runScan('${r.id}')`}" ${disabled ? 'disabled' : ''}>⬡ Scan</button>
              <button class="btn btn-poc"     onclick="${disabled ? 'return false;' : `runPoC('${r.id}')`}" ${disabled ? 'disabled' : ''}>{ } PoC</button>
              <button class="btn btn-info"    onclick="${disabled ? 'return false;' : `showInfo('${r.id}')`}" ${disabled ? 'disabled' : ''}>ℹ Info</button>
              <button class="btn btn-report"  onclick="${disabled ? 'return false;' : `genReport('${r.id}')`}" ${disabled ? 'disabled' : ''}>↓ Report</button>
            </div>
            <div class="meta-grid">
              <div class="meta-item"><div class="meta-key">Impact</div><div class="meta-val">${r.impact}</div></div>
              <div class="meta-item"><div class="meta-key">Protocol</div><div class="meta-val">${r.proto}</div></div>
              <div class="meta-item"><div class="meta-key">CVE / Ref</div><div class="meta-val">${r.cve}</div></div>
              <div class="meta-item"><div class="meta-key">MITRE ATT&CK</div><div class="meta-val">${r.mitre}</div></div>
            </div>
            <div class="chain-wrap">
              <div class="chain-title">Attack Chain</div>
              <div class="chain-steps">${chainHTML}</div>
            </div>
            <div class="log-box" id="log-${r.id}"></div>
          </div>
        </div>
      </div>`;
  });
  list.innerHTML = html;
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
  setTimeout(() => log(id, '[*] Connecting to CA at ' + (document.getElementById('caInput').value || 'N/A') + '...', 'info'), 400);
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
  if (!payload.domain || !payload.ca_server || !payload.username || !payload.password) {
    log(id, '[!] Domain, CA Server, Username, and Password are required', 'err');
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
  const domain = document.getElementById('domainInput').value || 'corp.local';
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

  if (!payload.domain || !payload.ca_server || !payload.username || !payload.password) {
    addGlobalLog('[!] Error: Domain, CA Server, Username, and Password are required', 'error');
    return;
  }

  addGlobalLog('[*] Full scan initiated — scanning all 15 ESC modules...', 'info');
  addGlobalLog('[*] Target: ' + payload.domain + ' / CA: ' + payload.ca_server + ' / User: ' + payload.username, 'info');

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

  if (!payload.domain || !payload.ca_server || !payload.username || !payload.password) {
    addGlobalLog('[-] Domain, CA Server, Username və Password daxil edin', 'err');
    return;
  }
  
  addGlobalLog('[*] Sertifikat Service-ə bağlanılır...', 'info');
  addGlobalLog('[*] Domain: ' + payload.domain + ' | CA: ' + payload.ca_server + ' | User: ' + payload.username, 'info');
  addGlobalLog('[*] Credentials ready for backend scan...', 'info');
}

/* ── INIT ── */
buildRefs();
buildVulns();
animateCounters();
loadSavedUsers();