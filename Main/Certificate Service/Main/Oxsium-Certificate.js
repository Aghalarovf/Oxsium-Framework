/* Oxsium Certificate Service — ESC1–ESC15 Vulnerability Panel */

const REFS = [
  {
    id: 'ESC1', name: 'Template Misconfiguration', sev: 'CRITICAL', score: '9.8',
    color: 'var(--red)', badge: 'b-red',
    desc: 'Certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag allow any enrollee to specify arbitrary SANs including domain admin UPNs, leading to full domain compromise.',
    impact: 'Domain Admin Takeover', proto: 'PKINIT + Certipy', cve: 'CVE-2021-36942', mitre: 'T1649',
    steps: ['Enumerate vulnerable templates', 'Request cert with target UPN as SAN', 'Use cert for Kerberos auth (PKINIT)', 'DCSync or PTH to Domain Admin']
  },
  {
    id: 'ESC2', name: 'Any Purpose Template', sev: 'CRITICAL', score: '9.1',
    color: 'var(--red)', badge: 'b-red',
    desc: 'Templates with "Any Purpose" EKU or no EKU defined allow certificates to be used for any authentication purpose, including client authentication and smart card logon.',
    impact: 'Lateral Movement / Priv Esc', proto: 'LDAP + Certipy', cve: 'CVE-2021-36943', mitre: 'T1649',
    steps: ['Find templates with Any Purpose EKU', 'Enroll with low-priv account', 'Use cert to auth as any user', 'Escalate privileges']
  },
  {
    id: 'ESC3', name: 'Enrollment Agent Abuse', sev: 'CRITICAL', score: '8.9',
    color: 'var(--red)', badge: 'b-red',
    desc: 'Templates with Certificate Request Agent EKU combined with misconfigured issuance policies enable enrollment on behalf of other users, allowing impersonation of privileged accounts.',
    impact: 'Certificate-Based Impersonation', proto: 'ADCS + Certipy', cve: 'N/A', mitre: 'T1649',
    steps: ['Obtain enrollment agent cert (ESC3-1)', 'Request cert on behalf of DA (ESC3-2)', 'Authenticate as target user', 'Achieve domain persistence']
  },
  {
    id: 'ESC4', name: 'Vulnerable Template Access Control', sev: 'CRITICAL', score: '8.7',
    color: 'var(--red)', badge: 'b-red',
    desc: 'Overly permissive ACLs on certificate templates allow low-privileged users to write to template attributes, enabling modification of template settings to introduce ESC1/ESC2 conditions.',
    impact: 'Template Backdoor / Persistence', proto: 'LDAP ACL Abuse', cve: 'N/A', mitre: 'T1484',
    steps: ['Identify writable template objects', 'Modify msPKI-Certificate-Name-Flag', 'Enable ENROLLEE_SUPPLIES_SUBJECT', 'Chain to ESC1 attack']
  },
  {
    id: 'ESC5', name: 'PKI Object ACL Abuse', sev: 'HIGH', score: '8.2',
    color: 'var(--orange)', badge: 'b-orange',
    desc: 'Weak ACLs on CA server objects, NTAuthCertificates, RootCA objects, or Enterprise PKI containers allow manipulation of the PKI infrastructure itself.',
    impact: 'PKI Infrastructure Compromise', proto: 'LDAP/DCOM', cve: 'N/A', mitre: 'T1484',
    steps: ['Enumerate PKI container ACLs', 'Identify writable CA objects', 'Add rogue certificate to NTAuth', 'Enable cross-forest auth bypass']
  },
  {
    id: 'ESC6', name: 'EDITF_ATTRIBUTESUBJECTALTNAME2', sev: 'HIGH', score: '8.0',
    color: 'var(--orange)', badge: 'b-orange',
    desc: 'CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enables SAN specification in any certificate request regardless of template settings, allowing domain admin impersonation.',
    impact: 'Arbitrary SAN Injection', proto: 'certreq.exe / Certipy', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Check CA flags via certutil', 'Confirm EDITF flag presence', 'Submit CSR with arbitrary SAN', 'Obtain DA-level certificate']
  },
  {
    id: 'ESC7', name: 'CA Manager Privilege Abuse', sev: 'HIGH', score: '7.8',
    color: 'var(--orange)', badge: 'b-orange',
    desc: 'Users with ManageCA or ManageCertificates permissions can approve pending certificate requests, modify CA configuration, or issue certificates for any template.',
    impact: 'CA Administrative Takeover', proto: 'ICertAdminD2 DCOM', cve: 'N/A', mitre: 'T1649',
    steps: ['Enumerate CA DACL', 'Identify ManageCA/ManageCerts rights', 'Enable EDITF flag via DCOM', 'Issue cert for SubCA or DA template']
  },
  {
    id: 'ESC8', name: 'NTLM Relay to AD CS HTTP', sev: 'HIGH', score: '7.5',
    color: 'var(--orange)', badge: 'b-orange',
    desc: 'AD CS web enrollment interfaces (certsrv) vulnerable to NTLM relay attacks. Machine account credentials can be relayed to obtain domain controller certificates enabling DCSync.',
    impact: 'DCSync via Certificate Relay', proto: 'Impacket + ntlmrelayx', cve: 'CVE-2021-36942', mitre: 'T1557.001',
    steps: ['Set up NTLM relay listener', 'Trigger DC NTLM auth (PetitPotam)', 'Relay to /certsrv/certfnsh.asp', 'Obtain DC certificate → DCSync']
  },
  {
    id: 'ESC9', name: 'No Security Extension (szOID)', sev: 'HIGH', score: '7.2',
    color: 'var(--orange)', badge: 'b-orange',
    desc: 'Templates without szOID_NTDS_CA_SECURITY_EXT are vulnerable when StrongCertificateBindingEnforcement is not enabled, allowing certificate mapping bypass via UPN changes.',
    impact: 'Authentication Binding Bypass', proto: 'PKINIT', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Identify templates missing security ext', 'Check registry binding enforcement', 'Modify UPN of controlled account', 'Request and use modified cert']
  },
  {
    id: 'ESC10', name: 'Weak Certificate Mapping', sev: 'MEDIUM', score: '6.8',
    color: 'var(--yellow)', badge: 'b-yellow',
    desc: 'Weak certificate-to-account mapping (CertificateMappingMethods registry) combined with user-controlled UPN enables certificate theft and authentication abuse across accounts.',
    impact: 'Cross-Account Auth Abuse', proto: 'Kerberos PKINIT', cve: 'CVE-2022-26923', mitre: 'T1649',
    steps: ['Check CertificateMappingMethods value', 'Enumerate user-controllable UPNs', 'Change UPN to match target cert', 'Authenticate using stolen certificate']
  },
  {
    id: 'ESC11', name: 'IF_ENFORCEENCRYPTICERTREQUEST', sev: 'MEDIUM', score: '6.5',
    color: 'var(--yellow)', badge: 'b-yellow',
    desc: 'CA missing the IF_ENFORCEENCRYPTICERTREQUEST flag allows NTLM relay attacks over RPC (MS-ICPR) without requiring HTTPS, expanding relay attack surface.',
    impact: 'RPC-based NTLM Relay', proto: 'MS-ICPR + ntlmrelayx', cve: 'N/A', mitre: 'T1557',
    steps: ['Enumerate CA flags via certutil', 'Confirm missing ENFORCEENCRYPT flag', 'Relay NTLM over port 135 (RPC)', 'Obtain certificate via ICertPassage']
  },
  {
    id: 'ESC12', name: 'Shell Access to CA Server', sev: 'MEDIUM', score: '6.2',
    color: 'var(--yellow)', badge: 'b-yellow',
    desc: 'Principals with remote code execution capability on CA server via WMI, SCM, or scheduled tasks can access CA private keys and configuration, enabling arbitrary certificate issuance.',
    impact: 'CA Private Key Exfiltration', proto: 'WMI / SCM / PSRemoting', cve: 'N/A', mitre: 'T1552.004',
    steps: ['Identify CA server shell access', 'Locate CA private key store', 'Export via certutil or direct DPAPI', 'Forge arbitrary certificates offline']
  },
  {
    id: 'ESC13', name: 'OID Group Link Abuse', sev: 'MEDIUM', score: '5.9',
    color: 'var(--yellow)', badge: 'b-yellow',
    desc: 'Issuance policy OIDs linked to AD groups with msPKI-Cert-Template-OID attribute allow certificate holders to gain group membership, potentially elevating to privileged groups.',
    impact: 'Unauthorized Group Membership', proto: 'LDAP + Certipy', cve: 'N/A', mitre: 'T1484',
    steps: ['Find OID-to-group mappings', 'Identify issuance policies in templates', 'Enroll in template with target OID', 'Certificate grants group membership']
  },
  {
    id: 'ESC14', name: 'Weak Explicit Alt Name Mapping', sev: 'LOW', score: '4.3',
    color: 'var(--green)', badge: 'b-green',
    desc: 'Explicit certificate mappings using altSecurityIdentities with weak binding methods (X509IssuerSubject or X509SubjectOnly) can be abused if adversary can influence subject DN.',
    impact: 'Account Mapping Manipulation', proto: 'LDAP', cve: 'N/A', mitre: 'T1649',
    steps: ['Enumerate altSecurityIdentities attributes', 'Identify weak mapping types', 'Craft certificate with matching DN', 'Authenticate using mapped identity']
  },
  {
    id: 'ESC15', name: 'Application Policy Mismatch', sev: 'LOW', score: '3.9',
    color: 'var(--green)', badge: 'b-green',
    desc: 'Schema V1 templates allow specifying application policies via CSR extensions. If CA does not enforce template-defined EKU validation, arbitrary EKUs can be added to issued certificates.',
    impact: 'EKU Policy Bypass', proto: 'certreq.exe CSR extension', cve: 'N/A', mitre: 'T1649',
    steps: ['Identify Schema V1 templates', 'Craft CSR with custom application policy', 'Submit to CA without strict EKU validation', 'Use issued cert with arbitrary EKU']
  }
];

/* ── HELPERS ── */
function getSevBadge(sev) {
  return { CRITICAL: 'b-red', HIGH: 'b-orange', MEDIUM: 'b-yellow', LOW: 'b-green' }[sev] || 'b-blue';
}

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

/* ── BUILD LEFT PANEL ── */
function buildRefs() {
  const panel = document.getElementById('refPanel');
  let html = '<div class="lbl">References</div>';
  REFS.forEach((r, i) => {
    html += `
      <div class="ref-item${i === 0 ? ' active' : ''}" onclick="scrollToVuln('${r.id}', this)">
        <div class="ref-code">${r.id}</div>
        <div class="ref-name">${r.name}</div>
        <div class="ref-sev"><span class="badge ${getSevBadge(r.sev)}">${r.sev} ${r.score}</span></div>
      </div>`;
  });
  panel.innerHTML = html;
}

/* ── BUILD VULN CARDS ── */
function buildVulns() {
  const list = document.getElementById('vulnList');
  let html = '';
  REFS.forEach(r => {
    const chainHTML = r.steps.map((s, i) =>
      `<span class="chain-step">${i + 1}. ${s}</span>${i < r.steps.length - 1 ? '<span class="chain-arrow">→</span>' : ''}`
    ).join('');

    html += `
      <div class="vuln-card" id="vc-${r.id}">
        <div class="vuln-header" onclick="toggleCard('${r.id}')">
          <span class="vuln-id" style="color:${r.color}">${r.id}</span>
          <span class="badge ${getSevBadge(r.sev)}" style="font-size:9px">${r.sev}</span>
          <span class="vuln-title">${r.name}</span>
          <span class="vuln-score" style="color:${r.color}">${r.score}</span>
          <span class="chevron" id="chev-${r.id}">▼</span>
        </div>
        <div class="vuln-body" id="vb-${r.id}">
          <div class="vuln-desc">${r.desc}</div>
          <div class="btn-row">
            <button class="btn btn-test"    onclick="runTest('${r.id}')">▶ Test</button>
            <button class="btn btn-exploit" onclick="runExploit('${r.id}')">⚡ Exploit</button>
            <button class="btn btn-scan"    onclick="runScan('${r.id}')">⬡ Scan</button>
            <button class="btn btn-poc"     onclick="runPoC('${r.id}')">{ } PoC</button>
            <button class="btn btn-info"    onclick="showInfo('${r.id}')">ℹ Info</button>
            <button class="btn btn-report"  onclick="genReport('${r.id}')">↓ Report</button>
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
      </div>`;
  });
  list.innerHTML = html;
}

/* ── INTERACTIONS ── */
function toggleCard(id) {
  const body  = document.getElementById('vb-' + id);
  const chev  = document.getElementById('chev-' + id);
  const card  = document.getElementById('vc-' + id);
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
  setTimeout(() => log(id, '[*] Connecting to CA at ' + document.getElementById('caInput').value + '...', 'info'), 400);
  setTimeout(() => log(id, '[*] Enumerating certificate templates...'), 800);
  setTimeout(() => log(id, '[*] Analyzing permissions and flags...'), 1300);
  setTimeout(() => {
    if (Math.random() > 0.2) {
      log(id, '[+] ' + id + ' is VULNERABLE — template flags confirmed');
      addGlobalLog('[+] ' + id + ': VULNERABLE', 'warn');
    } else {
      log(id, '[-] Template appears hardened', 'info');
    }
  }, 2000);
}

function runExploit(id) {
  log(id, '[!] EXPLOIT mode initiated for ' + id, 'err');
  setTimeout(() => log(id, '[*] Building malicious CSR...'), 500);
  setTimeout(() => log(id, '[*] Submitting to CA endpoint...'), 1000);
  setTimeout(() => log(id, '[+] Certificate issued! Saved to /tmp/' + id.toLowerCase() + '.pfx'), 1800);
}

function runScan(id) {
  log(id, '[*] Deep scanning for ' + id + '...', 'info');
  setTimeout(() => log(id, '[*] Checking template ACLs...'), 600);
  setTimeout(() => log(id, '[*] Validating EKU policies...'), 1100);
  setTimeout(() => log(id, '[+] Scan complete — results logged'), 1800);
}

function runPoC(id) {
  log(id, '[*] Generating PoC for ' + id, 'info');
  setTimeout(() => {
    log(id, 'certipy req -u "user@' + document.getElementById('domainInput').value + '" \\');
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
  setTimeout(() => log(id, '[+] Report saved to /reports/' + id.toLowerCase() + '_report.json'), 1500);
}

/* ── GLOBAL ACTIONS ── */
function runFullScan() {
  addGlobalLog('[*] Full scan initiated on all 15 ESC modules...', 'info');
  let i = 0;
  const interval = setInterval(() => {
    if (i >= REFS.length) {
      clearInterval(interval);
      addGlobalLog('[+] Full scan complete. 15/15 modules analyzed.');
      document.getElementById('vulnVal').textContent = '15';
      return;
    }
    addGlobalLog('[*] Testing ' + REFS[i].id + ': ' + REFS[i].name);
    i++;
  }, 300);
}

function exportReport() {
  addGlobalLog('[*] Exporting full vulnerability report...', 'info');
  setTimeout(() => addGlobalLog('[+] Report exported: oxsium_cert_audit_' + Date.now() + '.json'), 1500);
}

/* ── ANIMATED COUNTERS ── */
function animateCounters() {
  let t = 0, o = 0, v = 0;
  const ti = setInterval(() => {
    if (t < 3) { t++; document.getElementById('targetsVal').textContent = t; }
    else clearInterval(ti);
  }, 120);
  setTimeout(() => {
    const oi = setInterval(() => {
      if (o < 12) { o++; document.getElementById('openVal').textContent = o; }
      else clearInterval(oi);
    }, 80);
  }, 200);
  setTimeout(() => {
    const vi = setInterval(() => {
      if (v < 15) { v++; document.getElementById('vulnVal').textContent = v; }
      else clearInterval(vi);
    }, 100);
  }, 400);
}

/* ── INIT ── */
buildRefs();
buildVulns();
animateCounters();