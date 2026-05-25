/* ═══════════════════════════════════════════════════
   payload.js
   Oxsium Framework — Payload panel məntiqi
   (Agent + Beacon)
   Depends on: 00-globals.js (state, addLog, showToast)
   ═══════════════════════════════════════════════════ */

/* ── Internal payload state ── */
const payloadState = {
  activeTab:       'agent',
  agent: {
    fmt:          'exe',
    logoName:     '',
    paddingSize:  '',
    paddingUnit:  'KB',
    templates:    []
  },
  beacon: {
    type:      'https',
    fmt:       'exe',
    templates: []
  }
};

/* TAB SWITCHING */
function switchPayloadTab(tab) {
  payloadState.activeTab = tab;
  document.getElementById('payload-agent').style.display  = tab === 'agent'  ? 'block' : 'none';
  document.getElementById('payload-beacon').style.display = tab === 'beacon' ? 'block' : 'none';
  document.getElementById('ptab-agent').className  = 'payload-tab-btn agent'  + (tab === 'agent'  ? ' active' : '');
  document.getElementById('ptab-beacon').className = 'payload-tab-btn beacon' + (tab === 'beacon' ? ' active' : '');
  addLog(`Payload tab switched → ${tab.toUpperCase()}`, 'info');
}

/* FORMAT SELECTION */
function selectFmt(target, fmt, btn) {
  payloadState[target].fmt = fmt;
  const scope = target === 'agent' ? 'payload-agent' : 'payload-beacon';
  document.querySelectorAll(`#${scope} .fmt-btn.${target}`).forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
}

/* BEACON TYPE SELECTION */
function selectBeaconType(btype, btn) {
  payloadState.beacon.type = btype;
  document.querySelectorAll('.beacon-type-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  const smbSection = document.getElementById('smb-section');
  if (smbSection) smbSection.style.display = btype === 'smb' ? 'block' : 'none';
  const portMap = { https: '443', http: '80', dns: '53', smb: '445' };
  const portEl = document.getElementById('bc-port');
  if (portEl && (!portEl.value || Object.values(portMap).includes(portEl.value))) portEl.value = portMap[btype] || '';
}

/* RANGE ↔ INPUT SYNC */
function syncRange(rangeId, inputId, labelId, suffix) {
  const val = document.getElementById(rangeId).value;
  document.getElementById(inputId).value = val;
  document.getElementById(labelId).textContent = val + suffix;
}
function syncInput(inputId, rangeId, labelId, suffix) {
  const raw = parseInt(document.getElementById(inputId).value, 10);
  const range = document.getElementById(rangeId);
  if (!isNaN(raw)) {
    const clamped = Math.min(Math.max(raw, parseInt(range.min)), parseInt(range.max));
    range.value = clamped;
    document.getElementById(labelId).textContent = clamped + suffix;
  }
}

/* AES KEY GENERATION */
function genKey(inputId) {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById(inputId).value = hex;
  addLog('AES-256 key generated.', 'info');
}

/* Logo file picker handlers */
function browseLogo() {
  const fi = document.getElementById('ag-logo-file');
  if (fi) fi.click();
}
function handleLogoFileChange(e) {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  document.getElementById('ag-logo-path').value = f.name;
  payloadState.agent.logoName = f.name;
  const img = document.getElementById('ag-logo-img');
  if (img) {
    img.src = URL.createObjectURL(f);
    document.getElementById('ag-logo-preview').style.display = 'block';
  }
}

/* Padding unit selector */
function togglePaddingUnits() {
  const panel = document.getElementById('ag-padding-units');
  if (!panel) return;
  panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
}
function setPaddingUnit(u) {
  payloadState.agent.paddingUnit = u;
  const btn = document.getElementById('ag-padding-unit-btn');
  if (btn) btn.textContent = u;
  const panel = document.getElementById('ag-padding-units');
  if (panel) panel.style.display = 'none';
}

/* USER-AGENT PRESETS (Beacon) */
function applyUaPreset(preset) {
  const uaEl = document.getElementById('bc-ua');
  if (!uaEl || !preset) return;
  const presets = {
    chrome:  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    firefox: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    edge:    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
    curl:    'curl/8.7.1'
  };
  uaEl.value = presets[preset] || '';
  document.getElementById('bc-ua-preset').value = '';
}

/* PREVIEW COMMAND */
function previewPayloadCmd(target) {
  let cmd = '';
  if (target === 'agent') {
    const name     = document.getElementById('ag-name').value || 'oxsium-agent-001';
    const fmt      = payloadState.agent.fmt;
    const platform = document.getElementById('ag-platform').value || 'windows';
    cmd = `oxsium-builder agent \\\n  --name "${name}" \\\n  --platform ${platform} \\\n  --format ${fmt}`;
    if (document.getElementById('ag-sec-obf').checked)     cmd += ` \\\n  --obfuscate`;
    if (document.getElementById('ag-sec-vm').checked)      cmd += ` \\\n  --anti-vm`;
    if (document.getElementById('ag-sec-sandbox').checked) cmd += ` \\\n  --anti-sandbox`;
    if (document.getElementById('ag-sec-del').checked)     cmd += ` \\\n  --self-delete`;
    if (document.getElementById('ag-persist-svc').checked)  cmd += ` \\\n  --persist service`;
    if (document.getElementById('ag-persist-reg').checked)  cmd += ` \\\n  --persist registry`;
    if (document.getElementById('ag-persist-task').checked) cmd += ` \\\n  --persist task`;
    const key = document.getElementById('ag-aes-key').value;
    if (key) cmd += ` \\\n  --key "${key}"`;
    const out = document.getElementById('ag-output-path').value;
    if (out) cmd += ` \\\n  --output "${out}"`;
    const logo = document.getElementById('ag-logo-path').value;
    if (logo) cmd += ` \\\n  --logo "${logo}"`;
    const psize = document.getElementById('ag-padding-size').value;
    const punit = payloadState.agent.paddingUnit || 'KB';
    if (psize) cmd += ` \\\n  --padding ${psize}${punit}`;
  } else {
    const c2url     = document.getElementById('bc-c2url').value     || 'https://oxsium.local';
    const port      = document.getElementById('bc-port').value      || '22';
    const sleep     = document.getElementById('bc-sleep').value     || '30';
    const jmin      = document.getElementById('bc-jitter-min').value || '10';
    const jmax      = document.getElementById('bc-jitter-max').value || '50';
    const maxretry  = document.getElementById('bc-maxretry').value  || '5';
    const retdelay  = document.getElementById('bc-retrydelay').value || '60';
    const btype     = payloadState.beacon.type;
    const fmt       = payloadState.beacon.fmt;
    cmd = `oxsium-builder beacon \\\n  --type ${btype} \\\n  --format ${fmt} \\\n  --c2 "${c2url}:${port}" \\\n  --sleep ${sleep} \\\n  --jitter ${jmin}-${jmax} \\\n  --max-retry ${maxretry} \\\n  --retry-delay ${retdelay}`;
    if (btype === 'smb') {
      const pipe   = document.getElementById('bc-pipe').value;
      const target = document.getElementById('bc-smb-target').value;
      if (pipe)   cmd += ` \\\n  --pipe "${pipe}"`;
      if (target) cmd += ` \\\n  --smb-target "${target}"`;
    }
    const ua = document.getElementById('bc-ua').value;
    if (ua) cmd += ` \\\n  --user-agent "${ua}"`;
    if (document.getElementById('bc-mimic').checked)  cmd += ` \\\n  --mimic-browser`;
    if (document.getElementById('bc-enc').checked)    cmd += ` \\\n  --encrypt`;
    if (document.getElementById('bc-rsleep').checked) cmd += ` \\\n  --random-sleep`;
    if (document.getElementById('bc-dnsfb').checked)  cmd += ` \\\n  --dns-fallback`;
    if (document.getElementById('bc-antivm').checked) cmd += ` \\\n  --anti-vm`;
    if (document.getElementById('bc-antisb').checked) cmd += ` \\\n  --anti-sandbox`;
    const key = document.getElementById('bc-aes-key').value;
    if (key) cmd += ` \\\n  --key "${key}"`;
    const out = document.getElementById('bc-output-path').value;
    if (out) cmd += ` \\\n  --output "${out}"`;
  }
  addLog('─── Payload Preview ───', 'info');
  cmd.split('\n').forEach(line => addLog(line.trim(), 'raw'));
  addLog('───────────────────────', 'info');
  showToast('Command preview written to log terminal.', 'info');
}

/* GENERATE PAYLOAD */
function generatePayload(target) {
  const label = target === 'agent' ? 'Agent' : 'Beacon';
  if (target === 'beacon') {
    const urlEl = document.getElementById('bc-c2url');
    if (!urlEl || !urlEl.value.trim()) {
      showToast(`${label}: Callback URL is required.`, 'error');
      urlEl && urlEl.classList.add('error');
      return;
    }
    urlEl && urlEl.classList.remove('error');
  }
  addLog(`[PAYLOAD] Generating ${label} — format: ${payloadState[target].fmt.toUpperCase()}`, 'info');
  showToast(`${label} payload generation started…`, 'ok');
}

/* CONFIG COLLECTORS */
function collectAgentConfig() {
  return {
    name:      document.getElementById('ag-name').value,
    platform:  document.getElementById('ag-platform').value,
    fmt:       payloadState.agent.fmt,
    logo:      document.getElementById('ag-logo-path').value,
    paddingSize: document.getElementById('ag-padding-size').value,
    paddingUnit: payloadState.agent.paddingUnit,
    key:       document.getElementById('ag-aes-key').value,
    output:    document.getElementById('ag-output-path').value,
    persist: {
      service:  document.getElementById('ag-persist-svc').checked,
      registry: document.getElementById('ag-persist-reg').checked,
      task:     document.getElementById('ag-persist-task').checked,
      hook:     document.getElementById('ag-persist-hook').checked
    },
    security: {
      obfuscate:  document.getElementById('ag-sec-obf').checked,
      antiVm:     document.getElementById('ag-sec-vm').checked,
      antiSandbox:document.getElementById('ag-sec-sandbox').checked,
      selfDelete: document.getElementById('ag-sec-del').checked
    }
  };
}

function collectBeaconConfig() {
  return {
    type:      payloadState.beacon.type,
    fmt:       payloadState.beacon.fmt,
    c2url:     document.getElementById('bc-c2url').value,
    port:      document.getElementById('bc-port').value,
    sleep:     document.getElementById('bc-sleep').value,
    jitterMin: document.getElementById('bc-jitter-min').value,
    jitterMax: document.getElementById('bc-jitter-max').value,
    maxRetry:  document.getElementById('bc-maxretry').value,
    retryDelay:document.getElementById('bc-retrydelay').value,
    pipe:      document.getElementById('bc-pipe').value,
    smbTarget: document.getElementById('bc-smb-target').value,
    ua:        document.getElementById('bc-ua').value,
    key:       document.getElementById('bc-aes-key').value,
    output:    document.getElementById('bc-output-path').value,
    stealth: {
      mimic:      document.getElementById('bc-mimic').checked,
      encrypt:    document.getElementById('bc-enc').checked,
      randomSleep:document.getElementById('bc-rsleep').checked,
      dnsFallback:document.getElementById('bc-dnsfb').checked,
      antiVm:     document.getElementById('bc-antivm').checked,
      antiSandbox:document.getElementById('bc-antisb').checked
    }
  };
}

/* TEMPLATE SAVE / LOAD */
function savePayloadTemplate(target) {
  const cfg  = target === 'agent' ? collectAgentConfig() : collectBeaconConfig();
  const name = cfg.name || cfg.c2url || `template-${Date.now()}`;
  const key  = `oxsium_${target}_tpl_${Date.now()}`;
  const data = { name, cfg, saved: new Date().toISOString() };
  try {
    const existing = JSON.parse(localStorage.getItem(`oxsium_${target}_tpls`) || '[]');
    existing.push({ key, ...data });
    localStorage.setItem(`oxsium_${target}_tpls`, JSON.stringify(existing));
    addLog(`[PAYLOAD] Template saved: "${name}"`, 'ok');
    showToast(`Template "${name}" saved.`, 'ok');
    renderSavedPayloads(target);
  } catch(e) {
    showToast('Failed to save template.', 'error');
  }
}

function renderSavedPayloads(target) {
  const scrollEl = document.getElementById(`saved-${target}-scroll`);
  if (!scrollEl) return;
  let items = [];
  try { items = JSON.parse(localStorage.getItem(`oxsium_${target}_tpls`) || '[]'); } catch(e) { items = []; }
  if (!items.length) { scrollEl.innerHTML = `<div class="saved-user-empty">No saved ${target} templates yet.</div>`; return; }
  scrollEl.innerHTML = items.map((item, idx) => `
    <div class="saved-user-item" onclick="loadPayloadTemplate('${target}',${idx})">
      <div class="saved-user-top">
        <span class="saved-user-name">${escHtml(item.name)}</span>
        <span class="saved-user-proto">${target.toUpperCase()}</span>
      </div>
      <div class="saved-user-meta">${escHtml(item.cfg.url || item.cfg.c2url || item.cfg.output || '—')} | ${(item.cfg.fmt || '').toUpperCase()} | ${new Date(item.saved).toLocaleDateString()}</div>
    </div>
  `).join('');
}

function loadPayloadTemplate(target, idx) {
  let items = [];
  try { items = JSON.parse(localStorage.getItem(`oxsium_${target}_tpls`) || '[]'); } catch(e) { return; }
  const item = items[idx]; if (!item) return; const cfg = item.cfg;
  if (target === 'agent') {
    setVal('ag-name',        cfg.name);
    setVal('ag-aes-key',     cfg.key);
    setVal('ag-output-path', cfg.output);
    if (cfg.platform) {
      const allowed = ['windows', 'windows32'];
      document.getElementById('ag-platform').value = allowed.includes(cfg.platform) ? cfg.platform : 'windows';
    }
    if (cfg.logo) { setVal('ag-logo-path', cfg.logo); payloadState.agent.logoName = cfg.logo; }
    if (cfg.paddingSize) { setVal('ag-padding-size', cfg.paddingSize); setPaddingUnit(cfg.paddingUnit || 'KB'); }
    if (cfg.persist) {
      setChk('ag-persist-svc',  cfg.persist.service);
      setChk('ag-persist-reg',  cfg.persist.registry);
      setChk('ag-persist-task', cfg.persist.task);
      setChk('ag-persist-hook', cfg.persist.hook);
    }
    if (cfg.security) {
      setChk('ag-sec-obf',     cfg.security.obfuscate);
      setChk('ag-sec-vm',      cfg.security.antiVm);
      setChk('ag-sec-sandbox', cfg.security.antiSandbox);
      setChk('ag-sec-del',     cfg.security.selfDelete);
    }
  } else {
    setVal('bc-c2url',       cfg.c2url);
    setVal('bc-port',        cfg.port);
    setVal('bc-sleep',       cfg.sleep);
    setVal('bc-jitter-min',  cfg.jitterMin);
    setVal('bc-jitter-max',  cfg.jitterMax);
    setVal('bc-maxretry',    cfg.maxRetry);
    setVal('bc-retrydelay',  cfg.retryDelay);
    setVal('bc-pipe',        cfg.pipe);
    setVal('bc-smb-target',  cfg.smbTarget);
    setVal('bc-ua',          cfg.ua);
    setVal('bc-aes-key',     cfg.key);
    setVal('bc-output-path', cfg.output);
    if (cfg.stealth) {
      setChk('bc-mimic',  cfg.stealth.mimic);
      setChk('bc-enc',    cfg.stealth.encrypt);
      setChk('bc-rsleep', cfg.stealth.randomSleep);
      setChk('bc-dnsfb',  cfg.stealth.dnsFallback);
      setChk('bc-antivm', cfg.stealth.antiVm);
      setChk('bc-antisb', cfg.stealth.antiSandbox);
    }
  }
  addLog(`[PAYLOAD] Template loaded: "${item.name}"`, 'ok');
  showToast(`Template "${item.name}" loaded.`, 'ok');
}

/* HELPERS */
function setVal(id, val) { const el = document.getElementById(id); if (el && val !== undefined && val !== null) el.value = val; }
function setChk(id, val) { const el = document.getElementById(id); if (el) el.checked = !!val; }
function escHtml(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* Auto-init on DOM ready */
document.addEventListener('DOMContentLoaded', () => {
  const bcPort = document.getElementById('bc-port');
  if (bcPort && !bcPort.value) bcPort.value = '443';
  // padding default
  const padBtn = document.getElementById('ag-padding-unit-btn');
  if (padBtn) padBtn.textContent = payloadState.agent.paddingUnit || 'KB';
});
