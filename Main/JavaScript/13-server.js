function selectServerProto(proto, btn) {
  document.querySelectorAll('.transport-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  const portMap = { https: '443', http: '80', tcp: '4444', smb: '445' };
  const portEl = document.getElementById('srv-port');
  if (portEl && portMap[proto]) portEl.value = portMap[proto];
}

function setSrvStatusBadge(state) {
  const badge = document.getElementById('srv-global-status');
  const dot   = document.getElementById('srv-status-dot');
  const text  = document.getElementById('srv-status-text');
  if (!badge || !dot || !text) return;

  badge.className = `srv-status-badge ${state}`;
  dot.className   = `srv-status-dot ${state}`;
  text.textContent = state.toUpperCase();
}

const BRIDGE_BASE = (location.protocol === 'http:' || location.protocol === 'https:')
  ? `${location.protocol}//${location.hostname}:${location.port || 8000}`
  : 'http://127.0.0.1:8000';

function runServerToggle(btn) {
  const label   = document.getElementById('srv-run-label');
  const log     = document.getElementById('srv-log-terminal');
  const running = btn.dataset.running === '1';

  const host  = document.getElementById('srv-host')?.value?.trim()  || '0.0.0.0';
  const port  = parseInt(document.getElementById('srv-port')?.value, 10) || 4444;
  const proto = document.querySelector('.transport-btn.selected')
                  ?.textContent?.trim().split('\n')[0]?.trim().toLowerCase() || 'https';

  if (!running) {
    setSrvStatusBadge('starting');
    btn.disabled = true;

    fetch(`${BRIDGE_BASE}/api/launch/start`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ host, port, transport: proto }),
    })
      .then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error || r.statusText); });
        return r.json();
      })
      .then(data => {
        if (data.ok) {
          btn.dataset.running   = '1';
          btn.style.background  = 'rgba(255,68,85,0.1)';
          btn.style.borderColor = 'rgba(255,68,85,0.4)';
          btn.style.color       = '#ff4455';
          btn.style.boxShadow   = '0 0 20px rgba(255,68,85,0.15)';
          if (label) label.textContent = 'Stop Server';
          setSrvStatusBadge('online');
          const msg = `[+] server_api.py started — PID ${data.pid} → ${proto.toUpperCase()} ${host}:${port}`;
          if (log) log.innerHTML += `<div class="log-line log-ok"><span class="log-msg">${msg}</span></div>`;
          updateSrvListeners(proto.toUpperCase(), host, port);
          if (typeof addLog === 'function') addLog(msg, 'ok');
        } else {
          throw new Error(data.error || 'unknown error');
        }
      })
      .catch(err => {
        setSrvStatusBadge('error');
        const msg = `[!] Launch failed: ${err.message}`;
        if (log) log.innerHTML += `<div class="log-line log-err"><span class="log-msg">${msg}</span></div>`;
        if (typeof addLog === 'function') addLog(msg, 'err');
      })
      .finally(() => {
        btn.disabled = false;
        if (log) log.scrollTop = log.scrollHeight;
      });

  } else {
    setSrvStatusBadge('starting');   
    btn.disabled = true;

    fetch(`${BRIDGE_BASE}/api/launch/stop`, { method: 'POST' })
      .catch(() => {})   
      .finally(() => {
        btn.dataset.running   = '0';
        btn.style.background  = 'rgba(0,212,100,0.08)';
        btn.style.borderColor = 'rgba(0,212,100,0.3)';
        btn.style.color       = 'var(--accent)';
        btn.style.boxShadow   = 'none';
        if (label) label.textContent = 'Run Server';
        setSrvStatusBadge('offline');
        if (log) {
          log.innerHTML += '<div class="log-line log-warn"><span class="log-msg">[-] server_api.py stopped.</span></div>';
          log.scrollTop = log.scrollHeight;
        }
        resetSrvListeners();
        btn.disabled = false;
        if (typeof addLog === 'function') addLog('server_api.py stopped', 'warn');
      });
  }
}

(function syncSrvStatusOnLoad() {
  fetch(`${BRIDGE_BASE}/api/launch/status`)
    .then(r => r.json())
    .then(data => {
      if (data.running) {
        setSrvStatusBadge('online');
        const btn = document.getElementById('srv-run-btn');
        if (btn) {
          btn.dataset.running   = '1';
          btn.style.background  = 'rgba(255,68,85,0.1)';
          btn.style.borderColor = 'rgba(255,68,85,0.4)';
          btn.style.color       = '#ff4455';
          btn.style.boxShadow   = '0 0 20px rgba(255,68,85,0.15)';
        }
        const label = document.getElementById('srv-run-label');
        if (label) label.textContent = 'Stop Server';
      }
    })
    .catch(() => {  });
})();

function updateSrvListeners(proto, host, port) {
  const list = document.getElementById('srv-listeners-list');
  if (!list) return;
  list.innerHTML = `
    <div class="srv-iface-item">
      <div class="srv-iface-icon"><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="4" stroke="currentColor" stroke-width="1.2"/></svg></div>
      <div class="srv-iface-info">
        <span class="srv-iface-name">${proto} Listener</span>
        <span class="srv-iface-desc">${host}:${port}</span>
      </div>
      <span class="srv-iface-badge active">ACTIVE</span>
    </div>`;
}

function resetSrvListeners() {
  const list = document.getElementById('srv-listeners-list');
  if (!list) return;
  list.innerHTML = `
    <div class="srv-iface-item">
      <div class="srv-iface-icon"><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="4" stroke="currentColor" stroke-width="1.2"/></svg></div>
      <div class="srv-iface-info">
        <span class="srv-iface-name">No listeners</span>
        <span class="srv-iface-desc">Start the server to activate</span>
      </div>
    </div>`;
}