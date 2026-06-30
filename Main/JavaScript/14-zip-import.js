/* ═══════════════════════════════════════════════════
   14-zip-import.js
   ZIP Import: server-side only.
   Brauzerdə HEÇ bir parse/render edilmir (Client Side Render YOXDUR).
   ZIP faylı birbaşa serverə yüklənir (POST /api/upload-zip), backend
   onu Domain Object qovluğuna açır, sonra sqlite_engine.py ilə
   domain_data.db faylına çevirir (POST /api/build-sqlite-db).
   Cədvəllər/UI bu fayl tərəfindən doldurulmur — yalnız status
   mesajları (log + toast) göstərilir.
   ═══════════════════════════════════════════════════ */

/* ── Dropzone helpers ── */
function handleZipDrop(e) {
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.zip')) setZipFile(f);
  else showZipError();
}

function handleZipSelect(inp) {
  const f = inp.files[0];
  if (f && f.name.endsWith('.zip')) setZipFile(f);
  else { inp.value = ''; showZipError(); }
}

function setZipFile(f) {
  const info = document.getElementById('srv-zip-info');
  document.getElementById('srv-zip-name').textContent = f.name;
  document.getElementById('srv-zip-size').textContent = (f.size / 1024).toFixed(1) + ' KB';
  info.style.display = 'flex';
  document.getElementById('srv-zip-import-btn').disabled = false;
  document.getElementById('srv-zip-import-btn').style.opacity = '1';
}

function clearZip() {
  document.getElementById('srv-zip-info').style.display = 'none';
  document.getElementById('srv-zip-file').value = '';
  const btn = document.getElementById('srv-zip-import-btn');
  btn.disabled = true;
  btn.style.opacity = '0.45';
}

function showZipError() {
  if (typeof showToast === 'function') showToast('Only .zip files are accepted', 'error');
}

document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('srv-zip-import-btn').style.opacity = '0.45';
});

/* ── ZIP import state ── */
const ZIP_IMPORT = {
  active: false,
  files:  [],
};

/* ═══════════════════════════════════════════════════════════════════════════
   Upload ZIP to server → backend Domain Object qovluğuna açır
   (connection.py: POST /api/upload-zip)
   ═══════════════════════════════════════════════════════════════════════════ */
async function _uploadZipToServer(file, logLine) {
  const fd = new FormData();
  fd.append('file', file, file.name);

  logLine(`[*] Uploading ZIP to server (writing to Domain Object directory)...`, 'info');

  const resp = await fetch(`${API_BASE}/api/upload-zip`, {
    method: 'POST',
    body:   fd,
  });
  const data = await resp.json();

  if (!resp.ok || !data.success) {
    throw new Error(data.error || 'Server upload failed');
  }

  logLine(`[+] Written to Domain Object directory (${data.count} files) → ${data.destination}`, 'ok');
  addLog(`ZIP server-side write: ${data.count} files → ${data.destination}`, 'ok');

  return data;
}

/* ═══════════════════════════════════════════════════════════════════════════
   SQLite DB Build Trigger
   ZIP servere yazıldıqdan sonra /api/build-sqlite-db endpoint-ini çağırır
   ki, backend domain_data.db-ni qursun/yeniləsin.
   ═══════════════════════════════════════════════════════════════════════════ */
async function _triggerSqliteDbBuild(logLine) {
  logLine('[*] SQLite DB build triggered...', 'info');
  const resp = await fetch(`${API_BASE}/api/build-sqlite-db`, { method: 'POST' });
  const data = await resp.json();

  if (!resp.ok || !data.success) {
    throw new Error(data.error || 'DB build request failed');
  }

  logLine('[+] SQLite DB build started in background → ' + (data.output || ''), 'ok');
  addLog('sqlite_engine: DB build started', 'ok');

  return data;
}

/* ═══════════════════════════════════════════════════════════════════════════
   importZip() — server-side ZIP import.
   Client-side parse/render YOXDUR. Yalnız:
     1) ZIP-i serverə yükləyir → backend Domain Object qovluğuna açır
     2) sqlite_engine.py-ı tetikləyir → domain_data.db qurulur
   ═══════════════════════════════════════════════════════════════════════════ */
async function importZip() {
  const fileInput = document.getElementById('srv-zip-file');
  const file      = fileInput && fileInput.files[0];
  if (!file) {
    if (typeof showToast === 'function') showToast('No ZIP file selected', 'error');
    return;
  }

  const btn     = document.getElementById('srv-zip-import-btn');
  const log     = document.getElementById('srv-log-terminal');
  const logLine = (msg, cls) => {
    if (!log) return;
    log.innerHTML += `<div class="log-line log-${cls}"><span class="log-msg">${msg}</span></div>`;
    log.scrollTop  = log.scrollHeight;
  };

  /* ── Button → loading state ── */
  btn.disabled      = true;
  btn.style.opacity = '0.6';
  const origHTML    = btn.innerHTML;
  btn.innerHTML     = `
    <svg width="13" height="13" viewBox="0 0 13 13" fill="none"
         style="margin-right:7px;vertical-align:middle;animation:_zspin 1s linear infinite">
      <circle cx="6.5" cy="6.5" r="5" stroke="currentColor"
              stroke-width="1.4" stroke-dasharray="20 12"/>
    </svg>Importing...`;

  if (!document.getElementById('_zip-spin-style')) {
    const s = document.createElement('style');
    s.id        = '_zip-spin-style';
    s.textContent = '@keyframes _zspin{to{transform:rotate(360deg)}}';
    document.head.appendChild(s);
  }

  try {
    logLine(`[*] ${file.name} (${(file.size / 1024).toFixed(1)} KB) sending to server...`, 'info');

    /* 1. ZIP-i serverə yüklə → backend Domain Object qovluğuna açır */
    const uploadResult = await _uploadZipToServer(file, logLine);

    /* 2. sqlite_engine.py-ı tetiklə → domain_data.db qurulsun */
    await _triggerSqliteDbBuild(logLine);

    ZIP_IMPORT.active = true;
    ZIP_IMPORT.files  = uploadResult.extracted || [];

    /* 3. sqlite_reader.py (port 8800) hazır olana qədər gözlə */
    logLine('[*] Waiting for sqlite_reader (port 8800)...', 'info');
    const dbReady = await _waitForDbReaderReady(90000, 1500);

    if (dbReady) {
      /* 4. Offline rejimə keç — Connection state-i toxunulmaz qalır */
      state._zipOffline    = true;
      state.sessionStart   = state.sessionStart || Date.now();

      /* Topbar-da "OFFLINE (ZIP)" badge-i göstər */
      if (typeof setConnState === 'function') setConnState('offline-zip');

      /* 5. Bütün tab cache-lərini sıfırla və DB-dən yenidən yüklə */
      if (typeof refreshAllSectionsAfterConnect === 'function') {
        refreshAllSectionsAfterConnect();
      }

      logLine('[+] Offline mode active — all tabs loaded from domain_data.db', 'ok');
      addLog('ZIP import: DB ready, offline mode active, all sections loaded', 'ok');
    } else {
      logLine('[!] sqlite_reader (8800) did not become ready in time — tabs may be empty', 'warn');
      addLog('ZIP import: DB reader timeout — manual tab refresh may be needed', 'warn');
    }

    /* 6. Dropzone-u təmizlə */
    clearZip();

    logLine(`[+] ZIP import complete — ${uploadResult.count} files extracted`, 'ok');
    addLog(`ZIP import complete: ${uploadResult.count} files → ${uploadResult.destination}`, 'ok');

    if (typeof showToast === 'function')
      showToast(`ZIP Import: ${uploadResult.count} files extracted — Offline mode active`, 'success');

  } catch (err) {
    logLine(`[!] ZIP import error: ${err.message}`, 'err');
    addLog(`ZIP import error: ${err.message}`, 'warn');
    if (typeof showToast === 'function')
      showToast(`ZIP Import error: ${err.message}`, 'error');
  } finally {
    btn.disabled      = false;
    btn.style.opacity = '1';
    btn.innerHTML     = origHTML;
  }
}

/* ═══════════════════════════════════════════════════
   Reset ZIP import state when domain connects
   ═══════════════════════════════════════════════════ */
function zipOnDomainConnected() {
  ZIP_IMPORT.active    = false;
  ZIP_IMPORT.files     = [];
  state._zipOffline    = false;
  if (typeof setConnState === 'function') setConnState('connected');
}