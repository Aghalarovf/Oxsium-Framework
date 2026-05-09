/* ═══════════════════════════════════════════════════════════
   Oxsium Framework · Decision Engine · v2.1
   UI & Page Structure Module
   ─────────────────────────────────────────────────────────
   Əhatə edir:
     - Runtime state (GRAPH_DATA, ATTACK_PATHS, NODE_COLORS)
     - loadGraphData()  — C++ engine bridge
     - renderPathCards() — sol panel kartları
     - selectPath()     — sağ panel detalları
     - renderHopList()  — hop siyahısı
     - renderSparkline() — skor sparkline (native SVG)
     - initRootPrincipal() — root principal seçici
     - Nav tabs, ilkin render
   ─────────────────────────────────────────────────────────
   Bu modul D3-dən asılı DEYİL.
   D3 əməliyyatları: Oxsium-Decision-Graph.js
     Yüklənmə sırası (HTML-də):
         1. d3.js
         2. Oxsium-Decision.js       ← bu fayl
         3. Oxsium-Decision-Graph.js ← D3 modulu
═══════════════════════════════════════════════════════════ */

// ══════════════════════════════════════════════════════════════
//  Runtime state (C++ engine tərəfindən doldurulur)
// ══════════════════════════════════════════════════════════════
let GRAPH_DATA   = { nodes: [], links: [] };
let ATTACK_PATHS = [];

// ── Node rəng xəritəsi ───────────────────────────────────────
const NODE_COLORS = {
    user:     { fill: '#6366f1', glow: '#6366f1', stroke: '#818cf8' },
    group:    { fill: '#0ea5e9', glow: '#0ea5e9', stroke: '#38bdf8' },
    computer: { fill: '#10b981', glow: '#10b981', stroke: '#34d399' },
    domain:   { fill: '#f59e0b', glow: '#f59e0b', stroke: '#fbbf24' },
};

// ══════════════════════════════════════════════════════════════
//  PUBLIC API — C++ engine bridge tərəfindən çağırılır
//
//  graphData   : { nodes: [...], links: [...] }
//    node sahələri : { id, label, type, risk, depth, edges }
//    link sahələri : { source, target, rel, crit }
//
//  attackPaths : [ { id, sev, score, from, to, hops: [...] } ]
//    hop sahələri  : { name, type, nodeType }  — node hop
//                    { edge, edgeCrit }         — edge hop
// ══════════════════════════════════════════════════════════════
function loadGraphData(graphData, attackPaths) {
    GRAPH_DATA   = graphData   || { nodes: [], links: [] };
    ATTACK_PATHS = attackPaths || [];

    const maxHops = ATTACK_PATHS.reduce((m, p) =>
        Math.max(m, p.hops ? p.hops.filter(h => h.name).length - 1 : 0), 0);

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('node-count', GRAPH_DATA.nodes.length);
    setText('path-count', ATTACK_PATHS.length);
    setText('stat-nodes', GRAPH_DATA.nodes.length);
    setText('stat-hops',  maxHops);
    setText('depth-val',  maxHops || '—');

    renderPathCards();
    buildGraph();
}

// ══════════════════════════════════════════════════════════════
//  Sol panel — path kartları
// ══════════════════════════════════════════════════════════════
function renderPathCards() {
    const list = document.getElementById('path-list');
    list.innerHTML = '';

    if (ATTACK_PATHS.length === 0) {
        list.innerHTML = `
            <div style="padding:32px 14px;text-align:center;
                        font-size:9px;color:var(--text-dim);letter-spacing:1px;">
                AWAITING ENGINE DATA
            </div>`;
        return;
    }

    ATTACK_PATHS.forEach((path, i) => {
        const card = document.createElement('div');
        card.className = `path-card ${path.sev}`;
        card.style.animationDelay = `${i * 0.05}s`;
        card.dataset.id = path.id;

        const chainHTML = path.hops.map(h => {
            if (h.name) {
                return `<div class="chain-row">
                    <div class="chain-dot ${h.nodeType}"></div>
                    <span class="chain-name">${h.name}</span>
                    <span class="chain-type">${h.type}</span>
                </div>`;
            } else {
                const cls = h.edgeCrit ? 'red' : 'blue';
                return `<div class="chain-edge-row">
                    <div class="edge-line"></div>
                    <span class="edge-tag ${cls}">${h.edge}</span>
                </div>`;
            }
        }).join('');

        card.innerHTML = `
            <div class="path-card-top">
                <span class="path-id">${path.id}</span>
                <span class="sev-badge ${path.sev}">${path.sev}</span>
            </div>
            <div class="path-chain">${chainHTML}</div>
        `;

        card.addEventListener('click', () => selectPath(path, card));
        list.appendChild(card);
    });
}

// ══════════════════════════════════════════════════════════════
//  Sağ panel — path seçimi və detallar
// ══════════════════════════════════════════════════════════════
let selectedPath = null;

function selectPath(path, cardEl) {
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    cardEl.classList.add('active');
    selectedPath = path;

    // Başlıq
    document.getElementById('detail-name').textContent = path.id;
    document.getElementById('detail-sub').textContent  =
        `${path.from} → ${path.to} · ${path.hops.filter(h => h.name).length - 1} hops`;

    // Skor ringi
    const circ = 2 * Math.PI * 24;
    const pct  = path.score / 100;
    document.getElementById('score-ring').setAttribute(
        'stroke-dasharray', `${circ * pct} ${circ * (1 - pct)}`
    );
    document.getElementById('score-ring').setAttribute(
        'stroke', path.sev === 'crit' ? '#ef4444' : '#f97316'
    );
    document.getElementById('score-num').textContent = path.score;
    document.getElementById('score-num').style.color =
        path.sev === 'crit' ? 'var(--accent-red)' : 'var(--accent-orange)';

    // Meta məlumatlar
    const nodeCount = path.hops.filter(h => h.name).length;
    document.getElementById('meta-sev').textContent    = path.sev.toUpperCase();
    document.getElementById('meta-sev').className      = `score-meta-val ${path.sev === 'crit' ? 'red' : 'orange'}`;
    document.getElementById('meta-hops').textContent   = `${nodeCount - 1} hops / ${nodeCount} nodes`;
    document.getElementById('meta-start').textContent  = path.from;
    document.getElementById('meta-target').textContent = path.to;

    // Hop siyahısı və sparkline
    renderHopList(path);
    renderSparkline(path);

    // Graph node-larını vurgula (D3 modulundan)
    highlightPath(path);
}

// ── Hop siyahısı ─────────────────────────────────────────────
function renderHopList(path) {
    const list = document.getElementById('hop-list');
    list.innerHTML = '';
    let hopNum = 0;

    path.hops.forEach((h, i) => {
        if (h.name) {
            hopNum++;
            const div = document.createElement('div');
            div.className = 'hop-item';

            const nextEdge = path.hops[i + 1];
            const edgeHTML = nextEdge
                ? `<div class="hop-edge">
                    <span class="hop-edge-arrow">↓</span>
                    <span class="edge-tag ${nextEdge.edgeCrit ? 'red' : 'blue'}">${nextEdge.edge}</span>
                   </div>`
                : '';

            div.innerHTML = `
                <div class="hop-num">${String(hopNum).padStart(2, '0')}</div>
                <div class="hop-body">
                    <div class="hop-name">${h.name}</div>
                    <div class="hop-type">${h.type}</div>
                    ${edgeHTML}
                </div>
            `;
            list.appendChild(div);
        }
    });
}

// ── Sparkline (native SVG, D3 yox) ──────────────────────────
function renderSparkline(path) {
    const svg = document.getElementById('sparkline-svg');
    svg.innerHTML = '';

    if (ATTACK_PATHS.length < 2) return;

    const scores = ATTACK_PATHS.map(p => p.score);
    const max  = Math.max(...scores);
    const w = 280, h = 40;
    const step = w / (scores.length - 1);

    const points = scores.map((s, i) => [i * step, h - (s / max) * (h - 6) - 2]);

    // Sahə doldusu
    const area = `M${points[0][0]},${h} ` +
        points.map(p => `L${p[0]},${p[1]}`).join(' ') +
        ` L${points[points.length - 1][0]},${h} Z`;
    const areaEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    areaEl.setAttribute('d', area);
    areaEl.setAttribute('fill', 'rgba(56,189,248,0.06)');
    svg.appendChild(areaEl);

    // Xətt
    const line = `M` + points.map(p => `${p[0]},${p[1]}`).join(' L');
    const lineEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    lineEl.setAttribute('d', line);
    lineEl.setAttribute('fill', 'none');
    lineEl.setAttribute('stroke', 'rgba(56,189,248,0.6)');
    lineEl.setAttribute('stroke-width', '1');
    svg.appendChild(lineEl);

    // Seçilmiş nöqtə
    const idx = ATTACK_PATHS.indexOf(selectedPath);
    if (idx >= 0) {
        const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        dot.setAttribute('cx', points[idx][0]);
        dot.setAttribute('cy', points[idx][1]);
        dot.setAttribute('r', '3');
        dot.setAttribute('fill', selectedPath.sev === 'crit' ? '#ef4444' : '#f97316');
        svg.appendChild(dot);
    }
}

// ══════════════════════════════════════════════════════════════
//  Nav tabları (vizual)
// ══════════════════════════════════════════════════════════════
document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
    });
});

// ══════════════════════════════════════════════════════════════
//  İlkin boş render
//  Engine data göndərənə qədər sıfır göstər
// ══════════════════════════════════════════════════════════════
document.getElementById('node-count').textContent = '—';
document.getElementById('path-count').textContent = '—';
renderPathCards();   // "AWAITING ENGINE DATA" göstərir
// buildGraph() — Graph modulu yüklənəndə özü çağırılır

// Root principal seçimi yalnız saxlanır; qrafı `Analyze Paths` açacaq.
window.onRootPrincipalSelected = (principal) => {
    if (!principal) return;
    window.SELECTED_PRINCIPAL = principal;
    window.SELECTED_ROOT_PRINCIPAL_SID = principal.sid || '';
    sessionStorage.setItem('selectedRootPrincipal', principal.label || '');
    sessionStorage.setItem('selectedRootPrincipalType', principal.kind || '');
    sessionStorage.setItem('selectedRootPrincipalSID', principal.sid || '');
};

// ══════════════════════════════════════════════════════════════
//  ROOT PRINCIPAL SELECTOR
// ══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    if (window.RootPrincipal) return;
    initRootPrincipal();
});

function initRootPrincipal() {
    const btn         = document.getElementById('root-principal-trigger');
    const dropdown    = document.getElementById('root-principal-dropdown');
    const scrollArea  = document.getElementById('rp-scroll-area');
    const searchInput = document.getElementById('rp-search-input');

    if (!btn || !dropdown) return;

    // ── Tip müəyyənləşdirmə ──────────────────────────────────
    // Backend "users" / "computers" siyahısını ayırır.
    // Yedək: adın sonundakı "$" kompüter olduğunu göstərir.
    let _userSet     = new Set();
    let _computerSet = new Set();

    function principalType(name) {
        if (_computerSet.has(name)) return 'computer';
        if (_userSet.has(name))     return 'user';
        return name.endsWith('$')   ? 'computer' : 'user';
    }

    // ── Yükləmə ──────────────────────────────────────────────
    // Dropdown hər açıldığında fayllar yenidən oxunur
    async function loadPrincipals() {
        scrollArea.innerHTML = '<div class="rp-loading">Yüklənir...</div>';
        try {
            const runnerUrl = 'http://127.0.0.1:5200/run-root-js';
            const rresp = await fetch(`${runnerUrl}?_t=${Date.now()}`, { method: 'GET', cache: 'no-store' });
            if (!rresp.ok) throw new Error(`Runner HTTP ${rresp.status}`);
            const data = await rresp.json();
            _userSet     = new Set(data.users     || []);
            _computerSet = new Set(data.computers || []);
            renderPrincipals(data);
        } catch (rerr) {
            console.warn('[Root Principal] Runner əlçatmazdır:', rerr.message);
            scrollArea.innerHTML = '<div class="rp-loading rp-error">Runner işə düşmür — node .\\Helpers\\rp_runner.js işlədin</div>';
        }
    }

    // ── Render ───────────────────────────────────────────────
    function renderPrincipals(data) {
        const users     = data.users     || [];
        const computers = data.computers || [];
        const sources   = data.sources   || [];

        scrollArea.innerHTML = '';

        const totalCount = users.length + computers.length;

        if (totalCount === 0) {
            scrollArea.innerHTML =
                '<div class="rp-loading">Heç bir principal tapılmadı</div>';
            return;
        }

        const header = document.createElement('div');
        header.className = 'rp-section-header';
        header.innerHTML =
            `<span>Cəmi: <strong>${totalCount}</strong></span>` +
            `<span>👤 ${users.length} &nbsp; 💻 ${computers.length}</span>`;
        scrollArea.appendChild(header);

        if (sources.length > 0) {
            const sourcePanel = document.createElement('div');
            sourcePanel.className = 'rp-source-panel';
            sourcePanel.innerHTML = sources.map(source => `
                <div class="rp-source-card">
                    <div class="rp-source-top">
                        <span class="rp-source-label">${source.label}</span>
                        <span class="rp-source-count">${source.count}</span>
                    </div>
                    <div class="rp-source-file">${source.file}</div>
                    <div class="rp-source-meta">list: ${source.list_key} · attribute: ${source.field}</div>
                </div>
            `).join('');
            scrollArea.appendChild(sourcePanel);
        }

        // İstifadəçilər qrupu
        if (users.length > 0) {
            scrollArea.appendChild(_makeGroupLabel('👤 İstifadəçilər', users.length, 'user'));
            users.forEach(name => scrollArea.appendChild(_makeItem(name, 'user')));
        }

        // Kompüterlər qrupu
        if (computers.length > 0) {
            scrollArea.appendChild(_makeGroupLabel('💻 Kompüterlər', computers.length, 'computer'));
            computers.forEach(name => scrollArea.appendChild(_makeItem(name, 'computer')));
        }
    }

    function _makeGroupLabel(text, count, type) {
        const el = document.createElement('div');
        el.className    = 'rp-group-label';
        el.dataset.type = type;
        el.innerHTML    = `${text} <span class="rp-group-count">${count}</span>`;
        return el;
    }

    function _makeItem(name, type) {
        const item = document.createElement('div');
        item.className    = 'rp-item';
        item.dataset.name = name.toLowerCase();
        item.dataset.type = type;

        const icon = type === 'computer' ? '💻' : '👤';
        item.innerHTML = `
            <span class="rp-item-icon">${icon}</span>
            <span class="rp-item-text">${name}</span>
        `;

        item.addEventListener('click', () => selectPrincipal(name, type, item));
        return item;
    }

    // ── Seçim ────────────────────────────────────────────────
    function selectPrincipal(name, type, itemEl) {
        document.querySelectorAll('.rp-item.selected').forEach(el =>
            el.classList.remove('selected'));

        itemEl.classList.add('selected');

        const sid = window.RootPrincipal?.getSID?.(name) || '';
        const icon = type === 'computer' ? '💻' : '👤';
        btn.innerHTML = `<span class="rp-icon">${icon}</span><span>${name}</span>`;
        btn.classList.add('active');

        sessionStorage.setItem('selectedRootPrincipal', name);
        sessionStorage.setItem('selectedRootPrincipalType', type);
        sessionStorage.setItem('selectedRootPrincipalSID', sid);
        window.SELECTED_PRINCIPAL = { label: name, kind: type, sid };
        window.SELECTED_ROOT_PRINCIPAL_SID = sid;

        dropdown.classList.remove('open');
        console.log(`[Root Principal] Seçildi: ${name} (${type}) SID: ${sid || '(none)'}`);
    }

    // ── Toggle ────────────────────────────────────────────────
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = dropdown.classList.toggle('open');
        if (isOpen) {
            loadPrincipals();
            searchInput.value = '';
            setTimeout(() => searchInput.focus(), 80);
        }
    });

    // ── Axtarış ──────────────────────────────────────────────
    searchInput.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        scrollArea.querySelectorAll('.rp-item').forEach(item => {
            item.style.display = item.dataset.name.includes(q) ? 'flex' : 'none';
        });
        scrollArea.querySelectorAll('.rp-group-label').forEach(lbl => {
            const type    = lbl.dataset.type;
            const visible = [...scrollArea.querySelectorAll(`.rp-item[data-type="${type}"]`)]
                .some(el => el.style.display !== 'none');
            lbl.style.display = visible ? '' : 'none';
        });
    });

    // ── Kənar klik ilə bağla ─────────────────────────────────
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.root-principal-section')) {
            dropdown.classList.remove('open');
        }
    });

    // ── Escape ilə bağla ─────────────────────────────────────
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') dropdown.classList.remove('open');
    });
}