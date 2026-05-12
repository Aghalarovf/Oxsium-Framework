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

    const nodeEdgeCounts = new Map();
    (GRAPH_DATA.links || []).forEach(link => {
        const sourceId = String(link.source?.id || link.source || '').toLowerCase();
        const targetId = String(link.target?.id || link.target || '').toLowerCase();
        if (sourceId) nodeEdgeCounts.set(sourceId, (nodeEdgeCounts.get(sourceId) || 0) + 1);
        if (targetId) nodeEdgeCounts.set(targetId, (nodeEdgeCounts.get(targetId) || 0) + 1);
    });
    (GRAPH_DATA.nodes || []).forEach(node => {
        const key = String(node.id || '').toLowerCase();
        node.edgeDegree = nodeEdgeCounts.get(key) || 0;
    });

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

    restorePathFocusIfNeeded();
}

// ══════════════════════════════════════════════════════════════
//  Sağ panel — path seçimi və detallar
// ══════════════════════════════════════════════════════════════
let selectedPath = null;
let currentPathFocusId = '';

function setPathFocus(pathId) {
    currentPathFocusId = pathId || '';
    const cards = document.querySelectorAll('.path-card');
    cards.forEach(card => {
        const isMatch = card.dataset.id === pathId;
        card.classList.toggle('dimmed', !!pathId && !isMatch);
        card.classList.toggle('active', isMatch);
        if (pathId && !isMatch) {
            card.style.setProperty('opacity', '0.14', 'important');
            card.style.setProperty('filter', 'grayscale(1) brightness(0.52) saturate(0)', 'important');
            card.style.setProperty('background', 'rgba(0,0,0,0.16)', 'important');
        } else {
            card.style.removeProperty('opacity');
            card.style.removeProperty('filter');
            card.style.removeProperty('background');
        }
    });
}

function clearPathFocus() {
    currentPathFocusId = '';
    document.querySelectorAll('.path-card').forEach(card => {
        card.classList.remove('dimmed');
        card.style.removeProperty('opacity');
        card.style.removeProperty('filter');
        card.style.removeProperty('background');
    });
}

function restorePathFocusIfNeeded() {
    if (currentPathFocusId) {
        setPathFocus(currentPathFocusId);
    }
}

function selectPath(path, cardEl) {
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    cardEl.classList.add('active');
    selectedPath = path;

    // Başlıq
                card.style.removeProperty('opacity');
                card.style.removeProperty('filter');
                card.style.removeProperty('background');
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
    renderRiskDistributionList(buildRiskDistributionEntriesFromPath(path), 'Path edges');
    renderPathExplanation({ kind: 'path', path });

    // Graph node-larını vurgula (D3 modulundan)
    highlightPath(path);
    setPathFocus(path.id);
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

function renderPathExplanation(context) {
    const chip = document.getElementById('detail-explain-chip');
    const body = document.getElementById('detail-explain-body');
    if (!chip || !body) return;

    const esc = (value) => String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

    const setBody = (parts) => {
        body.innerHTML = parts.filter(Boolean).map(text => `<p>${text}</p>`).join('');
    };

    if (!context) {
        chip.textContent = 'Path';
        body.innerHTML = '<p class="detail-muted">Select a node or edge in the graph to see a detailed explanation here.</p>';
        return;
    }

    if (context.kind === 'node') {
        const node = context.node || {};
        const path = context.path || null;
        const edgeNames = Array.isArray(context.edgeNames) ? context.edgeNames.filter(Boolean) : [];
        chip.textContent = 'Node';
        document.getElementById('detail-name').textContent = node.label || 'Selected Node';
        document.getElementById('detail-sub').textContent = `${String(node.type || 'object').toUpperCase()} · Depth ${node.depth != null ? node.depth : '—'} · ${node.edges != null ? node.edges : '—'} edges`;

        const edgeLine = edgeNames.length
            ? `Connected edge${edgeNames.length > 1 ? 's' : ''}: ${edgeNames.map(name => `<span class="detail-edge-tag">${esc(name)}</span>`).join(' ')}`
            : 'No explicit edge name was matched for this node in the current path.';

        const pathLine = path
            ? `It is part of path <strong>${esc(path.id)}</strong> from <strong>${esc(path.from)}</strong> to <strong>${esc(path.to)}</strong>.`
            : 'It is not currently attached to a selected path, but it remains the active focus node in the graph.';

        setBody([
            `The selected node is <strong>${esc(node.label || 'Unknown')}</strong> and it is classified as <strong>${esc(String(node.type || 'object').toUpperCase())}</strong>.`,
            `It sits at depth <strong>${esc(node.depth != null ? node.depth : '—')}</strong> and currently shows <strong>${esc(node.edges != null ? node.edges : '—')}</strong> connected edges in the graph.`,
            edgeLine,
            pathLine,
            'Use this view to follow how the node participates in the current attack chain and which neighboring relationships make it relevant.'
        ]);
        return;
    }

    if (context.kind === 'edge') {
        const edge = context.edge || {};
        const path = context.path || null;
        const match = context.match || null;
        chip.textContent = 'Edge';
        document.getElementById('detail-name').textContent = `${edge.source || 'Unknown'} → ${edge.target || 'Unknown'}`;
        document.getElementById('detail-sub').innerHTML = `${esc(edge.rel || 'RELATION')} · edge focus`;

        const chainLine = match
            ? `This edge is drawn because the selected route contains <strong>${esc(match.source || edge.source || 'Unknown')}</strong> → <span class="detail-edge-tag">${esc(match.rel || edge.rel || 'RELATION')}</span> → <strong>${esc(match.target || edge.target || 'Unknown')}</strong>.`
            : `This edge is drawn to represent the direct relationship from <strong>${esc(edge.source || 'Unknown')}</strong> to <strong>${esc(edge.target || 'Unknown')}</strong>.`;

        const reasonLine = match
            ? `It appears in <strong>${esc(path?.id || 'the selected path')}</strong> because the path data records this step as a real transition between principals, not just a visual connector.`
            : 'It remains visible as a direct graph relationship even when no exact path chain match is available.';

        setBody([
            `The selected edge connects <strong>${esc(edge.source || 'Unknown')}</strong> to <strong>${esc(edge.target || 'Unknown')}</strong> and carries the relation <span class="detail-edge-tag">${esc(edge.rel || 'RELATION')}</span>.`,
            chainLine,
            reasonLine,
            'Use edge inspection to understand exactly which principal reaches which target and why that transition is part of the attack route.'
        ]);
        return;
    }

    if (context.kind === 'path') {
        const path = context.path || {};
        chip.textContent = 'Path';
        document.getElementById('detail-name').textContent = path.id || 'Selected Path';
        document.getElementById('detail-sub').textContent = `${path.from || '—'} → ${path.to || '—'} · ${path.hops ? path.hops.filter(h => h.name).length - 1 : '—'} hops`;
        setBody([
            `The selected route is <strong>${esc(path.id || 'Unknown')}</strong>.`,
            `It starts at <strong>${esc(path.from || '—')}</strong> and ends at <strong>${esc(path.to || '—')}</strong>, with the full hop chain shown below.`,
            'Click any node or edge in the graph to switch this panel into a more focused explanation view.'
        ]);
    }
}

window.updatePathDetailContext = renderPathExplanation;

function buildRiskDistributionEntriesFromPath(path) {
    if (!path || !Array.isArray(path.hops)) return [];
    const entries = [];

    for (let i = 0; i < path.hops.length; i++) {
        const hop = path.hops[i];
        if (!hop || !hop.edge) continue;
        const prevNode = i > 0 ? path.hops[i - 1] : null;
        const nextNode = i + 1 < path.hops.length ? path.hops[i + 1] : null;
        entries.push({
            name: hop.edge,
            source: prevNode?.name || '',
            target: nextNode?.name || '',
            meta: prevNode?.name && nextNode?.name
                ? `${prevNode.name} → ${nextNode.name}`
                : 'Path edge'
        });
    }

    return entries;
}

function normalizeRiskDistributionEntry(entry) {
    if (typeof entry === 'string') {
        return { name: entry, meta: '', step: null, nodeName: '' };
    }
    return {
        name: entry?.name || entry?.rel || entry?.edge || 'Edge',
        source: entry?.source || '',
        target: entry?.target || '',
        meta: entry?.meta || entry?.note || '',
        step: entry?.step ?? null,
        nodeName: entry?.nodeName || ''
    };
}

function renderRiskDistributionList(entries, subtitle) {
    const list = document.getElementById('risk-distribution-list');
    const sub = document.getElementById('risk-distribution-sub');
    if (!list) return;

    if (sub && subtitle) {
        sub.textContent = subtitle;
    }

    const items = Array.isArray(entries) ? entries.map(normalizeRiskDistributionEntry).filter(item => item.name) : [];

    if (items.length === 0) {
        list.innerHTML = '<div class="risk-distribution-empty">No edge names available for the current selection</div>';
        return;
    }

    list.innerHTML = items.map(item => {
        const chain = item.meta || (item.source || item.target ? `${item.source || 'Unknown'} → ${item.target || 'Unknown'}` : '');
        const stepLabel = item.step != null ? `Step ${item.step}` : '';
        const nodeLabel = item.nodeName ? `Target node: ${item.nodeName}` : '';
        return `
        <div class="risk-distribution-item">
            <div class="risk-distribution-item-top">
                <div class="risk-distribution-item-step">${escapeHtml(stepLabel)}</div>
                <div class="risk-distribution-item-name">${escapeHtml(item.name)}</div>
            </div>
            <div class="risk-distribution-item-meta">${escapeHtml(chain)}</div>
            ${nodeLabel ? `<div class="risk-distribution-item-node">${escapeHtml(nodeLabel)}</div>` : ''}
        </div>`;
    }).join('');
}

function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

window.updateRiskDistributionList = renderRiskDistributionList;

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
const _nodeCountEl = document.getElementById('node-count') || document.getElementById('stat-nodes');
const _pathCountEl = document.getElementById('path-count') || document.getElementById('stat-hops');
if (_nodeCountEl) _nodeCountEl.textContent = '—';
if (_pathCountEl) _pathCountEl.textContent = '—';
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

// Apply selected root principal to currently loaded GRAPH_DATA (if present)
function applyRootPrincipalToGraph(principal) {
    if (!principal || !GRAPH_DATA || !GRAPH_DATA.nodes) return;
    const label = String(principal.label || '').toLowerCase();
    const kind  = principal.kind || '';

    // Clear existing root flags
    GRAPH_DATA.nodes.forEach(n => { n.root = false; });

    // Try to find matching node by label and/or type
    let matched = GRAPH_DATA.nodes.find(n => String(n.label || '').toLowerCase() === label && (!kind || n.type === kind));
    if (!matched) {
        // Fallback: match by startsWith or includes
        matched = GRAPH_DATA.nodes.find(n => String(n.label || '').toLowerCase().includes(label));
    }

    if (matched) {
        matched.root = true;
        // Rebuild graph to reflect root styling
        try { buildGraph(); } catch (e) { console.warn('[Decision] rebuild failed:', e && e.message); }
    } else {
        console.info('[Decision] Selected root principal not found in current graph:', principal.label);
    }
}

// If other modules call window.onRootPrincipalSelected, also apply to graph
const _origOnRoot = window.onRootPrincipalSelected;
window.onRootPrincipalSelected = (p) => {
    try { if (typeof _origOnRoot === 'function') _origOnRoot(p); } catch (e) {}
    try { applyRootPrincipalToGraph(p); } catch (e) {}
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

        const file = type === 'computer' ? 'computer.png' : 'user.png';
        const href = new URL(`../../assets/Icons/${file}`, window.location.href).href;
        item.innerHTML = `
            <span class="rp-item-icon"><img src="${href}" alt="${type}" style="width:18px;height:18px;vertical-align:middle" onerror="this.onerror=null;this.src='../../assets/favicon.png'"></span>
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
        const file = type === 'computer' ? 'computer.png' : 'user.png';
        const href = new URL(`../../assets/Icons/${file}`, window.location.href).href;
        btn.innerHTML = `<span class="rp-icon"><img src="${href}" alt="${type}" style="width:18px;height:18px;vertical-align:middle" onerror="this.onerror=null;this.src='../../assets/favicon.png'"></span><span>${name}</span>`;
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

window.setPathFocus = setPathFocus;
window.clearPathFocus = clearPathFocus;