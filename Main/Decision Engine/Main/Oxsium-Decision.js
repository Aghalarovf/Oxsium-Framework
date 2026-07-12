let GRAPH_DATA   = { nodes: [], links: [] };
let ATTACK_PATHS = [];

window.GRAPH_DATA   = GRAPH_DATA;
window.ATTACK_PATHS = ATTACK_PATHS;

const NODE_COLORS = {
    user:     { fill: '#6366f1', glow: '#6366f1', stroke: '#818cf8' },
    group:    { fill: '#0ea5e9', glow: '#0ea5e9', stroke: '#38bdf8' },
    computer: { fill: '#10b981', glow: '#10b981', stroke: '#34d399' },
    domain:   { fill: '#f59e0b', glow: '#f59e0b', stroke: '#fbbf24' },
};

function loadGraphData(graphData, attackPaths) {
    GRAPH_DATA   = graphData   || { nodes: [], links: [] };
    ATTACK_PATHS = attackPaths || [];

    window.GRAPH_DATA   = GRAPH_DATA;
    window.ATTACK_PATHS = ATTACK_PATHS;

    const rootNode = GRAPH_DATA.nodes?.find(n => n.root);
    if (rootNode && typeof window !== 'undefined' && window.Oxsium !== undefined) {
        if (typeof window.updateDomainBoundaryName === 'function') {
            window.updateDomainBoundaryName(rootNode.label || '');
        }
    }

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

        card.addEventListener('click', () => {
            document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');
        });
        list.appendChild(card);
    });

    restorePathFocusIfNeeded();
}

document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
    });
});

const _nodeCountEl = document.getElementById('node-count') || document.getElementById('stat-nodes');
const _pathCountEl = document.getElementById('path-count') || document.getElementById('stat-hops');
if (_nodeCountEl) _nodeCountEl.textContent = '—';
if (_pathCountEl) _pathCountEl.textContent = '—';
renderPathCards();

window.onRootPrincipalSelected = (principal) => {
    if (!principal) return;
    window.SELECTED_PRINCIPAL = principal;
    window.SELECTED_ROOT_PRINCIPAL_SID = principal.sid || '';
    sessionStorage.setItem('selectedRootPrincipal', principal.label || '');
    sessionStorage.setItem('selectedRootPrincipalType', principal.kind || '');
    sessionStorage.setItem('selectedRootPrincipalSID', principal.sid || '');
};

function applyRootPrincipalToGraph(principal) {
    if (!principal || !GRAPH_DATA || !GRAPH_DATA.nodes) return;
    const label = String(principal.label || '').toLowerCase();
    const kind  = principal.kind || '';

    GRAPH_DATA.nodes.forEach(n => { n.root = false; });

    let matched = GRAPH_DATA.nodes.find(n => String(n.label || '').toLowerCase() === label && (!kind || n.type === kind));
    if (!matched) {
        matched = GRAPH_DATA.nodes.find(n => String(n.label || '').toLowerCase().includes(label));
    }

    if (matched) {
        matched.root = true;
        try { buildGraph(); } catch (e) { console.warn('[Decision] rebuild failed:', e && e.message); }
    } else {
        console.info('[Decision] Selected root principal not found in current graph:', principal.label);
    }
}

const _origOnRoot = window.onRootPrincipalSelected;
window.onRootPrincipalSelected = (p) => {
    try { if (typeof _origOnRoot === 'function') _origOnRoot(p); } catch (e) {}
    try { applyRootPrincipalToGraph(p); } catch (e) {}
};
