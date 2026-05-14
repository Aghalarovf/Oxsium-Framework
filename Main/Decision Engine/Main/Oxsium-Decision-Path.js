/* ═══════════════════════════════════════════════════════════
   Oxsium Framework · Decision Engine · Path Module
   ─────────────────────────────────────────────────────────
   Path selection, hop list, sparkline, and focus state only.
   Old auto-generated Path Detail text was removed.
═══════════════════════════════════════════════════════════ */

let selectedPath = null;
let currentPathFocusIds = new Set();

function normalizePathFocusIds(pathIds) {
    if (Array.isArray(pathIds)) {
        return new Set(pathIds.filter(Boolean).map(String));
    }
    if (pathIds instanceof Set) {
        return new Set([...pathIds].filter(Boolean).map(String));
    }
    return new Set(pathIds ? [String(pathIds)] : []);
}

function setPathFocus(pathId) {
    currentPathFocusIds = normalizePathFocusIds(pathId);
    const cards = document.querySelectorAll('.path-card');
    cards.forEach(card => {
        const isMatch = currentPathFocusIds.has(card.dataset.id);
        card.classList.toggle('dimmed', currentPathFocusIds.size > 0 && !isMatch);
        card.classList.toggle('active', isMatch);
        if (currentPathFocusIds.size > 0 && !isMatch) {
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
    currentPathFocusIds = new Set();
    document.querySelectorAll('.path-card').forEach(card => {
        card.classList.remove('dimmed');
        card.style.removeProperty('opacity');
        card.style.removeProperty('filter');
        card.style.removeProperty('background');
    });
}

function restorePathFocusIfNeeded() {
    if (currentPathFocusIds.size > 0) {
        setPathFocus(currentPathFocusIds);
    }
}

function selectPath(path, cardEl) {
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    cardEl.classList.add('active');
    selectedPath = path;

    document.getElementById('detail-name').textContent = path.id || 'Selected Path';
    document.getElementById('detail-sub').textContent = `${path.from} → ${path.to} · ${path.hops.filter(h => h.name).length - 1} hops`;

    const circ = 2 * Math.PI * 24;
    const pct = path.score / 100;
    document.getElementById('score-ring').setAttribute('stroke-dasharray', `${circ * pct} ${circ * (1 - pct)}`);
    document.getElementById('score-ring').setAttribute('stroke', path.sev === 'crit' ? '#ef4444' : '#f97316');
    document.getElementById('score-num').textContent = path.score;
    document.getElementById('score-num').style.color = path.sev === 'crit' ? 'var(--accent-red)' : 'var(--accent-orange)';

    const nodeCount = path.hops.filter(h => h.name).length;
    document.getElementById('meta-sev').textContent = path.sev.toUpperCase();
    document.getElementById('meta-sev').className = `score-meta-val ${path.sev === 'crit' ? 'red' : 'orange'}`;
    document.getElementById('meta-hops').textContent = `${nodeCount - 1} hops / ${nodeCount} nodes`;
    document.getElementById('meta-start').textContent = path.from;
    document.getElementById('meta-target').textContent = path.to;

    renderHopList(path);
    renderSparkline(path);
    renderRiskDistributionList(buildRiskDistributionEntriesFromPath(path), 'Path edges');

    highlightPath(path);
    setPathFocus(path.id);
}

function selectPaths(paths) {
    const pathList = Array.isArray(paths) ? paths.filter(Boolean) : [];
    if (pathList.length === 0) {
        clearPathFocus();
        return;
    }

    const firstPath = pathList[0];
    const firstCard = document.querySelector(`.path-card[data-id="${CSS.escape(firstPath.id)}"]`);
    if (firstCard) {
        selectPath(firstPath, firstCard);
    } else {
        selectedPath = firstPath;
    }

    setPathFocus(pathList.map(path => path.id));
}

function renderHopList(path) {
    const list = document.getElementById('hop-list');
    list.innerHTML = '';
    let hopNum = 0;

    path.hops.forEach((h, i) => {
        if (!h.name) return;
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
    });
}

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
            meta: prevNode?.name && nextNode?.name ? `${prevNode.name} → ${nextNode.name}` : 'Path edge'
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
        list.innerHTML = '<div class="risk-distribution-empty">No edge names available for this selection</div>';
        return;
    }

    list.innerHTML = items.map((item, idx) => {
        const parts = [
            `<span class="risk-distribution-index">${String(idx + 1).padStart(2, '0')}</span>`,
            `<span class="risk-distribution-name">${item.name}</span>`
        ];
        if (item.source || item.target) {
            parts.push(`<span class="risk-distribution-route">${item.source || '—'} → ${item.target || '—'}</span>`);
        }
        if (item.meta) {
            parts.push(`<span class="risk-distribution-meta">${item.meta}</span>`);
        }
        return `<div class="risk-distribution-item">${parts.join('')}</div>`;
    }).join('');
}

window.updateRiskDistributionList = renderRiskDistributionList;

function renderSparkline(path) {
    const svg = document.getElementById('sparkline-svg');
    svg.innerHTML = '';
    if (ATTACK_PATHS.length < 2) return;

    const scores = ATTACK_PATHS.map(p => p.score);
    const max = Math.max(...scores);
    const w = 280, h = 40;
    const step = w / (scores.length - 1);

    const points = scores.map((s, i) => [i * step, h - (s / max) * (h - 6) - 2]);

    const area = `M${points[0][0]},${h} ` + points.map(p => `L${p[0]},${p[1]}`).join(' ') + ` L${points[points.length - 1][0]},${h} Z`;
    const areaEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    areaEl.setAttribute('d', area);
    areaEl.setAttribute('fill', 'rgba(56,189,248,0.06)');
    svg.appendChild(areaEl);

    const line = `M` + points.map(p => `${p[0]},${p[1]}`).join(' L');
    const lineEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    lineEl.setAttribute('d', line);
    lineEl.setAttribute('fill', 'none');
    lineEl.setAttribute('stroke', 'rgba(56,189,248,0.6)');
    lineEl.setAttribute('stroke-width', '1');
    svg.appendChild(lineEl);

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

window.setPathFocus = setPathFocus;
window.clearPathFocus = clearPathFocus;
window.restorePathFocusIfNeeded = restorePathFocusIfNeeded;
window.selectPath = selectPath;
window.selectPaths = selectPaths;
