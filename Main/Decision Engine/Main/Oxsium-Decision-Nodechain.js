let _chainActiveNode = null;
let _hintPanelOpen   = false;
let _hintPanelData   = null;

function renderNodeChainPanel(nodeData) {
    _chainActiveNode = nodeData;
    const panel = document.getElementById('panel-right-inner');
    if (!panel) return;

    const chain = buildChainToNode(nodeData);

    if (!chain || chain.length === 0) {
        panel.innerHTML = _emptyState('No chain path found from root to this node.');
        return;
    }

    let html = `
    <div class="nc-header">
        <div class="nc-header-top">
            <div class="nc-header-label">Node Chain</div>
            <div class="nc-header-close" id="nc-close-btn" title="Clear selection">✕</div>
        </div>
        <div class="nc-target-row">
            <div class="nc-target-dot ${nodeData.type || 'user'}"></div>
            <div class="nc-target-info">
                <div class="nc-target-name">${nodeData.label || nodeData.id}</div>
                <div class="nc-target-type">${(nodeData.type || 'OBJECT').toUpperCase()} · Depth ${nodeData.depth ?? '—'}</div>
            </div>
            ${nodeData.risk != null ? `<div class="nc-risk-badge ${_riskClass(nodeData.risk)}">${nodeData.risk}</div>` : ''}
        </div>
    </div>
    <div class="nc-stats-bar">
        <div class="nc-stat">
            <div class="nc-stat-val">${chain.filter(s => s.kind === 'node').length}</div>
            <div class="nc-stat-lbl">Hops</div>
        </div>
        <div class="nc-stat">
            <div class="nc-stat-val accent-blue">${chain.filter(s => s.kind === 'edge').length}</div>
            <div class="nc-stat-lbl">Edges</div>
        </div>
        <div class="nc-stat">
            <div class="nc-stat-val">${nodeData.depth ?? '—'}</div>
            <div class="nc-stat-lbl">Depth</div>
        </div>
    </div>`;

    html += '<div class="nc-chain">';

    chain.forEach((step, idx) => {
        if (step.kind === 'node') {
            const isRoot   = step.isRoot;
            const isTarget = step.isTarget;
            const dotClass = step.type || 'user';

            html += `
            <div class="nc-node-step ${isRoot ? 'nc-root' : ''} ${isTarget ? 'nc-target' : ''}" data-step-idx="${idx}">
                <div class="nc-node-connector-wrap">
                    <div class="nc-step-dot ${dotClass} ${isRoot ? 'nc-root-dot' : ''} ${isTarget ? 'nc-target-dot-anim' : ''}"></div>
                    ${!isTarget ? '<div class="nc-step-vline"></div>' : ''}
                </div>
                <div class="nc-node-content">
                    <div class="nc-node-label">${step.label}</div>
                    <div class="nc-node-meta">
                        <span class="nc-node-type">${(step.type || 'OBJECT').toUpperCase()}</span>
                        ${step.risk != null ? `<span class="nc-node-risk ${_riskClass(step.risk)}">Risk ${step.risk}</span>` : ''}
                        ${isRoot  ? '<span class="nc-badge-root">ROOT</span>'   : ''}
                        ${isTarget? '<span class="nc-badge-target">TARGET</span>' : ''}
                    </div>
                </div>
            </div>`;

        } else if (step.kind === 'edge') {

            const critClass = step.crit ? 'red' : 'blue';
            const hintIdx   = idx;

            html += `
            <div class="nc-edge-step" data-step-idx="${idx}">
                <div class="nc-edge-connector-wrap">
                    <div class="nc-edge-vert-line"></div>
                    <div class="nc-edge-arrow">▾</div>
                    <div class="nc-edge-vert-line"></div>
                </div>
                <div class="nc-edge-content">
                    <div class="nc-edge-rel-wrap">
                        <span class="nc-edge-rel edge-tag ${critClass}">${step.rel}</span>
                        ${step.crit ? '<span class="nc-edge-crit-flag">CRITICAL</span>' : ''}
                    </div>
                    <div class="nc-edge-route">${step.source} → ${step.target}</div>
                    <button class="nc-hint-bar" data-hint-idx="${hintIdx}" title="View edge details">
                        <img class="nc-hint-settings" src="../../assets/Icons/settings.png" alt="Settings" title="Settings"/>
                        <span class="nc-hint-bar-icon">⬡</span>
                        <span class="nc-hint-bar-label">Edge Hint</span>
                        <span class="nc-hint-bar-arrow">›</span>
                    </button>
                </div>
            </div>`;
        }
    });

    html += '</div>';

    html += _buildNodeStatsFooter(nodeData, chain);

    panel.innerHTML = html;

    const closeBtn = panel.querySelector('#nc-close-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            clearNodeChainPanel();
            window.resetHighlight?.();
            window.clearPathFocus?.();
        });
    }

    panel.querySelectorAll('.nc-hint-bar').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const idx = parseInt(btn.dataset.hintIdx);
            const step = chain[idx];
            openHintPanel(step, nodeData);
        });
    });

    panel.querySelectorAll('.nc-node-step').forEach(el => {
        el.addEventListener('click', () => {

        });
    });
}

function buildChainToNode(targetNode) {
    if (!targetNode || !window.GRAPH_DATA) return [];

    const nodes = window.GRAPH_DATA.nodes || [];
    const links = window.GRAPH_DATA.links || [];

    const nodeById = new Map();
    nodes.forEach(n => nodeById.set(String(n.id).toLowerCase(), n));

    const rootNode = nodes.find(n => n.root);
    if (!rootNode) return _fallbackChain(targetNode);

    const targetId = String(targetNode.id).toLowerCase();
    const rootId   = String(rootNode.id).toLowerCase();

    if (rootId === targetId) {
        return [{
            kind: 'node', label: rootNode.label, type: rootNode.type,
            risk: rootNode.risk, isRoot: true, isTarget: true, id: rootId
        }];
    }

    const adj = new Map();
    links.forEach(link => {
        const srcId = String(link.source?.id || link.source || '').toLowerCase();
        const tgtId = String(link.target?.id || link.target || '').toLowerCase();
        const rel   = link.rel || link.label || 'EDGE';
        const crit  = !!link.crit;
        if (!adj.has(srcId)) adj.set(srcId, []);
        adj.get(srcId).push({ tgtId, rel, crit });
    });

    const parentPath = _traceParentPath(targetNode, nodeById);
    if (parentPath.length > 0) {
        return _buildChainFromNodePath(parentPath, adj, nodeById);
    }

    const bfsPath = _bfsPath(rootId, targetId, adj, nodeById);
    if (bfsPath.length > 0) {
        return _buildChainFromNodePath(bfsPath, adj, nodeById);
    }

    return _fallbackChain(targetNode, rootNode, adj);
}

function _traceParentPath(targetNode, nodeById) {
    const path = [];
    let current = targetNode;
    let safety = 0;

    while (current && safety < 64) {
        path.unshift(current);
        const parentId = String(current._parentId || '').toLowerCase();
        if (!parentId) break;
        current = nodeById.get(parentId);
        safety++;
    }

    if (path.length === 0 || !path[0]?.root) return [];
    return path;
}

function _bfsPath(rootId, targetId, adj, nodeById) {
    const visited = new Map();
    const queue = [rootId];
    visited.set(rootId, null);

    while (queue.length > 0) {
        const curr = queue.shift();
        if (curr === targetId) break;
        const neighbors = adj.get(curr) || [];
        for (const { tgtId } of neighbors) {
            if (!visited.has(tgtId)) {
                visited.set(tgtId, curr);
                queue.push(tgtId);
            }
        }
    }

    if (!visited.has(targetId)) return [];

    const path = [];
    let cur = targetId;
    while (cur !== null) {
        const node = nodeById.get(cur);
        if (node) path.unshift(node);
        cur = visited.get(cur);
    }
    return path;
}

function _buildChainFromNodePath(nodePath, adj, nodeById) {
    const chain = [];

    

    nodePath.forEach((node, i) => {
        const isRoot   = i === 0;
        const isTarget = i === nodePath.length - 1;

        chain.push({
            kind: 'node',
            label: node.label || node.id,
            type:  node.type  || 'object',
            risk:  node.risk,
            depth: node.depth,
            id:    String(node.id).toLowerCase(),
            isRoot,
            isTarget
        });

        if (i < nodePath.length - 1) {
            const srcId = String(node.id).toLowerCase();
            const tgtId = String(nodePath[i + 1].id).toLowerCase();
            const srcLabel = node.label || node.id;
            const tgtLabel = nodePath[i + 1].label || nodePath[i + 1].id;

            const edges = (adj.get(srcId) || []).filter(e => e.tgtId === tgtId);
            const mainEdge = edges[0] || { rel: 'CONNECTS', crit: false };

            chain.push({
                kind:   'edge',
                rel:    _normalizeRel(mainEdge.rel),
                crit:   mainEdge.crit,
                source: srcLabel,
                target: tgtLabel,
                allEdges: edges,
                srcId, tgtId
            });
        }
    });

    return chain;
}

function _fallbackChain(targetNode, rootNode, adj) {
    const chain = [];
    if (rootNode) {
        chain.push({ kind: 'node', label: rootNode.label, type: rootNode.type, risk: rootNode.risk, isRoot: true, isTarget: false });
        const srcId = String(rootNode.id).toLowerCase();
        const tgtId = String(targetNode.id).toLowerCase();
        const edges = (adj?.get(srcId) || []).filter(e => e.tgtId === tgtId);
        if (edges.length > 0) {
            const rel = (/ds[-_ ]?replication.*get[-_ ]?changes/i.test(String(edges[0].rel || '')) || /dcsync/i.test(String(edges[0].rel || ''))) ? 'DS-Replication-Get-Changes-All' : edges[0].rel;
            chain.push({ kind: 'edge', rel: rel, crit: edges[0].crit, source: rootNode.label, target: targetNode.label, allEdges: edges, srcId, tgtId });
        } else {
            chain.push({ kind: 'edge', rel: '···', crit: false, source: rootNode.label, target: targetNode.label, allEdges: [], srcId, tgtId });
        }
    }
    chain.push({ kind: 'node', label: targetNode.label || targetNode.id, type: targetNode.type, risk: targetNode.risk, isRoot: !rootNode, isTarget: true });
    return chain;
}

function _buildNodeStatsFooter(nodeData, chain) {
    const edgeCount    = (window.GRAPH_DATA?.links || []).filter(l => {
        const src = String(l.source?.id || l.source || '').toLowerCase();
        const tgt = String(l.target?.id || l.target || '').toLowerCase();
        const nId = String(nodeData.id).toLowerCase();
        return src === nId || tgt === nId;
    }).length;

    const hopCount = chain.filter(s => s.kind === 'node').length - 1;

    const chainEdges = chain.filter(s => s.kind === 'edge').map(s => {
        const r = String(s.rel || '');
        if (/ds[-_ ]?replication.*get[-_ ]?changes/i.test(r) || /dcsync/i.test(r)) return 'DS-Replication-Get-Changes-All';
        return r;
    });
    const uniqueEdges = [...new Set(chainEdges)];

    return `
    <div class="nc-footer">
        <div class="nc-footer-title">CHAIN EDGES</div>
        <div class="nc-edge-list">
            ${uniqueEdges.length > 0 
                ? uniqueEdges.map(e => `<span class="nc-footer-edge edge-tag blue">${e}</span>`).join('')
                : '<span class="nc-footer-empty">—</span>'}
        </div>
        <div class="nc-footer-meta">
            <span>${edgeCount} total connections</span>
            <span>${hopCount} hop${hopCount !== 1 ? 's' : ''} from root</span>
        </div>
    </div>`;
}

function openHintPanel(edgeStep, nodeData) {
    _hintPanelOpen = true;
    _hintPanelData = { edgeStep, nodeData };

    let panel = document.getElementById('nc-hint-panel');
    if (!panel) {
        panel = document.createElement('div');
        panel.id = 'nc-hint-panel';
        panel.className = 'nc-hint-panel';
        document.querySelector('.oxsium-shell').appendChild(panel);
    }

    const sourceNode = _getNodeByLabel(edgeStep.source);
    const targetNode = _getNodeByLabel(edgeStep.target);
    const _formatDisplayName = (node, rawLabel) => {
        if (!node) return rawLabel || '';
        let name = node.label || node.id || rawLabel || '';
        const typeStr = String(node.type || '').toLowerCase();
        const looksLikeComputer = typeStr.includes('comput') || typeStr.includes('host');
        const rawEndsWithDollar = String(rawLabel || '').endsWith('$');
        const nodeIdEndsWithDollar = String(node.id || '').endsWith('$');
        const nodeLabelEndsWithDollar = String(node.label || '').endsWith('$');
        if ((looksLikeComputer || rawEndsWithDollar || nodeIdEndsWithDollar || nodeLabelEndsWithDollar) && !name.endsWith('$')) name += '$';
        return name;
    };
    const displaySource = _formatDisplayName(sourceNode, edgeStep.source);
    const displayTarget = _formatDisplayName(targetNode, edgeStep.target);

    const critBg = edgeStep.crit
        ? 'rgba(239,68,68,0.06)'
        : 'rgba(56,189,248,0.04)';

    panel.innerHTML = `
    <div class="nc-hint-panel-inner">
        <div class="nc-hint-panel-head">
            <div class="nc-hint-panel-title-row">
                <span class="nc-hint-panel-icon">⬡</span>
                <span class="nc-hint-panel-title">Edge Detail</span>
                ${edgeStep.crit ? '<span class="nc-hint-crit-chip">CRITICAL</span>' : ''}
            </div>
            <button class="nc-hint-panel-close" id="nc-hint-close">✕</button>
        </div>

        <div class="nc-hint-panel-body">
            <!-- Edge Summary -->
            <div class="nc-hint-section">
                <div class="nc-hint-section-label">Relation</div>
                <div class="nc-hint-rel-display ${edgeStep.crit ? 'crit' : 'normal'}">${edgeStep.rel}</div>
            </div>

            <div class="nc-hint-section">
                <div class="nc-hint-section-label">Route</div>
                <div class="nc-hint-route">
                    <span class="nc-hint-route-node">${displaySource}</span>
                    <span class="nc-hint-route-arrow">──▶</span>
                    <span class="nc-hint-route-node target">${displayTarget}</span>
                </div>
            </div>

            ${edgeStep.allEdges && edgeStep.allEdges.length > 1 ? `
            <div class="nc-hint-section">
                <div class="nc-hint-section-label">Parallel Edges (${edgeStep.allEdges.length})</div>
                <div class="nc-hint-parallel-list">
                    ${edgeStep.allEdges.map((e, i) => `
                    <div class="nc-hint-parallel-item">
                        <span class="nc-hint-parallel-idx">${String(i+1).padStart(2,'0')}</span>
                        <span class="edge-tag ${e.crit ? 'red' : 'blue'}">${_normalizeRel(e.rel)}</span>
                        ${e.crit ? '<span class="nc-hint-crit-flag-sm">CRIT</span>' : ''}
                    </div>`).join('')}
                </div>
            </div>` : ''}

            <!-- Attack Vectors — dinamik komandalr -->
            <div class="nc-hint-section">
                <div class="nc-hint-section-label">Attack Vectors</div>
                <div id="nc-attack-vectors-content" class="nc-hint-placeholder-body">
                    <div class="nc-hint-placeholder-icon">⊡</div>
                    <div class="nc-hint-placeholder-text">Loading attack vectors...</div>
                </div>
            </div>

            <div class="nc-hint-section nc-hint-section-placeholder">
                <div class="nc-hint-section-label">Remediation</div>
                <div class="nc-hint-placeholder-body">
                    <div class="nc-hint-placeholder-icon">⊡</div>
                    <div class="nc-hint-placeholder-text">Remediation guidance will appear here</div>
                </div>
            </div>

            <div class="nc-hint-section nc-hint-section-placeholder">
                <div class="nc-hint-section-label">References</div>
                <div class="nc-hint-placeholder-body">
                    <div class="nc-hint-placeholder-icon">⊡</div>
                    <div class="nc-hint-placeholder-text">Reference links and documentation will appear here</div>
                </div>
            </div>
        </div>
    </div>`;

    requestAnimationFrame(() => panel.classList.add('open'));

    const vectorsContent = document.getElementById('nc-attack-vectors-content');
    if (vectorsContent && typeof window.renderAttackVectors === 'function') {
        const vectorsHtml = window.renderAttackVectors(edgeStep.rel, sourceNode, targetNode);
        vectorsContent.innerHTML = vectorsHtml;
        

        setTimeout(() => {
            vectorsContent.querySelectorAll('.nc-vector-copy').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const cmd = btn.dataset.cmd;
                    navigator.clipboard.writeText(cmd).then(() => {

                        btn.classList.add('copied');
                        const originalHTML = btn.innerHTML;
                        btn.innerHTML = '<span class="nc-copy-icon">✓</span>';
                        
                        setTimeout(() => {
                            btn.classList.remove('copied');
                            btn.innerHTML = originalHTML;
                        }, 1500);
                        

                        _showToastNotification('Command copied to clipboard', 'success', 2000);
                    }).catch(err => {
                        _showToastNotification('Failed to copy command', 'error', 2000);
                    });
                });
            });
        }, 50);
    }

    const closeBtn = document.getElementById('nc-hint-close');
    if (closeBtn) closeBtn.addEventListener('click', closeHintPanel);

    panel.addEventListener('click', (e) => {
        if (e.target === panel) closeHintPanel();
    });
}

function closeHintPanel() {
    const panel = document.getElementById('nc-hint-panel');
    if (!panel) return;
    panel.classList.remove('open');
    _hintPanelOpen = false;
    setTimeout(() => panel.remove(), 260);
}

function clearNodeChainPanel() {
    _chainActiveNode = null;
    const panel = document.getElementById('panel-right-inner');
    if (panel) {
        panel.innerHTML = _emptyState();
    }
    closeHintPanel();
}

function _emptyState(msg) {
    return `
    <div class="nc-empty">
        <div class="nc-empty-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" width="28" height="28">
                <circle cx="12" cy="12" r="9"/>
                <path d="M8 12h8M12 8v8"/>
            </svg>
        </div>
        <div class="nc-empty-title">Node Inspector</div>
        <div class="nc-empty-sub">${msg || 'Click any node in the graph to inspect its chain from root'}</div>
    </div>`;
}

function _riskClass(risk) {
    if (risk >= 80) return 'risk-crit';
    if (risk >= 50) return 'risk-high';
    return 'risk-low';
}

function _normalizeRel(rel) {
    if (!rel) return rel;
    const r = String(rel || '');
    if (/ds[-_ ]?replication.*get[-_ ]?changes/i.test(r) || /dcsync/i.test(r)) return 'DS-Replication-Get-Changes-All';
    return r;
}

function _getNodeByLabel(label) {
    if (!label || !window.GRAPH_DATA || !window.GRAPH_DATA.nodes) return null;
    const raw = String(label);
    const search = raw.toLowerCase();
    const nodes = window.GRAPH_DATA.nodes;

    let found = nodes.find(n => String(n.label || n.id).toLowerCase() === search);
    if (found) return found;

    const stripped = search.endsWith('$') ? search.slice(0, -1) : search;
    found = nodes.find(n => {
        const nlabel = String(n.label || n.id).toLowerCase();
        return nlabel === stripped || (nlabel + '$') === search || nlabel === search;
    });
    if (found) return found;

    found = nodes.find(n => String(n.id).toLowerCase() === search || String(n.id).toLowerCase() === stripped);
    if (found) return found;

    found = nodes.find(n => String(n.label || '').toLowerCase().includes(stripped));
    return found || null;
}

function _showToastNotification(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `nc-toast nc-toast-${type}`;
    toast.textContent = message;
    

    Object.assign(toast.style, {
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        padding: '12px 16px',
        backgroundColor: type === 'success' ? 'rgba(34, 197, 94, 0.9)' : type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(56, 189, 248, 0.9)',
        color: '#fff',
        borderRadius: '6px',
        fontSize: '11px',
        fontWeight: '500',
        fontFamily: "'JetBrains Mono', monospace",
        zIndex: '10000',
        animation: 'slideInRight 0.3s ease-out',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
    });
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

window.renderNodeChainPanel = renderNodeChainPanel;
window.clearNodeChainPanel  = clearNodeChainPanel;
window.closeHintPanel       = closeHintPanel;

document.addEventListener('DOMContentLoaded', () => {
    const right = document.querySelector('.panel-right');
    if (!right) return;

    right.innerHTML = `<div class="nc-scroll" id="panel-right-inner"></div>`;

    const inner = document.getElementById('panel-right-inner');
    if (inner) inner.innerHTML = _emptyState();
});