const canvas = document.getElementById('d3-canvas');
const svgEl  = d3.select(canvas).append('svg')
    .attr('width', '100%').attr('height', '100%');

const defs = svgEl.append('defs');

['critical', 'high', 'normal'].forEach(type => {
    const color = EDGE_RULES.colors[type]?.arrowFill || (EDGE_RULES.colors.normal && EDGE_RULES.colors.normal.arrowFill) || '#334155';
    const ar    = EDGE_RULES.arrow;
    defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', ar.viewBox)
        .attr('refX',  ar.refX)
        .attr('refY',  0)
        .attr('markerWidth',  ar.markerWidth)
        .attr('markerHeight', ar.markerHeight)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', ar.path)
        .attr('fill', color);
});

const glowFilter = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
glowFilter.append('feGaussianBlur').attr('stdDeviation', '5').attr('result', 'coloredBlur');
const feMerge = glowFilter.append('feMerge');
feMerge.append('feMergeNode').attr('in', 'coloredBlur');
feMerge.append('feMergeNode').attr('in', 'coloredBlur');
feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

const zoomGroup = svgEl.append('g').attr('class', 'zoom-root');

let currentTransform = d3.zoomIdentity;
const zoom = d3.zoom()
    .scaleExtent([0.1, 5])
    .on('zoom', evt => {
        currentTransform = evt.transform;
        zoomGroup.attr('transform', evt.transform);
        updateScaleDisplay(Math.round(evt.transform.k * 100));
        
        // Scale 50% altında node labels'ı gizle
        const nodeLabels = zoomGroup.selectAll('.node-label');
        const nodeTypeLabels = zoomGroup.selectAll('.node-type-label');
        const labelOpacity = evt.transform.k < 0.5 ? 0 : 1;
        
        nodeLabels.transition().duration(300).attr('opacity', labelOpacity);
        nodeTypeLabels.transition().duration(300).attr('opacity', labelOpacity);
    });

svgEl.call(zoom);

let linkLine, linkLabel, node, simulation;

function prepareLayeredNodePositions(nodes, width, height) {
    const cx = width / 2;
    const cy = height / 2;

    // Root node-u həmişə tam mərkəzdə saxla
    const rootNode = nodes.find(n => n.root);
    if (!rootNode) return;

    rootNode.x  = cx;
    rootNode.y  = cy;
    rootNode.fx = cx;
    rootNode.fy = cy;

    // Root-dan birbaşa çıxan linklər (source id uyğunluğu)
    // Qeyd: buildGraph çağrılmadan əvvəl linklər hələ string id-lərlə ola bilər
    const rootId = String(rootNode.id).toLowerCase();
    const rootLinks = GRAPH_DATA.links.filter(l => {
        const sid = typeof l.source === 'object' ? String(l.source.id) : String(l.source);
        return sid.toLowerCase() === rootId;
    });

    // Hər bir birbaşa uşağın branch oxunu müəyyənləşdir
    // Root-dan çıxan hər edge üçün bərabər bucaq bölgüsü
    const branchCount = rootLinks.length;
    const branchStep  = branchCount > 0 ? (2 * Math.PI) / branchCount : 0;

    // Hər node-un hansı branch-a aid olduğunu müəyyən etmək üçün
    // BFS ilə root-dan ağacı gəzirik
    const nodeBranch = new Map();   // nodeId → { angle, depth }
    const nodeById   = new Map(nodes.map(n => [String(n.id).toLowerCase(), n]));

    // Branch açıları: üstdən başlayaraq saat istiqamətinə
    // (başlanğıc açı: -90° yəni yuxarı) — istifadəçi öz zövqünə uyğun dəyişə bilər
    const startAngle = -Math.PI / 2;

    rootLinks.forEach((link, i) => {
        const tid = typeof link.target === 'object'
            ? String(link.target.id).toLowerCase()
            : String(link.target).toLowerCase();
        const angle = startAngle + i * branchStep;
        nodeBranch.set(tid, { angle, depth: 1 });
    });

    // BFS: qalan bütün node-ları öz branch oxuna yerləşdir
    const queue = [...nodeBranch.keys()];
    while (queue.length > 0) {
        const currentId = queue.shift();
        const currentInfo = nodeBranch.get(currentId);

        const childLinks = GRAPH_DATA.links.filter(l => {
            const sid = typeof l.source === 'object'
                ? String(l.source.id).toLowerCase()
                : String(l.source).toLowerCase();
            return sid === currentId;
        });

        childLinks.forEach(link => {
            const tid = typeof link.target === 'object'
                ? String(link.target.id).toLowerCase()
                : String(link.target).toLowerCase();
            if (!nodeBranch.has(tid) && tid !== rootId) {
                nodeBranch.set(tid, { angle: currentInfo.angle, depth: currentInfo.depth + 1 });
                queue.push(tid);
            }
        });
    }

    // Hər node-u öz branch oxu üzərindəki mövqeyə yerləşdir
    const STEP = 190;  // branch boyunca ardıcıl node-lar arasındakı məsafə (px)

    nodeBranch.forEach((info, nid) => {
        const n = nodeById.get(nid);
        if (!n) return;
        const dist = info.depth * STEP;
        n.x = cx + dist * Math.cos(info.angle);
        n.y = cy + dist * Math.sin(info.angle);
    });

    // Branch-a düşməyən node-ları (varsa) mərkəz ətrafında yerləşdir
    nodes.forEach(n => {
        if (n.root) return;
        const nid = String(n.id).toLowerCase();
        if (!nodeBranch.has(nid)) {
            n.x = cx + (Math.random() - 0.5) * 300;
            n.y = cy + (Math.random() - 0.5) * 300;
        }
    });
}

function getTrimmedLinkPoints(link) {
    const source = link.source;
    const target = link.target;
    const sx = source.x ?? 0;
    const sy = source.y ?? 0;
    const tx = target.x ?? 0;
    const ty = target.y ?? 0;
    const dx = tx - sx;
    const dy = ty - sy;
    const distance = Math.hypot(dx, dy) || 1;
    const sourcePadding = getNodeEdgePadding(source, false);
    const targetPadding = getNodeEdgePadding(target, true);
    const sourceRatio = sourcePadding / distance;
    const targetRatio = targetPadding / distance;

    return {
        x1: sx + dx * sourceRatio,
        y1: sy + dy * sourceRatio,
        x2: tx - dx * targetRatio,
        y2: ty - dy * targetRatio
    };
}

function buildGraph() {
    zoomGroup.selectAll('*').remove();
    if (simulation) { simulation.stop(); simulation = null; }

    if (GRAPH_DATA.nodes.length === 0) {
        zoomGroup.append('text')
            .attr('x', 0).attr('y', 0)
            .attr('text-anchor', 'middle')
            .attr('fill', 'var(--text-dim)')
            .attr('font-size', '11px')
            .attr('font-family', 'JetBrains Mono, monospace')
            .attr('letter-spacing', '2px')
            .text('AWAITING ENGINE DATA');
        return;
    }

    const cw = canvas.clientWidth  || 800;
    const ch = canvas.clientHeight || 500;
    const cx = cw / 2;
    const cy = ch / 2;
    prepareLayeredNodePositions(GRAPH_DATA.nodes, cw, ch);

    // ── Links ──────────────────────────────────────────────
    const linkGroup = zoomGroup.append('g').attr('class', 'links');
    const link = linkGroup.selectAll('g').data(GRAPH_DATA.links).enter().append('g');

    linkLine = link.append('line')
        .attr('class', 'link-line')
        .attr('stroke',       d => getEdgeStroke(d))
        .attr('stroke-width', d => getEdgeWidth(d))
        .attr('opacity',      EDGE_RULES.opacity.default)
        .attr('marker-end',   d => getEdgeMarker(d));

    linkLabel = link.append('text')
        .attr('class', 'link-label')
        .attr('fill',       d => getEdgeLabelColor(d))
        .attr('font-size',  EDGE_RULES.label.fontSize)
        .attr('font-family',EDGE_RULES.label.fontFamily)
        .attr('font-weight',EDGE_RULES.label.fontWeight)
        .attr('opacity',    0)          // default gizli
        .attr('pointer-events', 'none') // mouse event-i line-a ötür
        .attr('text-anchor','middle')
        .text(d => formatEdgeLabel(d.rel));

    linkLine
        .on('mouseover.label', function(evt, d) {
            const idx = linkLine.nodes().indexOf(this);
            d3.select(linkLabel.nodes()[idx]).attr('opacity', 1);
        })
        .on('mouseout.label', function(evt, d) {
            const idx = linkLine.nodes().indexOf(this);
            d3.select(linkLabel.nodes()[idx]).attr('opacity', 0);
        });

    // ── Nodes ──────────────────────────────────────────────
    const nodeGroup = zoomGroup.append('g').attr('class', 'nodes');
    node = nodeGroup.selectAll('g').data(GRAPH_DATA.nodes).enter().append('g')
        .attr('class', 'node-group')
        .attr('transform', d => `translate(${d.x},${d.y})`)
        .call(d3.drag()
            .on('start', dragStart)
            .on('drag',  dragging)
            .on('end',   dragEnd));

    node.append('circle')
        .attr('r', d => getNodeOuterRadius(d))
        .attr('fill', 'none')
        .attr('stroke', d => getNodeOuterStyle(d).stroke)
        .attr('stroke-width', d => getNodeOuterStyle(d).strokeWidth)
        .attr('stroke-dasharray', d => getNodeOuterStyle(d).dash)
        .attr('opacity', d => getNodeOuterStyle(d).opacity)
        .attr('filter', 'url(#glow)');

    node.filter(d => d.root)
        .append('circle')
        .attr('r', d => getNodeRootExtraRadius(d))
        .attr('fill', 'none')
        .attr('stroke', d => getNodeRootExtraStyle(d).stroke)
        .attr('stroke-width', d => getNodeRootExtraStyle(d).strokeWidth)
        .attr('stroke-dasharray', d => getNodeRootExtraStyle(d).dash)
        .attr('opacity', d => getNodeRootExtraStyle(d).opacity)
        .attr('filter', 'url(#glow)');

    node.append('circle')
        .attr('class', 'node-circle')
        .attr('r',            d => getNodeRadius(d))
        .attr('fill',         d => getNodeFillColor(d))
        .attr('stroke',       d => getNodeStrokeColor(d))
        .attr('stroke-width', d => NODE_RULES.highlight.inactiveStrokeWidth)
        .attr('opacity',      d => NODE_RULES.offsets.nodeOpacity)
        .on('mouseover', showTooltip)
        .on('mousemove', moveTooltip)
        .on('mouseout',  hideTooltip)
        .on('click', clickNode);

    const NODE_ICONS = {
        user:      '\u{1F464}',  // 👤
        computer:  '\u{1F4BB}',  // 💻
        group:     '\u{1F465}',  // 👥
        domain:    '\u{1F310}',  // 🌐
        ou:        '\u{1F4C1}',  // 📁
        gpo:       '\u2699\uFE0F', // ⚙️
        container: '\u{1F4E6}',  // 📦
        object:    '\u2699\uFE0F'  // ⚙️
    };

    node.append('text')
        .attr('class', 'node-icon')
        .attr('dy', '0.38em')
        .attr('text-anchor', 'middle')
        .attr('font-size', d => getNodeIconFontSize(d))
        .attr('pointer-events', 'none')
        .text(d => NODE_ICONS[d.type] || NODE_ICONS.object);

    const riskTxtCfg = NODE_RULES.label.riskText;
    node.filter(d => (d.risk || 0) > riskTxtCfg.showIfRiskAbove)
        .append('text')
        .attr('class', 'node-label')
        .attr('dy', '0.35em')
        .attr('fill',        riskTxtCfg.fill)
        .attr('font-size',   riskTxtCfg.fontSize)
        .attr('font-weight', riskTxtCfg.fontWeight)
        .attr('text-anchor', 'middle')
        .text(d => d.risk);

    node.append('text')
        .attr('class', 'node-label')
        .attr('dy', d => getNodeLabelDy(d))
        .attr('fill', d => getNodeLabelColor(d))
        .attr('font-size', NODE_RULES.label.fontSize)
        .attr('font-weight', NODE_RULES.label.fontWeight)
        .attr('font-family', NODE_RULES.label.fontFamily)
        .attr('text-anchor', 'middle')
        .attr('letter-spacing', '0.3px')
        .text(d => formatNodeLabel(d.label));

    node.append('text')
        .attr('class', 'node-type-label')
        .attr('dy', d => getNodeTypeLabelDy(d))
        .attr('fill', d => getNodeTypeLabelColor(d))
        .attr('font-size', '9px')
        .attr('font-weight', '400')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('text-anchor', 'middle')
        .attr('letter-spacing', '1.5px')
        .text(d => (d.type || 'OBJECT').toUpperCase());

    // Hər node üçün başlanğıc (branch) mövqeyini yadda saxla
    GRAPH_DATA.nodes.forEach(n => {
        if (!n.root) {
            n._bx = n.x;
            n._by = n.y;
            n._dragged = false;
        }
    });

    simulation = d3.forceSimulation(GRAPH_DATA.nodes)
        .force('link', d3.forceLink(GRAPH_DATA.links)
            .id(d => d.id)
            .distance(d => getEdgeForce(d).distance)
            .strength(0.02))
        .force('charge', d3.forceManyBody().strength(-80))
        .force('collision', d3.forceCollide().radius(d => getNodeCollisionRadius(d)));

    simulation.on('tick', () => {
        // Root həmişə mərkəzdə sabit
        const rootNode = GRAPH_DATA.nodes.find(n => n.root);
        if (rootNode) {
            rootNode.x = cx;
            rootNode.y = cy;
            rootNode.vx = 0;
            rootNode.vy = 0;
        }

        // Drag edilməmiş node-ları öz branch ox mövqeyinə qaytar
        GRAPH_DATA.nodes.forEach(n => {
            if (n.root || n._dragged) return;
            // Yavaş-yavaş branch oxuna çəkilsin (lerp)
            n.x += (n._bx - n.x) * 0.15;
            n.y += (n._by - n.y) * 0.15;
            n.vx = 0;
            n.vy = 0;
        });

        linkLine
            .attr('x1', d => getTrimmedLinkPoints(d).x1)
            .attr('y1', d => getTrimmedLinkPoints(d).y1)
            .attr('x2', d => getTrimmedLinkPoints(d).x2)
            .attr('y2', d => getTrimmedLinkPoints(d).y2);

        linkLabel
            .attr('x', d => (getTrimmedLinkPoints(d).x1 + getTrimmedLinkPoints(d).x2) / 2)
            .attr('y', d => (getTrimmedLinkPoints(d).y1 + getTrimmedLinkPoints(d).y2) / 2);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    simulation.on('end', fitGraph);
}

function fitGraph() {
    if (!GRAPH_DATA.nodes.length) return;
    const bounds = canvas.getBoundingClientRect();
    const w = bounds.width  || canvas.clientWidth  || 800;
    const h = bounds.height || canvas.clientHeight || 500;
    const xs = GRAPH_DATA.nodes.map(n => n.x).filter(v => v != null && !isNaN(v));
    const ys = GRAPH_DATA.nodes.map(n => n.y).filter(v => v != null && !isNaN(v));
    if (!xs.length) return;
    const x0 = Math.min(...xs), x1 = Math.max(...xs);
    const y0 = Math.min(...ys), y1 = Math.max(...ys);
    const gw = x1 - x0 || 1, gh = y1 - y0 || 1;
    const pad = 80;
    const k   = Math.min((w - pad * 2) / gw, (h - pad * 2) / gh, 1.4);
    const tx  = w / 2 - k * (x0 + gw / 2);
    const ty  = h / 2 - k * (y0 + gh / 2);
    svgEl.transition().duration(600)
        .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(k));
}

function dragStart(evt, d) {
    if (!evt.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}
function dragging(evt, d) {
    d.fx = evt.x;
    d.fy = evt.y;
    d._dragged = true;
    d._bx = evt.x;
    d._by = evt.y;
}
function dragEnd(evt, d) {
    if (!evt.active) simulation.alphaTarget(0);
    d._bx = d.x;
    d._by = d.y;
    d.fx = null;
    d.fy = null;
}

const tooltip = document.getElementById('node-tooltip');

function showTooltip(evt, d) {
    document.getElementById('tt-type').textContent  = d.type.toUpperCase();
    document.getElementById('tt-name').textContent  = d.label;
    document.getElementById('tt-score').textContent = d.risk != null ? `${d.risk} / 100` : '—';
    document.getElementById('tt-edges').textContent = d.edges != null ? d.edges : '—';
    document.getElementById('tt-depth').textContent = d.depth != null ? `Depth ${d.depth}` : 'Depth —';
    tooltip.style.display = 'block';
    moveTooltip(evt);
}
function moveTooltip(evt) {
    const rect = canvas.getBoundingClientRect();
    let x = evt.clientX - rect.left + 12;
    let y = evt.clientY - rect.top  + 12;
    if (x + 180 > rect.width)  x -= 200;
    if (y + 120 > rect.height) y -= 130;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
}
function hideTooltip() {
    tooltip.style.display = 'none';
}

function clickNode(evt, d) {
    const relatedPath = ATTACK_PATHS.find(p =>
        p.hops.some(h => h.name && h.name.toLowerCase() === d.label.toLowerCase())
    );
    if (relatedPath) {
        const cards = document.querySelectorAll('.path-card');
        cards.forEach(c => {
            if (c.dataset.id === relatedPath.id) {
                selectPath(relatedPath, c);   // UI modulundan
                c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        });
    }
}

function highlightPath(path) {
    if (!node || !linkLine) return;
    const names = new Set(path.hops.filter(h => h.name).map(h => h.name.toLowerCase()));

    node.select('circle')
        .attr('opacity', d => names.has(d.label.toLowerCase()) ? NODE_RULES.highlight.activeOpacity : NODE_RULES.highlight.inactiveOpacity)
        .attr('stroke-width', d => names.has(d.label.toLowerCase()) ? NODE_RULES.highlight.activeStrokeWidth : NODE_RULES.highlight.inactiveStrokeWidth);

    linkLine
        .attr('opacity', d => {
            const s = d.source.label?.toLowerCase() || '';
            const t = d.target.label?.toLowerCase() || '';
            return names.has(s) && names.has(t) ? EDGE_RULES.opacity.highlighted : EDGE_RULES.opacity.dimmed;
        })
        .attr('stroke-width', d => {
            const s = d.source.label?.toLowerCase() || '';
            const t = d.target.label?.toLowerCase() || '';
            return names.has(s) && names.has(t) ? EDGE_RULES.width.highlighted : EDGE_RULES.width.normal;
        });
}

function resetHighlight() {
    if (!node || !linkLine) return;
    node.select('circle')
        .attr('opacity', NODE_RULES.highlight.inactiveOpacity)
        .attr('stroke-width', NODE_RULES.highlight.inactiveStrokeWidth);
    linkLine
        .attr('opacity', EDGE_RULES.opacity.default)
        .attr('stroke-width', d => getEdgeWidth(d));
}

function updateScaleDisplay(pct) {
    const slider  = document.getElementById('scale-slider');
    const display = document.getElementById('scale-display');
    slider.value  = Math.max(30, Math.min(300, pct));
    display.textContent = pct + '%';
}

document.getElementById('scale-slider').addEventListener('input', e => {
    const k = Number(e.target.value) / 100;
    const bounds = canvas.getBoundingClientRect();
    svgEl.transition().duration(200)
        .call(zoom.transform, d3.zoomIdentity
            .translate(bounds.width / 2, bounds.height / 2)
            .scale(k)
            .translate(-bounds.width / 2, -bounds.height / 2));
    document.getElementById('scale-display').textContent = e.target.value + '%';
});

document.getElementById('zoom-in').addEventListener('click', () => {
    svgEl.transition().duration(200).call(zoom.scaleBy, 1.3);
});
document.getElementById('zoom-out').addEventListener('click', () => {
    svgEl.transition().duration(200).call(zoom.scaleBy, 0.75);
});
document.getElementById('zoom-reset').addEventListener('click', () => {
    svgEl.transition().duration(400).call(zoom.transform, d3.zoomIdentity);
    updateScaleDisplay(100);
});
document.getElementById('zoom-fit').addEventListener('click', () => {
    fitGraph();
});

function getSelectedRootPrincipal() {
    const helperSelected = window.RootPrincipal?.getSelected?.() || null;
    const runtimeSelected = helperSelected || window.SELECTED_PRINCIPAL || null;
    const storedName = sessionStorage.getItem('selectedRootPrincipal') || '';
    const storedType = sessionStorage.getItem('selectedRootPrincipalType') || '';
    const storedSid = sessionStorage.getItem('selectedRootPrincipalSID') || '';

    const selected = runtimeSelected || (storedName ? {
        label: storedName,
        kind: storedType,
        sid: storedSid
    } : null);

    if (!selected || (!selected.label && !selected.sid)) return null;

    return selected;
}

function renderSelectedRootPrincipal(selected) {
    if (!selected || (!selected.label && !selected.sid)) return false;

    const node = {
        id: selected.sid || selected.label,
        label: selected.label,
        type: selected.kind === 'computer' ? 'computer' : 'user',
        sid: selected.sid || '',
        depth: 0,
        edges: 0,
        root: true
    };

    loadGraphData({ nodes: [node], links: [] }, []);
    return true;
}

function normalizeNodeId(record, fallback) {
    return record?.target_sid || record?.principal_sid || record?.target_dn || record?.target_name || fallback;
}

function normalizeLabel(record, fallback) {
    return record?.target_name || record?.target_dn || fallback;
}

function normalizeType(value) {
    return String(value || 'object').toLowerCase();
}

function edgeLabel(record) {
    return record?.rights_display || (Array.isArray(record?.edge_rights) ? record.edge_rights.join(', ') : 'ACE');
}

function buildGraphDataFromEngine(engineData, selected) {
    const rootNode = {
        id: selected.sid || selected.label,
        label: selected.label,
        type: selected.kind === 'computer' ? 'computer' : 'user',
        sid: selected.sid || '',
        depth: 0,
        edges: 0,
        root: true,
        risk: 0,
        target_attributes: selected.target_attributes ?? null
    };

    const nodes = [rootNode];
    const links = [];
    const seenNodes = new Map([[String(rootNode.id).toLowerCase(), rootNode]]);
    const seenLinks = new Set();

    function ensureNode(record, fallbackId, fallbackLabel, fallbackType, depth) {
        const nodeId = normalizeNodeId(record, fallbackId);
        const nodeKey = String(nodeId).toLowerCase();
        if (!seenNodes.has(nodeKey)) {
            const node = {
                id: nodeId,
                label: normalizeLabel(record, fallbackLabel),
                type: normalizeType(record?.target_type || fallbackType),
                sid: record?.target_sid || '',
                dn: record?.target_dn || '',
                depth,
                edges: Array.isArray(record?.edge_rights) ? record.edge_rights.length : 0,
                risk: 0,
                target_attributes: record?.target_attributes ?? null
            };
            nodes.push(node);
            seenNodes.set(nodeKey, node);
        }
        return seenNodes.get(nodeKey);
    }

    function addEdge(sourceId, targetId, record) {
        const edgeRights = Array.isArray(record?.edge_rights)
            ? record.edge_rights.filter(Boolean)
            : (Array.isArray(record?.rights) ? record.rights.filter(Boolean) : []);
        const key = `${String(sourceId).toLowerCase()}->${String(targetId).toLowerCase()}::${edgeLabel(record)}`;
        if (seenLinks.has(key)) return;
        seenLinks.add(key);
        const crit = typeof getEdgeCategory === 'function'
            ? getEdgeCategory({ crit: false, edge_rights: edgeRights }) === 'critical'
            : false;
        links.push({
            source: sourceId,
            target: targetId,
            rel: edgeLabel(record),
            crit,
            edge_rights: edgeRights
        });
    }

    function walkRecord(record, parentNode, depth) {
        if (!record || typeof record !== 'object') return;

        const targetNode = ensureNode(
            record,
            `target-${nodes.length}`,
            record.target_name || record.target_dn || `target-${nodes.length}`,
            record.target_type || 'object',
            depth
        );

        addEdge(parentNode.id, targetNode.id, record);

        const nested = Array.isArray(record.next_step) ? record.next_step : [];
        for (const child of nested) {
            walkRecord(child, targetNode, depth + 1);
        }
    }

    const graphObjects = Array.isArray(engineData?.graph_objects) ? engineData.graph_objects : [];
    for (const record of graphObjects) {
        walkRecord(record, rootNode, 1);
    }

    return { nodes, links };
}

async function loadGraphObjectsFile() {
    const ts = Date.now();
    const candidates = [
        `../Engine/graph_objects.json?_t=${ts}`,
        `graph_objects.json?_t=${ts}`,
        `./graph_objects.json?_t=${ts}`,
    ];

    for (const url of candidates) {
        try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 3000); // 3s timeout
            const resp = await fetch(url, { cache: 'no-store', signal: ctrl.signal });
            clearTimeout(timer);
            if (resp.ok) return await resp.json();
        } catch (_) { /* növbəti yola keç */ }
    }

    throw new Error('graph_objects.json heç bir yolda tapılmadı');
}

const LOADING_STEPS = [
    { title: 'Initializing Engine',          sub: 'ACE Graph Engine is starting up',               pct:  5 },
    { title: 'Loading ACE Source Files',     sub: 'Reading dangerous_ace + extended_rights',        pct: 20 },
    { title: 'Scanning L1 ACEs',             sub: 'Finding direct rights for root principal',       pct: 40 },
    { title: 'Resolving Recursive Chain',    sub: 'Expanding next_step at all depths',              pct: 60 },
    { title: 'Writing Graph Objects',        sub: 'Serializing results to graph_objects.json',      pct: 80 },
    { title: 'Building Graph',               sub: 'Rendering nodes and edges',                      pct: 95 },
];

let _loadingTimer = null;
let _loadingStep  = 0;

function setAnalyzeLoading(isLoading, stepIndex) {
    const overlay = document.getElementById('analyze-loading-overlay');
    const card    = overlay?.querySelector('.analyze-loading-card');
    if (!overlay) return;

    if (isLoading) {
        if (_loadingTimer) { clearInterval(_loadingTimer); _loadingTimer = null; }

        overlay.classList.add('open');
        overlay.setAttribute('aria-hidden', 'false');

        _loadingStep = stepIndex != null ? stepIndex : 0;
        _applyLoadingStep(card, _loadingStep);

        _loadingTimer = setInterval(() => {
            if (_loadingStep < LOADING_STEPS.length - 1) {
                _loadingStep++;
                _applyLoadingStep(card, _loadingStep);
            }
        }, 1400);
    } else {
        if (_loadingTimer) { clearInterval(_loadingTimer); _loadingTimer = null; }
        _applyLoadingPct(100);
        setTimeout(() => {
            overlay.classList.remove('open');
            overlay.setAttribute('aria-hidden', 'true');
        }, 320);
    }
}

function _applyLoadingPct(pct) {
    const bar   = document.getElementById('analyze-loading-bar');
    const pctEl = document.getElementById('analyze-loading-pct');
    if (bar)   bar.style.width   = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';
}

function _applyLoadingStep(card, idx) {
    if (!card) return;
    const step    = LOADING_STEPS[Math.min(idx, LOADING_STEPS.length - 1)];
    const titleEl = card.querySelector('.analyze-loading-title');
    const subEl   = card.querySelector('.analyze-loading-subtitle');
    if (titleEl) titleEl.textContent = step.title;
    if (subEl)   subEl.textContent   = step.sub;
    _applyLoadingPct(step.pct);
}


async function analyzeSelectedRootPrincipal() {
    const selected    = getSelectedRootPrincipal();
    const selectedSid = selected?.sid || window.RootPrincipal?.getSelectedSID?.() || '';

    if (!selected || !selectedSid) {
        return renderSelectedRootPrincipal(selected);
    }

    setAnalyzeLoading(true, 0);
    await new Promise(resolve => requestAnimationFrame(resolve));

    try {
        const apiCtrl  = new AbortController();
        const apiTimer = setTimeout(() => apiCtrl.abort(), 60000); // 60s — engine uzun çəkə bilər
        let resp;
        try {
            const host = window.ENGINE_API_HOST || '127.0.0.1';
            const port = window.ENGINE_API_PORT || '5100';
            const apiUrl = `http://${host}:${port}/api/analyze-root`;
            resp = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sid: selectedSid, name: selected.label || '' }),
                cache: 'no-store',
                signal: apiCtrl.signal
            });
        } finally {
            clearTimeout(apiTimer);
        }

        if (!resp.ok) throw new Error(`API HTTP ${resp.status}`);

        const payload = await resp.json();
        if (!payload.success) throw new Error(payload.error || 'Unknown API error');

        const fileData = await loadGraphObjectsFile();
        window.LAST_ENGINE_GRAPH_OBJECTS = fileData;
        console.info('[Analyze] Engine returned', fileData?.total || 0, 'ACE records');

        const graphData = buildGraphDataFromEngine(fileData, selected);
        setAnalyzeLoading(false);
        loadGraphData(graphData, []);
        return true;

    } catch (err) {
        console.warn('[Analyze] Engine API uğursuz oldu, graph_objects.json birbaşa oxunur:', err.message);

        try {
            const fileData = await loadGraphObjectsFile();
            window.LAST_ENGINE_GRAPH_OBJECTS = fileData;
            console.info('[Analyze] Fallback — graph_objects.json:', fileData?.total || 0, 'records');

            const graphData = buildGraphDataFromEngine(fileData, {
                label : fileData.principal_name || selected?.label || 'root',
                sid   : fileData.principal_sid  || selectedSid     || '',
                kind  : 'user'
            });

            setAnalyzeLoading(false);
            loadGraphData(graphData, []);
            return true;

        } catch (fileErr) {
            console.error('[Analyze] graph_objects.json oxuna bilmədi:', fileErr.message);
            setAnalyzeLoading(false);
            return renderSelectedRootPrincipal(selected);
        }
    }
}

document.getElementById('analyze-btn').addEventListener('click', () => {
    analyzeSelectedRootPrincipal().then(rendered => {
        if (!rendered && simulation) {
            simulation.alphaTarget(0.5).restart();
            setTimeout(() => simulation.alphaTarget(0), 1500);
        }
    });
    resetHighlight();
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
});