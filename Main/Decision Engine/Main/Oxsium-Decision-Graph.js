const canvas = document.getElementById('d3-canvas');
const svgEl  = d3.select(canvas).append('svg')
    .attr('width', '100%').attr('height', '100%');

const defs = svgEl.append('defs');

['blue', 'critical', 'high', 'normal'].forEach(type => {
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

// inject DC animation styles from node rules (if available)
try { if (typeof injectDcAnimationStyles === 'function') injectDcAnimationStyles(); } catch (e) {}

const glowFilter = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
glowFilter.append('feGaussianBlur').attr('stdDeviation', '5').attr('result', 'coloredBlur');
const feMerge = glowFilter.append('feMerge');
feMerge.append('feMergeNode').attr('in', 'coloredBlur');
feMerge.append('feMergeNode').attr('in', 'coloredBlur');
feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

const zoomGroup = svgEl.append('g').attr('class', 'zoom-root');

let currentTransform = d3.zoomIdentity;
let currentDomainName = ''; // Domain adını saxla

const zoom = d3.zoom()
    .scaleExtent([0.001, 5])
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
        
        // Scale-bağlı domain boundary vizualizasiyası
        const boundaryGroup = zoomGroup.select('.domain-boundary-group');
        if (boundaryGroup && !boundaryGroup.empty()) {
            const scale = evt.transform.k;
            // Scale < 20 (20%) olduqda görünür olur
            // Scale 20% - 10% arasında: opacity artır (20%'de 0 → 10%'de 1)
            // Scale ≤ 10% olduqda: opacity 1 (fulla görünən qalır)
            const VISIBILITY_START = 0.2;  // 20%
            const OPACITY_PEAK = 0.1;      // 10% (pik opacity noktası)
            
            let opacity = 0;
            let visible = false;
            
            if (scale < VISIBILITY_START) {
                visible = true;
                if (scale > OPACITY_PEAK) {
                    // 20% ile 10% arasında: opacity artır
                    opacity = (VISIBILITY_START - scale) / (VISIBILITY_START - OPACITY_PEAK);
                    opacity = Math.min(1, Math.max(0, opacity));
                } else {
                    // 10% və altında: tam opak (fulla görünən)
                    opacity = 1;
                }
            }
            
            boundaryGroup.transition().duration(200)
                .style('display', visible ? 'block' : 'none')
                .attr('opacity', opacity);
        }
        
        // 10%-də node'lar və link'ləri gizlə
        const nodesGroup = zoomGroup.select('.nodes');
        const linksGroup = zoomGroup.select('.links');
        const currentScale = evt.transform.k;
        const nodeOpacity = currentScale <= 0.1 ? 0 : 1;
        
        if (nodesGroup && !nodesGroup.empty()) {
            nodesGroup.transition().duration(200).attr('opacity', nodeOpacity);
        }
        if (linksGroup && !linksGroup.empty()) {
            linksGroup.transition().duration(200).attr('opacity', nodeOpacity);
        }
    });

svgEl.call(zoom);

svgEl.on('click.clear-focus', evt => {
    if (evt.target !== svgEl.node()) return;
    window.clearPathFocus?.();
    currentGraphFocus = {
        active: false,
        nodeNames: new Set(),
        linkPairs: new Set()
    };
    resetHighlight();
});

canvas.addEventListener('click', evt => {
    if (evt.target !== canvas) return;
    window.clearPathFocus?.();
    currentGraphFocus = {
        active: false,
        nodeNames: new Set(),
        linkPairs: new Set()
    };
    resetHighlight();
});

// Domain boundary adını yeniləmə funksiyası
window.updateDomainBoundaryName = function(domainName) {
    currentDomainName = domainName || '';
};

let linkLine, linkHitLine, linkLabel, node, simulation;
let currentGraphFocus = {
    active: false,
    nodeNames: new Set(),
    linkPairs: new Set()
};
const GRAPH_FOCUS_FADE_MS = 260;

function normalizeGraphName(value) {
    return String(value || '').trim().toLowerCase();
}

function makeLinkPairKey(sourceName, targetName) {
    return `${normalizeGraphName(sourceName)}->${normalizeGraphName(targetName)}`;
}

function getNodeNameFromLinkEndpoint(endpoint) {
    return normalizeGraphName(endpoint?.label || endpoint?.id || endpoint || '');
}

function buildGraphFocusFromNode(nodeData) {
    const nodeNames = new Set();
    const linkPairs = new Set();
    const nodeById = new Map(GRAPH_DATA.nodes.map(n => [normalizeGraphName(n.id), n]));

    let current = nodeData;
    let safety = 0;
    while (current && safety < 128) {
        const currentName = normalizeGraphName(current.label || current.id);
        if (currentName) nodeNames.add(currentName);

        const parentId = normalizeGraphName(current._parentId);
        if (!parentId) break;

        const parentNode = nodeById.get(parentId);
        const parentName = normalizeGraphName(parentNode?.label || parentNode?.id || current._parentLabel || '');
        if (parentName) nodeNames.add(parentName);
        if (parentName && currentName) {
            linkPairs.add(makeLinkPairKey(parentName, currentName));
        }

        current = parentNode;
        safety++;
    }

    return { nodeNames, linkPairs };
}

function buildGraphFocusFromPath(path, nodeIndex) {
    const nodeNames = new Set();
    const linkPairs = new Set();

    const entries = buildRiskDistributionEntriesToNode(path, nodeIndex);
    entries.forEach(entry => {
        const sourceName = normalizeGraphName(entry.source);
        const targetName = normalizeGraphName(entry.target);
        if (sourceName) nodeNames.add(sourceName);
        if (targetName) nodeNames.add(targetName);
        if (sourceName && targetName) {
            linkPairs.add(makeLinkPairKey(sourceName, targetName));
        }
    });

    return { nodeNames, linkPairs };
}

function applyGraphFocus(path, nodeIndex) {
    if (!node || !linkLine) return;

    const focus = buildGraphFocusFromPath(path, nodeIndex);
    const hasFocus = focus.nodeNames.size > 0;
    currentGraphFocus = {
        active: hasFocus,
        nodeNames: focus.nodeNames,
        linkPairs: focus.linkPairs
    };

    if (!hasFocus) {
        resetHighlight();
        return;
    }

    node
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => focus.nodeNames.has(normalizeGraphName(d.label)) ? 1 : 0.14)
        .style('filter', d => focus.nodeNames.has(normalizeGraphName(d.label))
            ? 'none'
            : 'grayscale(1) brightness(0.72) saturate(0.2)')
        .select('circle.node-circle')
        .attr('stroke-width', d => d.root
            ? NODE_RULES.highlight.inactiveStrokeWidth
            : (focus.nodeNames.has(normalizeGraphName(d.label))
            ? NODE_RULES.highlight.activeStrokeWidth
            : NODE_RULES.highlight.inactiveStrokeWidth));

    linkLine
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? 1 : 0.10;
        })
        .attr('stroke', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? getEdgeStroke(d) : 'rgba(148, 163, 184, 0.7)';
        });

    linkLabel
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? 0.9 : 0.04;
        })
        .attr('fill', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? getEdgeLabelColor(d) : '#94a3b8';
        });
}

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

    // Collect unique child node ids for root (angle distribution should be per-node)
    const rootChildIds = [];
    const rootChildSet = new Set();
    for (const l of rootLinks) {
        const tid = typeof l.target === 'object' ? String(l.target.id) : String(l.target);
        const key = String(tid).toLowerCase();
        if (!rootChildSet.has(key)) { rootChildSet.add(key); rootChildIds.push(key); }
    }

    // Hər bir birbaşa uşağın branch oxunu müəyyənləşdir
    // Root-dan çıxan hər node üçün bərabər bucaq bölgüsü (node-based, not edge-based)
    const STEP = 190;  // branch boyunca ardıcıl node-lar arasındakı məsafə (px)
    const branchCount = rootChildIds.length;
    const branchStep  = branchCount > 0 ? (2 * Math.PI) / branchCount : 0;

    // Hər node-un hansı branch-a aid olduğunu müəyyən etmək üçün
    // BFS ilə root-dan ağacı gəzirik
    const nodeBranch = new Map();   // nodeId → { angle, depth }
    const nodeById   = new Map(nodes.map(n => [String(n.id).toLowerCase(), n]));

    const getEdgeDegree = (id) => {
        const node = nodeById.get(String(id || '').toLowerCase());
        return Number(node?.edgeDegree || node?.degree || 0);
    };

    const getSpacingScale = (id) => {
        const degree = getEdgeDegree(id);
        if (degree >= 20) return 3;
        if (degree >= 15) return 2;
        if (degree >= 10) return 1.5;
        return 1;
    };

    const getOutgoingLinks = (sourceId) => GRAPH_DATA.links.filter(l => {
        const sid = typeof l.source === 'object'
            ? String(l.source.id).toLowerCase()
            : String(l.source).toLowerCase();
        return sid === sourceId;
    });

    // Bir node-a gələn bütün edge-ləri qaytarır (istiqamətdən asılı olmayaraq)
    const getIncomingLinks = (targetId) => GRAPH_DATA.links.filter(l => {
        const tid = typeof l.target === 'object'
            ? String(l.target.id).toLowerCase()
            : String(l.target).toLowerCase();
        return tid === targetId;
    });

    // Branch açıları: üstdən başlayaraq saat istiqamətinə
    // (başlanğıc açı: -90° yəni yuxarı) — istifadəçi öz zövqünə uyğun dəyişə bilər
    const startAngle = -Math.PI / 2;

    // Iterate unique child ids in preserved order
    rootChildIds.forEach((tid, i) => {
        const angle = startAngle + i * branchStep;
        const factor = Math.max(getSpacingScale(rootId), getSpacingScale(tid));
        nodeBranch.set(tid, { angle, depth: 1, parent: rootId, segmentLength: STEP * factor });
    });

    // Hər node öz child-larını da eyni qayda ilə fan-out etsin
    const queue = [...nodeBranch.keys()];
    while (queue.length > 0) {
        const currentId = queue.shift();
        const currentInfo = nodeBranch.get(currentId);

        const childLinks = getOutgoingLinks(currentId);
        if (!childLinks.length) continue;

        // Collect unique child node ids (node-based expansion)
        const uniqueChildren = [];
        const uSet = new Set();
        for (const link of childLinks) {
            const tid = typeof link.target === 'object' ? String(link.target.id).toLowerCase() : String(link.target).toLowerCase();
            if (tid === rootId) continue;
            if (!nodeBranch.has(tid) && !uSet.has(tid)) { uSet.add(tid); uniqueChildren.push(tid); }
        }
        if (!uniqueChildren.length) continue;

        // Calculate angular slots based on unique node counts: incoming unique nodes + outgoing unique children
        const incomingNodes = (function() {
            const inc = new Set();
            for (const l of GRAPH_DATA.links) {
                const tid = typeof l.target === 'object' ? String(l.target.id).toLowerCase() : String(l.target).toLowerCase();
                if (tid === currentId) {
                    const sid = typeof l.source === 'object' ? String(l.source.id).toLowerCase() : String(l.source).toLowerCase();
                    inc.add(sid);
                }
            }
            return inc.size;
        })();

        const totalNodes = Math.max(incomingNodes + uniqueChildren.length, 2);
        const angleStep  = (2 * Math.PI) / totalNodes;

        // Slot 0 reserved for parent; children start from slot 1
        const backAngle = currentInfo.angle + Math.PI;

        uniqueChildren.forEach((tid, slotIndex) => {
            const factor = Math.max(getSpacingScale(currentId), getSpacingScale(tid));
            const childAngle = backAngle + (slotIndex + 1) * angleStep;

            nodeBranch.set(tid, {
                angle: childAngle,
                depth: currentInfo.depth + 1,
                parent: currentId,
                segmentLength: STEP * factor
            });
            queue.push(tid);
        });
    }

    // Hər node-u öz PARENT-indən nisbi olaraq yerləşdir.
    // Əvvəlki üsul (mərkəzdən dist * cos/sin) yanlış idi: child açısı
    // dəyişdikdə node mərkəzdən uzaqlaşırdı, parent-dən deyil.
    // İndi: position(node) = position(parent) + segmentLength * [cos(angle), sin(angle)]
    const absPos = new Map();
    absPos.set(rootId, { x: cx, y: cy });

    const rootRecord = nodeById.get(rootId);
    if (rootRecord) {
        rootRecord._parentId = '';
        rootRecord._parentLabel = '';
    }

    // Depth-ə görə sırala ki, parent həmişə child-dan əvvəl yerləşdirilsin
    const sortedIds = [...nodeBranch.keys()].sort(
        (a, b) => nodeBranch.get(a).depth - nodeBranch.get(b).depth
    );

    for (const nid of sortedIds) {
        const info      = nodeBranch.get(nid);
        const parentPos = absPos.get(info.parent);
        if (!parentPos) continue;

        const seg = info.segmentLength || STEP;
        const x   = parentPos.x + seg * Math.cos(info.angle);
        const y   = parentPos.y + seg * Math.sin(info.angle);
        absPos.set(nid, { x, y });

        const n = nodeById.get(nid);
        if (n) {
            n.x = x;
            n.y = y;
            n._parentId = info.parent;
            n._parentLabel = nodeById.get(info.parent)?.label || info.parent;
        }
    }

        // Branch-a düşməyən node-ları (varsa) mərkəz ətrafında yerləşdir
    nodes.forEach(n => {
        if (n.root) return;
        const nid = String(n.id).toLowerCase();
        if (!nodeBranch.has(nid)) {
            n.x = cx + (Math.random() - 0.5) * 300;
            n.y = cy + (Math.random() - 0.5) * 300;
            n._parentId = '';
            n._parentLabel = '';
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

    if (distance === 1 && sx === tx && sy === ty) {
        const nodePadding = Math.max(getNodeEdgePadding(source, false), getNodeEdgePadding(target, true), 18);
        const stubLength = nodePadding + 28;
        return {
            x1: sx - stubLength,
            y1: sy,
            x2: sx + stubLength,
            y2: sy
        };
    }

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

    // Node mövqelərini əvvəlcə hazırla (boundary radius hesablamaq üçün)
    prepareLayeredNodePositions(GRAPH_DATA.nodes, cw, ch);

    // Ən uzaq node-a qədər olan maksimum məsafəni hesabla
    let maxDistance = 200; // minimum radius
    GRAPH_DATA.nodes.forEach(node => {
        if (node.x != null && node.y != null && !isNaN(node.x) && !isNaN(node.y)) {
            const dx = node.x - cx;
            const dy = node.y - cy;
            const distance = Math.hypot(dx, dy);
            maxDistance = Math.max(maxDistance, distance);
        }
    });

    // Padding əlavə et ki dairə node-ları tam əhatə etsin
    const BOUNDARY_PADDING = 60; // ekstra boşluq
    const BOUNDARY_RADIUS = maxDistance + BOUNDARY_PADDING;

    // Domain boundary visualization group (nodes/links-dən arxada olsun)
    const boundaryGroup = zoomGroup.append('g').attr('class', 'domain-boundary-group')
        .style('display', 'none')
        .attr('opacity', 0);
    
    // Transparent circle (domain sınırı)
    boundaryGroup.append('circle')
        .attr('class', 'domain-boundary-circle')
        .attr('cx', cx)
        .attr('cy', cy)
        .attr('r', BOUNDARY_RADIUS)
        .attr('fill', 'rgba(100, 150, 200, 0.05)')
        .attr('stroke', 'rgba(100, 150, 200, 0.3)')
        .attr('stroke-width', 2)
        .attr('pointer-events', 'none');
    
    // Domain adı text (dairənin üst kenarında)
    if (currentDomainName) {
        boundaryGroup.append('text')
            .attr('class', 'domain-boundary-label')
            .attr('x', cx)
            .attr('y', cy - BOUNDARY_RADIUS + 15)
            .attr('text-anchor', 'middle')
            .attr('fill', 'rgba(100, 150, 200, 0.8)')
            .attr('font-size', '16px')
            .attr('font-weight', 'bold')
            .attr('font-family', 'JetBrains Mono, monospace')
            .attr('pointer-events', 'none')
            .text(currentDomainName);
    }

    // ── Links ──────────────────────────────────────────────
    const linkGroup = zoomGroup.append('g').attr('class', 'links');
    const link = linkGroup.selectAll('g').data(GRAPH_DATA.links).enter().append('g');

    // Use path elements so we can render curved arcs for parallel links
    linkHitLine = link.append('path')
        .attr('class', 'link-hit-line')
        .attr('stroke', 'transparent')
        .attr('stroke-width', d => Math.max(getEdgeWidth(d) + 12, 18))
        .attr('stroke-linecap', 'round')
        .attr('opacity', 1)
        .attr('pointer-events', 'stroke');

    linkLine = link.append('path')
        .attr('class', 'link-line')
        .attr('stroke',       d => getEdgeStroke(d))
        .attr('stroke-width', d => getEdgeWidth(d))
        .attr('opacity',      EDGE_RULES.opacity.default)
        .attr('fill', 'none')
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

    const baseLinkLabelSize = Number.parseFloat(EDGE_RULES.label.fontSize) || 9;

    const showLinkLabel = function() {
        const idx = linkHitLine.nodes().indexOf(this);
        const label = d3.select(linkLabel.nodes()[idx]);
        label
            .classed('is-visible', true)
            .attr('opacity', 1)
            .attr('font-size', baseLinkLabelSize + 6)
            .attr('font-weight', 900)
            .classed('is-hovered', true);
    };

    const hideLinkLabel = function() {
        const idx = linkHitLine.nodes().indexOf(this);
        const label = d3.select(linkLabel.nodes()[idx]);
        label
            .classed('is-visible', false)
            .attr('opacity', 0)
            .attr('font-size', EDGE_RULES.label.fontSize)
            .attr('font-weight', EDGE_RULES.label.fontWeight)
            .classed('is-hovered', false);
    };

    linkHitLine
        .on('mouseover.label', showLinkLabel)
        .on('mousemove.label', showLinkLabel)
        .on('mouseout.label', hideLinkLabel)
        .on('click', clickEdge);

    // ── Nodes ──────────────────────────────────────────────
    const nodeGroup = zoomGroup.append('g').attr('class', 'nodes');
    node = nodeGroup.selectAll('g').data(GRAPH_DATA.nodes).enter().append('g')
        .attr('class', 'node-group')
        .classed('is-domain-controller', d => (typeof shouldHighlightAsDomainController === 'function' && shouldHighlightAsDomainController(d)) )
        .attr('transform', d => `translate(${d.x},${d.y})`)
        .on('click', clickNode)
        .call(d3.drag()
            .on('start', dragStart)
            .on('drag',  dragging)
            .on('end',   dragEnd));

    node.append('circle')
        .attr('r', d => getNodeOuterRadius(d))
        .attr('class', 'node-outer-ring')
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
        .on('mouseout',  hideTooltip);

    // Map node types to icon image files located in assets/Icons
    const NODE_ICON_FILES = {
        user:      'user.png',
        computer:  'computer.png',
        group:     'group.png',
        domain:    'ou.png',    // fallback to folder-style icon
        ou:        'ou.png',
        gpo:       'gpo.png',
        container: 'ou.png',
        object:    'acl.png'
    };

    function getNodeIconSize(d) {
        // return numeric px size
        const v = getNodeIconFontSize(d) || '16px';
        return parseInt(String(v).replace('px', ''));
    }

    function getNodeIconHref(d) {
        // Build absolute URL for the icon relative to the current page so paths resolve
        try {
            const sel = window.SELECTED_PRINCIPAL;
            let file;
            if (sel && sel.label && String(sel.label).toLowerCase() === String(d.label || '').toLowerCase()) {
                const kind = sel.kind || d.type;
                file = NODE_ICON_FILES[kind] || NODE_ICON_FILES[d.type] || 'acl.png';
            } else {
                file = NODE_ICON_FILES[d.type] || NODE_ICON_FILES.object || 'acl.png';
            }
            // icons live under Main/assets/Icons — use URL() to resolve correctly from any page location
            return new URL(`../../assets/Icons/${file}`, window.location.href).href;
        } catch (e) {
            return new URL('../../assets/favicon.png', window.location.href).href;
        }
    }

    // Render image icons centered on node
    node.append('image')
        .attr('class', 'node-icon-img')
        .attr('width', d => getNodeIconSize(d))
        .attr('height', d => getNodeIconSize(d))
        .attr('x', d => -getNodeIconSize(d) / 2)
        .attr('y', d => -getNodeIconSize(d) / 2)
        .attr('pointer-events', 'none')
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .each(function(d) {
            // set both href and xlink:href for broader compatibility
            const href = getNodeIconHref(d);
            d3.select(this).attr('href', href).attr('xlink:href', href);
        })
        .on('error', function(event, d) {
            const fb = new URL('../../assets/favicon.png', window.location.href).href;
            d3.select(this).attr('href', fb).attr('xlink:href', fb);
        });

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
        .attr('font-weight', '200')
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

        // Update path d attribute; use quadratic curve for parallel links
        linkLine.attr('d', d => {
            const p = getTrimmedLinkPoints(d);
            const sx = p.x1, sy = p.y1, tx = p.x2, ty = p.y2;
            if (!d.parallelTotal || d.parallelTotal <= 1) {
                return `M ${sx} ${sy} L ${tx} ${ty}`;
            }
            const dx = tx - sx, dy = ty - sy;
            const nx = -dy, ny = dx; // perpendicular
            const nlen = Math.hypot(nx, ny) || 1;
            const ux = nx / nlen, uy = ny / nlen;
            const gap = Math.max(24, getEdgeWidth(d) * 10);
            // center offset so arcs are symmetrically placed
            const midIndex = (d.parallelTotal - 1) / 2;
            const offset = (d.parallelIndex - midIndex) * gap;
            const cx = (sx + tx) / 2 + ux * offset;
            const cy = (sy + ty) / 2 + uy * offset;
            return `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`;
        });

        linkHitLine.attr('d', d => {
            const p = getTrimmedLinkPoints(d);
            const sx = p.x1, sy = p.y1, tx = p.x2, ty = p.y2;
            if (!d.parallelTotal || d.parallelTotal <= 1) return `M ${sx} ${sy} L ${tx} ${ty}`;
            const dx = tx - sx, dy = ty - sy;
            const nx = -dy, ny = dx;
            const nlen = Math.hypot(nx, ny) || 1;
            const ux = nx / nlen, uy = ny / nlen;
            const gap = Math.max(24, getEdgeWidth(d) * 10);
            const midIndex = (d.parallelTotal - 1) / 2;
            const offset = (d.parallelIndex - midIndex) * gap;
            const cx = (sx + tx) / 2 + ux * offset;
            const cy = (sy + ty) / 2 + uy * offset;
            return `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`;
        });

        // Position label at curve midpoint (t=0.5) for quadratic curve
        linkLabel
            .attr('x', d => {
                const p = getTrimmedLinkPoints(d);
                const sx = p.x1, sy = p.y1, tx = p.x2, ty = p.y2;
                if (!d.parallelTotal || d.parallelTotal <= 1) return (sx + tx) / 2;
                const dx = tx - sx, dy = ty - sy;
                const nx = -dy, ny = dx;
                const nlen = Math.hypot(nx, ny) || 1;
                const ux = nx / nlen, uy = ny / nlen;
                const gap = Math.max(24, getEdgeWidth(d) * 10);
                const midIndex = (d.parallelTotal - 1) / 2;
                const offset = (d.parallelIndex - midIndex) * gap;
                const cx = (sx + tx) / 2 + ux * offset;
                // quadratic midpoint at t=0.5
                const mx = 0.25 * sx + 0.5 * cx + 0.25 * tx;
                return mx;
            })
            .attr('y', d => {
                const p = getTrimmedLinkPoints(d);
                const sx = p.x1, sy = p.y1, tx = p.x2, ty = p.y2;
                if (!d.parallelTotal || d.parallelTotal <= 1) return (sy + ty) / 2;
                const dx = tx - sx, dy = ty - sy;
                const nx = -dy, ny = dx;
                const nlen = Math.hypot(nx, ny) || 1;
                const ux = nx / nlen, uy = ny / nlen;
                const gap = Math.max(24, getEdgeWidth(d) * 10);
                const midIndex = (d.parallelTotal - 1) / 2;
                const offset = (d.parallelIndex - midIndex) * gap;
                const cx = (sx + tx) / 2 + ux * offset;
                const my = 0.25 * sy + 0.5 * cx * 0 + 0.5 * cx * 0 + 0.25 * ty; // keep fallback
                // compute quadratic midpoint y properly
                const my2 = 0.25 * sy + 0.5 * cx * 0 + 0.25 * ty; // simplified; use cy below
                const myFinal = 0.25 * sy + 0.5 * ((sy + ty) / 2 + uy * offset) + 0.25 * ty;
                return myFinal;
            });

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Avtomatik fit deaktiv - sadəcə fit düyməsi istifadə olunacaq
    // simulation.on('end', fitGraph);
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
    d.fx = d.x;
    d.fy = d.y;
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
    // Graph focus (highlight chain in graph)
    applyGraphFocusToNode(d);

    // Right panel: render node chain from root to clicked node
    if (typeof window.renderNodeChainPanel === 'function') {
        window.renderNodeChainPanel(d);
    }

    evt?.stopPropagation?.();
}

function applyGraphFocusToNode(nodeData) {
    if (!node || !linkLine) return;

    const focus = buildGraphFocusFromNode(nodeData);
    const hasFocus = focus.nodeNames.size > 0;
    currentGraphFocus = {
        active: hasFocus,
        nodeNames: focus.nodeNames,
        linkPairs: focus.linkPairs
    };

    if (!hasFocus) {
        resetHighlight();
        return;
    }

    node
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => focus.nodeNames.has(normalizeGraphName(d.label || d.id)) ? 1 : 0.14)
        .style('filter', d => focus.nodeNames.has(normalizeGraphName(d.label || d.id))
            ? 'none'
            : 'grayscale(1) brightness(0.72) saturate(0.2)')
        .select('circle.node-circle')
        .attr('stroke-width', d => d.root
            ? NODE_RULES.highlight.inactiveStrokeWidth
            : (focus.nodeNames.has(normalizeGraphName(d.label || d.id))
            ? NODE_RULES.highlight.activeStrokeWidth
            : NODE_RULES.highlight.inactiveStrokeWidth));

    linkLine
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? 1 : 0.10;
        })
        .attr('stroke', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? getEdgeStroke(d) : 'rgba(148, 163, 184, 0.7)';
        });

    linkLabel
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? 0.9 : 0.04;
        })
        .attr('fill', d => {
            const sourceName = getNodeNameFromLinkEndpoint(d.source);
            const targetName = getNodeNameFromLinkEndpoint(d.target);
            const pairKey = makeLinkPairKey(sourceName, targetName);
            return focus.linkPairs.has(pairKey) ? getEdgeLabelColor(d) : '#94a3b8';
        });
}

function clickEdge(evt, d) {
    const relatedPath = findRelatedPathForEdge(d);
    if (relatedPath?.path) {
        const cards = document.querySelectorAll('.path-card');
        cards.forEach(c => {
            if (c.dataset.id === relatedPath.path.id) {
                selectPath(relatedPath.path, c);
                c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        });
    }

    evt?.stopPropagation?.();
}

function findRelatedPathsForNode(nodeData) {
    const label = String(nodeData?.label || nodeData?.id || '').toLowerCase();
    if (!label) return [];

    const matches = [];

    for (const path of ATTACK_PATHS) {
        const hopIndex = path.hops.findIndex(h => h.name && h.name.toLowerCase() === label);
        if (hopIndex === -1) continue;

        const edgeNames = [];
        const prevEdge = hopIndex > 0 ? path.hops[hopIndex - 1] : null;
        const nextEdge = hopIndex + 1 < path.hops.length ? path.hops[hopIndex + 1] : null;

        if (prevEdge?.edge) edgeNames.push(prevEdge.edge);
        if (nextEdge?.edge && nextEdge.edge !== prevEdge?.edge) edgeNames.push(nextEdge.edge);

        matches.push({
            path,
            edgeNames,
            nodeIndex: hopIndex
        });
    }

    return matches;
}

function buildRiskDistributionEntriesToNode(path, nodeIndex) {
    if (!path || !Array.isArray(path.hops) || nodeIndex < 0) return [];

    const entries = [];
    let step = 1;

    for (let i = 0; i < nodeIndex; i += 2) {
        const sourceNode = path.hops[i];
        const edgeHop = path.hops[i + 1];
        const targetNode = path.hops[i + 2];
        if (!sourceNode?.name || !edgeHop?.edge || !targetNode?.name) continue;

        entries.push({
            name: edgeHop.edge,
            source: sourceNode.name,
            target: targetNode.name,
            meta: `${sourceNode.name} → ${targetNode.name}`,
            step,
            nodeName: targetNode.name
        });
        step++;

        if (i + 2 >= nodeIndex) break;
    }

    return entries;
}

function collectConnectedEdges(nodeData) {
    const nodeLabel = String(nodeData?.label || nodeData?.id || '').toLowerCase();
    if (!nodeLabel || !Array.isArray(GRAPH_DATA?.links)) return [];

    const edges = [];
    const seen = new Set();

    GRAPH_DATA.links.forEach(link => {
        const sourceLabel = String(link.source?.label || link.source?.id || link.source || '').toLowerCase();
        const targetLabel = String(link.target?.label || link.target?.id || link.target || '').toLowerCase();
        const rel = String(link.rel || 'RELATION');

        if (sourceLabel !== nodeLabel && targetLabel !== nodeLabel) return;

        const key = `${sourceLabel}->${rel}->${targetLabel}`;
        if (seen.has(key)) return;
        seen.add(key);

        edges.push({
            name: rel,
            source: link.source?.label || link.source?.id || link.source || '',
            target: link.target?.label || link.target?.id || link.target || '',
            meta: `${link.source?.label || link.source?.id || link.source || 'Unknown'} → ${link.target?.label || link.target?.id || link.target || 'Unknown'}`
        });
    });

    return edges;
}

function findRelatedPathForEdge(edgeData) {
    const sourceLabel = String(edgeData?.source?.label || edgeData?.source?.id || '').toLowerCase();
    const targetLabel = String(edgeData?.target?.label || edgeData?.target?.id || '').toLowerCase();
    const rel = String(edgeData?.rel || '').toLowerCase();

    if (!sourceLabel && !targetLabel) return null;

    for (const path of ATTACK_PATHS) {
        for (let i = 0; i < path.hops.length - 2; i++) {
            const current = path.hops[i];
            const edgeHop = path.hops[i + 1];
            const next = path.hops[i + 2];
            if (!current?.name || !next?.name || !edgeHop) continue;
            const matchesSource = !sourceLabel || current.name.toLowerCase() === sourceLabel;
            const matchesTarget = !targetLabel || next.name.toLowerCase() === targetLabel;
            const matchesRel = !rel || String(edgeHop.edge || '').toLowerCase() === rel;
            if (matchesSource && matchesTarget && matchesRel) {
                return {
                    path,
                    match: {
                        source: current.name,
                        rel: edgeHop.edge || edgeData?.rel || 'RELATION',
                        target: next.name
                    }
                };
            }
        }
    }

    return null;
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
    currentGraphFocus = {
        active: false,
        nodeNames: new Set(),
        linkPairs: new Set()
    };
    node
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', 1)
        .style('filter', 'none')
        .selectAll('circle')
        .attr('opacity', 1);
    node.select('.node-circle')
        .attr('stroke-width', NODE_RULES.highlight.inactiveStrokeWidth);
    linkLine
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', EDGE_RULES.opacity.default)
        .attr('stroke-width', d => getEdgeWidth(d))
        .attr('stroke', d => getEdgeStroke(d));
    linkLabel
        .transition()
        .duration(GRAPH_FOCUS_FADE_MS)
        .ease(d3.easeCubicOut)
        .attr('opacity', 0)
        .attr('fill', d => getEdgeLabelColor(d));
}

function updateScaleDisplay(pct) {
    const slider  = document.getElementById('scale-slider');
    const display = document.getElementById('scale-display');
    slider.value  = Math.max(0.1, Math.min(300, pct));
    display.textContent = pct.toFixed(1) + '%';
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
    const storedAttrsRaw = sessionStorage.getItem('selectedRootPrincipalAttrs') || '';
    let storedAttrs = null;
    if (storedAttrsRaw) {
        try {
            storedAttrs = JSON.parse(storedAttrsRaw);
        } catch (err) {
            storedAttrs = null;
        }
    }

    const selected = runtimeSelected || (storedName ? {
        label: storedName,
        kind: storedType,
        sid: storedSid,
        target_attributes: storedAttrs
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
    // Extract target_attributes for the selected principal from graph_objects
    let selectedAttributes = null;
    if (engineData?.graph_objects && Array.isArray(engineData.graph_objects)) {
        const matchingRecord = engineData.graph_objects.find(record => {
            // Match by SID if available
            if (selected?.sid && record?.target_sid === selected.sid) return true;
            // Match by name
            if (selected?.label && record?.target_name === selected.label) return true;
            // Match by principal SID as fallback
            if (selected?.sid && record?.principal_sid === selected.sid) return true;
            return false;
        });
        if (matchingRecord?.target_attributes) {
            selectedAttributes = matchingRecord.target_attributes;
        }
    }

    const rootAttributes = selected?.target_attributes ?? selectedAttributes ?? null;

    const rootNode = {
        id: selected.sid || selected.label,
        label: selected.label,
        type: selected.kind === 'computer' ? 'computer' : 'user',
        sid: selected.sid || '',
        depth: 0,
        edges: 0,
        root: true,
        risk: 0,
        target_attributes: rootAttributes
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
        } else {
            // If node already exists but this record has target_attributes and the node doesn't, update it
            const existingNode = seenNodes.get(nodeKey);
            if (record?.target_attributes && !existingNode.target_attributes) {
                existingNode.target_attributes = record.target_attributes;
            }
        }
        return seenNodes.get(nodeKey);
    }

    function addEdge(sourceId, targetId, record) {
        const edgeRights = Array.isArray(record?.edge_rights)
            ? record.edge_rights.filter(Boolean)
            : (Array.isArray(record?.rights) ? record.rights.filter(Boolean) : []);

        // If multiple rights, create one link per right so each is rendered separately
        const rightsToUse = edgeRights.length ? edgeRights : (edgeLabel(record) ? [edgeLabel(record)] : ['ACE']);

        for (const r of rightsToUse) {
            const key = `${String(sourceId).toLowerCase()}->${String(targetId).toLowerCase()}::${String(r).toLowerCase()}`;
            if (seenLinks.has(key)) continue;
            seenLinks.add(key);
            const crit = typeof getEdgeCategory === 'function'
                ? getEdgeCategory({ crit: false, edge_rights: [r] }) === 'critical'
                : false;
            links.push({
                source: sourceId,
                target: targetId,
                rel: r,
                crit,
                edge_rights: [r],
                // parallel properties will be assigned after all links are collected
                parallelIndex: 0,
                parallelTotal: 1
            });
        }
    }

    function walkRecord(record, parentNode, depth) {
        if (!record || typeof record !== 'object') return;

        // Ensure principal node exists so we can attach principal_attributes
        if (record.principal_sid) {
            const principalRec = {
                target_sid: record.principal_sid,
                target_name: record.principal_name || record.principal_sid,
                target_type: (record.principal_type || 'User')
            };
            const principalNode = ensureNode(
                principalRec,
                `node-${nodes.length}`,
                principalRec.target_name,
                principalRec.target_type || 'user',
                Math.max(0, depth - 1)
            );
            // Merge principal_attributes into node.target_attributes (if present)
            if (record.principal_attributes) {
                try {
                    // If node has no target_attributes, copy principal attrs directly
                    if (!principalNode.target_attributes) {
                        principalNode.target_attributes = record.principal_attributes;
                    } else if (typeof principalNode.target_attributes === 'object' && !Array.isArray(principalNode.target_attributes)) {
                        // Merge keys from principal_attributes into target_attributes without overwriting
                        const src = record.principal_attributes;
                        if (src && typeof src === 'object' && !Array.isArray(src)) {
                            for (const k of Object.keys(src)) {
                                if (!(k in principalNode.target_attributes)) {
                                    principalNode.target_attributes[k] = src[k];
                                }
                            }
                        }
                    }
                } catch (e) {
                    // No-op on merge errors
                    console.warn('Failed to merge principal_attributes:', e && e.message);
                }
            }
        }

        const targetNode = ensureNode(
            record,
            `target-${nodes.length}`,
            record.target_name || record.target_dn || `target-${nodes.length}`,
            record.target_type || 'object',
            depth
        );

        // If record carries principal_attributes (old engine output), merge
        // them into the target node's target_attributes so highlighting
        // logic (which looks at target_attributes) works without rebuilding
        // the C++ engine.
        if (record.principal_attributes) {
            try {
                if (!targetNode.target_attributes) {
                    targetNode.target_attributes = record.principal_attributes;
                } else if (typeof targetNode.target_attributes === 'object' && !Array.isArray(targetNode.target_attributes)) {
                    const src = record.principal_attributes;
                    if (src && typeof src === 'object' && !Array.isArray(src)) {
                        for (const k of Object.keys(src)) {
                            if (!(k in targetNode.target_attributes)) {
                                targetNode.target_attributes[k] = src[k];
                            }
                        }
                    }
                }
            } catch (e) {
                console.warn('Failed to merge record.principal_attributes into target node:', e && e.message);
            }
        }

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

    // Compute parallel link counts for same source->target so we can render arcs
    const buckets = new Map(); // key: source::target -> [indexes]
    links.forEach((l, idx) => {
        const s = String(l.source).toLowerCase();
        const t = String(l.target).toLowerCase();
        const k = `${s}::${t}`;
        if (!buckets.has(k)) buckets.set(k, []);
        buckets.get(k).push(idx);
    });
    for (const [k, idxs] of buckets.entries()) {
        const total = idxs.length;
        for (let i = 0; i < idxs.length; ++i) {
            const li = links[idxs[i]];
            li.parallelTotal = total;
            li.parallelIndex = i; // 0..total-1
        }
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