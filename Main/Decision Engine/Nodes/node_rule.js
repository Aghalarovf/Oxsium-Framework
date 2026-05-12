const NODE_RULES = {
    colors: {
        domain: {
            fill:   '#7c3aed',   
            stroke: '#a78bfa',
            glow:   '#c4b5fd',
            label:  '#c4b5fd'
        },
        user: {
            fill:   '#0ea5e9',   
            stroke: '#38bdf8',
            glow:   '#7dd3fc',
            label:  '#38bdf8'
        },
        computer: {
            fill:   '#10b981',   
            stroke: '#34d399',
            glow:   '#6ee7b7',
            label:  '#34d399'
        },
        group: {
            fill:   '#8c00ff',  
            stroke: '#7a24fb',
            glow:   '#8d10fb',
            label:  '#7f00cd'
        },
        ou: {
            fill:   '#6366f1',  
            stroke: '#818cf8',
            glow:   '#a5b4fc',
            label:  '#818cf8'
        },
        gpo: {
            fill:   '#ec4899', 
            stroke: '#f472b6',
            glow:   '#fbcfe8',
            label:  '#f472b6'
        },
        container: {
            fill:   '#14b8a6',   
            stroke: '#2dd4bf',
            glow:   '#99f6e4',
            label:  '#2dd4bf'
        },
        object: {
            fill:   '#475569',  
            stroke: '#64748b',
            glow:   '#94a3b8',
            label:  '#64748b'
        },
        _riskOverride: {
            critical: { fill: '#ef4444', stroke: '#f87171', glow: '#fca5a5' },  // risk > 85
            high:     { fill: '#f97316', stroke: '#fb923c', glow: '#fdba74' },  // risk > 70
            medium:   { fill: '#eab308', stroke: '#facc15', glow: '#fde047' }   // risk > 50
        }
    },

    radius: {
        domain:   35,   
        byRisk: [
            { minRisk: 85, radius: 25 },   
            { minRisk: 70, radius: 25 },   
            { minRisk: 50, radius: 25 },   
        ],
        default:  25    
    },

    glowRing: {
        showForTypes: ['domain'],  
        showIfRiskAbove: 85,       
        ringOffset: 8,             
        strokeWidth: 1,
        strokeDash: '3 3',
        opacity: 0.4
    },

    label: {
        fontSize: '10px',
        fontWeight: '200',
        fontFamily: 'JetBrains Mono, monospace',
        yOffsetBelowNode: 20,   
        maxLength: 24,
        defaultColor: '#ffffff', // saf beyaz label rəngi
        riskText: {
            showIfRiskAbove: 70,
            fontSize: '9px',
            fontWeight: '600',
            fill: '#ffffff'
        }
    },

    highlight: {
        activeOpacity:   1.0,
        inactiveOpacity: 0.25,
        activeStrokeWidth:   2.5,
        inactiveStrokeWidth: 1.5
    },

    root: {
        extraRingOffset: 14,
        extraRingStroke: '#0ea5e9',
        extraRingDash:   '5 3',
        extraRingOpacity: 0
    },

    adminHighlight: {
        fill:           '#ea580c',   
        stroke:         '#f97316',
        glow:           '#fdba74',
        label:          '#f97316',
        ringOffset:     11,
        ringStrokeWidth: 2,
        ringOpacity:    0.7,
        ringDash:       '2 2'
    },

    potentialAdminHighlight: {
        fill:           '#eab308',  
        stroke:         '#facc15',
        glow:           '#fde047',
        label:          '#facc15',
        ringOffset:     11,
        ringStrokeWidth: 2,
        ringOpacity:    0.6,
        ringDash:       '3 3'
    }
};

// Muted highlight variants for disabled+admin/potential_admin
NODE_RULES.adminMuted = {
    fill: '#e8a86a', stroke: '#d4904f', glow: '#c07d42', label: '#cc8f58'
};
NODE_RULES.potentialAdminMuted = {
    fill: '#fff1bf', stroke: '#fde68a', glow: '#fff7d6', label: '#fde68a'
};
NODE_RULES.disabledColor = { fill: '#9ca3af', stroke: '#6b7280', glow: '#cbd5e1', label: '#6b7280' };

function getNodeColor(d) {
    const risk = d.risk || 0;
    const override = NODE_RULES.colors._riskOverride;

    if (risk > 85) return override.critical;
    if (risk > 70) return override.high;
    if (risk > 50 && d.type !== 'domain') return override.medium;

    return NODE_RULES.colors[d.type] || NODE_RULES.colors.object;
}

function getNodeRadius(d) {
    if (d.type === 'domain') return NODE_RULES.radius.domain;
    const risk = d.risk || 0;
    for (const rule of NODE_RULES.radius.byRisk) {
        if (risk > rule.minRisk) return rule.radius;
    }
    return NODE_RULES.radius.default;
}

function shouldShowGlowRing(d) {
    return NODE_RULES.glowRing.showForTypes.includes(d.type)
        || (d.risk || 0) > NODE_RULES.glowRing.showIfRiskAbove;
}

function formatNodeLabel(label) {
    const max = NODE_RULES.label.maxLength;
    if (!label) return '';
    return label.length > max ? label.slice(0, max - 1) + '…' : label;
}

function isTruthyAttrValue(v) {
    if (v === true) return true;
    if (typeof v === 'string') return v.toLowerCase() === 'true';
    if (typeof v === 'number') return v === 1;
    if (v && typeof v === 'object') {
        if (v.type === 'Bool') return v.b === true;
        if (v.type === 'String' && typeof v.s === 'string') return v.s.toLowerCase() === 'true';
        if (v.type === 'Number') return Number(v.n) === 1;
    }
    return false;
}

function hasAttrTrue(attrs, key) {
    if (!attrs) return false;
    if (!Array.isArray(attrs) && typeof attrs === 'object') {
        return isTruthyAttrValue(attrs[key]);
    }
    if (Array.isArray(attrs)) {
        for (const [k, v] of attrs) {
            if (k === key && isTruthyAttrValue(v)) return true;
        }
    }
    return false;
}

function getCombinedNodeAttributes(d) {
    return [d?.target_attributes, d?.principal_attributes].filter(Boolean);
}

function shouldHighlightAsAdmin(d) {
    if (!d || d.type !== 'user') return false;
    const attrsList = getCombinedNodeAttributes(d);
    return attrsList.some(attrs => hasAttrTrue(attrs, 'is_admin'));
}

function getAdminNodeColor() {
    return NODE_RULES.adminHighlight;
}

function shouldHighlightAsPotentialAdmin(d) {
    if (!d || d.type !== 'user') return false;
    if (shouldHighlightAsAdmin(d)) return false;
    const attrsList = getCombinedNodeAttributes(d);
    return attrsList.some(attrs => hasAttrTrue(attrs, 'potential_admin'));
}

function getPotentialAdminNodeColor() {
    return NODE_RULES.potentialAdminHighlight;
}


function getNodeHighlightColor(d) {
    if (!d) return null;
    const attrsList = getCombinedNodeAttributes(d);
    let isAdmin = false, isPotential = false, isDisabled = false;
    for (const attrs of attrsList) {
        if (hasAttrTrue(attrs, 'disabled')) isDisabled = true;
        if (d.type === 'user' && hasAttrTrue(attrs, 'is_admin')) isAdmin = true;
        if (d.type === 'user' && hasAttrTrue(attrs, 'potential_admin')) isPotential = true;
    }

    // If disabled=true exists in target_attributes or principal_attributes,
    // force gray regardless of node type.
    if (isDisabled) return NODE_RULES.disabledColor;

    if (isAdmin) {
        return getAdminNodeColor();
    }
    if (isPotential) {
        return getPotentialAdminNodeColor();
    }
    return null;
}


function getNodeFillColor(d) {
    const highlightColor = getNodeHighlightColor(d);
    return highlightColor ? highlightColor.fill : (getNodeColor(d).fill || '#1e293b');
}


function getNodeStrokeColor(d) {
    const highlightColor = getNodeHighlightColor(d);
    return highlightColor ? highlightColor.stroke : (getNodeColor(d).stroke || '#64748b');
}


function getNodeGlowColor(d) {
    const highlightColor = getNodeHighlightColor(d);
    return highlightColor ? highlightColor.glow : (getNodeColor(d).stroke || '#64748b');
}


function getNodeLabelColor(d) {
    const highlightColor = getNodeHighlightColor(d);
    return highlightColor ? highlightColor.label : NODE_RULES.label.defaultColor;
}

NODE_RULES.offsets = {
    outerRing: { root: 15, normal: 8 },
    rootExtra: 30,
    labelTypeOffset: 35,
    collisionPadding: 0,  
    iconScale: 0.85,
        iconScale: 1.25,
    outerRingOpacity: { root: 0.75, normal: 0.55 },
    nodeOpacity: 0.95,
    edgePadding: { source: 0, target: 0 },
    edgeExtraOffset: 4  // xarici halqa dışında kenarlar için ekstra padding
};

function getNodeOuterRadius(d) {
    return getNodeRadius(d) + (d && d.root ? NODE_RULES.offsets.outerRing.root : NODE_RULES.offsets.outerRing.normal);
}

function getNodeRootExtraRadius(d) {
    return getNodeRadius(d) + NODE_RULES.offsets.rootExtra;
}

function getNodeOuterStyle(d) {
    if (d && d.root) {
        return {
            stroke: NODE_RULES.root.extraRingStroke,
            strokeWidth: NODE_RULES.highlight.activeStrokeWidth || 2.5,
            opacity: NODE_RULES.offsets.outerRingOpacity.root,
            dash: NODE_RULES.root.extraRingDash || NODE_RULES.glowRing.strokeDash
        };
    }
    return {
        stroke: getNodeGlowColor(d),
        strokeWidth: NODE_RULES.highlight.inactiveStrokeWidth || 1.5,
        opacity: NODE_RULES.offsets.outerRingOpacity.normal,
        dash: NODE_RULES.glowRing.strokeDash
    };
}

function getNodeRootExtraStyle(d) {
    return {
        stroke: NODE_RULES.root.extraRingStroke,
        strokeWidth: NODE_RULES.highlight.inactiveStrokeWidth || 1.5,
        dash: NODE_RULES.root.extraRingDash,
        opacity: NODE_RULES.root.extraRingOpacity
    };
}

function getNodeIconFontSize(d) {
    return `${Math.round(getNodeRadius(d) * NODE_RULES.offsets.iconScale)}px`;
}

function getNodeLabelDy(d) {
    return getNodeRadius(d) + NODE_RULES.label.yOffsetBelowNode;
}

function getNodeTypeLabelDy(d) {
    return getNodeRadius(d) + NODE_RULES.offsets.labelTypeOffset;
}

function getNodeCollisionRadius(d) {
    // Hitbox xarici halqaya qədər - heç bir edge keçə bilməz
    return getNodeOuterRadius(d);
}

function getNodeEdgePadding(d, isTarget = false) {
    // Kenarlar xarici halqa sınırından başlayıp, biraz daha dışında
    return getNodeOuterRadius(d) + (NODE_RULES.offsets.edgeExtraOffset || 4);
}

function getNodeTypeLabelColor(d) {
    return getNodeFillColor(d);
}

// Domain Controller (DC) animated highlight
NODE_RULES.dc = {
    // animation colors sequence: Sarı, narıncı, qırmızı, mavvi, göy, çəhrayı, bənövşəyi
    colors: ['#FBBF24', '#FB923C', '#EF4444', '#3B82F6', '#06B6D4', '#F472B6', '#8B5CF6'],
    animationName: 'dc-color-cycle',
    animationDuration: '6s',
    strokeWidth: 3,
    glowStdDeviation: 6
};

function shouldHighlightAsDomainController(d) {
    if (!d) return false;
    const attrs = d.target_attributes || d.principal_attributes || {};
    try {
        if (typeof attrs === 'object' && !Array.isArray(attrs)) return Boolean(attrs.is_domain_controller === true || attrs.is_domain_controller);
        if (Array.isArray(attrs)) {
            for (const [k, v] of attrs) {
                if (k === 'is_domain_controller' && (v === true || (v && v.type === 'Bool' && v.b === true))) return true;
            }
        }
    } catch (e) {
        return false;
    }
    return false;
}

function injectDcAnimationStyles() {
    if (typeof document === 'undefined') return;
    const id = 'dc-anim-styles';
    if (document.getElementById(id)) return;
    const colors = NODE_RULES.dc.colors;
    const frames = colors.map((c, i) => {
        const pct = Math.round((i / colors.length) * 100);
        return `${pct}%{ fill:${c}; stroke:${c}; }`;
    }).join('\n');
    const css = `@keyframes ${NODE_RULES.dc.animationName} {\n${frames}\n100%{ fill:${colors[0]}; stroke:${colors[0]}; }\n}\n` +
        `.is-domain-controller .node-circle{ animation:${NODE_RULES.dc.animationName} ${NODE_RULES.dc.animationDuration} linear infinite; filter:url(#glow); }\n` +
        `.is-domain-controller .node-outer-ring, .is-domain-controller .node-root-extra{ animation:${NODE_RULES.dc.animationName} ${NODE_RULES.dc.animationDuration} linear infinite; filter:url(#glow); }\n` +
        `.is-domain-controller .node-label, .is-domain-controller .node-type-label{ animation:${NODE_RULES.dc.animationName} ${NODE_RULES.dc.animationDuration} linear infinite; }\n` +
        `/* Force lighter font-weight for node labels in case font lacks light weight */\n` +
        `.node-label, .node-type-label { font-weight: 200 !important; font-family: "JetBrains Mono", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif !important; font-variation-settings: 'wght' 200 !important; }`;
    const style = document.createElement('style');
    style.id = id;
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
}