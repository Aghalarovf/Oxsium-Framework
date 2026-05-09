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
        fontWeight: '500',
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

function shouldHighlightAsAdmin(d) {
    if (!d || d.type !== 'user') return false;
    const attrs = d.target_attributes;
    if (!attrs) return false;
    
    if (typeof attrs === 'object' && !Array.isArray(attrs)) {
        return attrs.is_admin === true;
    }
    
    if (Array.isArray(attrs)) {
        for (const [key, val] of attrs) {
            if (key === 'is_admin' && val === true) return true;
        }
    }
    return false;
}

function getAdminNodeColor() {
    return NODE_RULES.adminHighlight;
}

function shouldHighlightAsPotentialAdmin(d) {
    if (!d || d.type !== 'user') return false;
    if (shouldHighlightAsAdmin(d)) return false;
    const attrs = d.target_attributes;
    if (!attrs) return false;
    
    if (typeof attrs === 'object' && !Array.isArray(attrs)) {
        return attrs.potential_admin === true;
    }
    
    if (Array.isArray(attrs)) {
        for (const [key, val] of attrs) {
            if (key === 'potential_admin' && val === true) return true;
        }
    }
    return false;
}

function getPotentialAdminNodeColor() {
    return NODE_RULES.potentialAdminHighlight;
}


function getNodeHighlightColor(d) {
    if (shouldHighlightAsAdmin(d)) return getAdminNodeColor();
    if (shouldHighlightAsPotentialAdmin(d)) return getPotentialAdminNodeColor();
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