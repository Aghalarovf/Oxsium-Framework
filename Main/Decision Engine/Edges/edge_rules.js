const EDGE_RULES = {

    colors: {
        blue: {
            stroke:       'rgba(56, 189, 248, 0.75)',
            strokeActive: 'rgba(56, 189, 248, 1.0)',
            arrowFill:    '#38bdf8',
            labelFill:    '#38bdf8'
        },
        critical: {
            stroke:       'rgba(239, 68, 68, 0.75)',   
            strokeActive: 'rgba(239, 68, 68, 1.0)',
            arrowFill:    '#ef4444',
            labelFill:    '#f87171'
        },
        high: {
            stroke:       'rgba(249, 115, 22, 0.75)', 
            strokeActive: 'rgba(249, 115, 22, 1.0)',
            arrowFill:    '#f97316',
            labelFill:    '#fb923c'
        },
        special: {
            stroke:       'rgba(234, 179, 8, 0.75)',
            strokeActive: 'rgba(234, 179, 8, 1.0)',
            arrowFill:    '#eab308',
            labelFill:    '#facc15'
        },
        normal: {
            stroke:       'rgba(51, 65, 85, 0.6)',     
            strokeActive: 'rgba(100, 116, 139, 0.9)',
            arrowFill:    '#334155',
            labelFill:    '#64748b'
        }
    },

    width: {
        blue:    3,
        critical: 3,     
        high:     3,
        special:  3,
        normal:   3,
        highlighted: 3,
        dimmed:      3
    },

    opacity: {
        default:     0.7,
        highlighted: 1.0,
        dimmed:      0.1
    },

    arrow: {
        viewBox:      '0 -5 10 10',
        path:         'M0,-5L10,0L0,5',
        refX:         38,          
        markerWidth:  6,
        markerHeight: 6,
        refXByType: {
            domain: 46,
            default: 38
        }
    },

    label: {
        fontSize:   '9px',
        fontFamily: 'JetBrains Mono, monospace',
        fontWeight: '400',
        opacity:    0.7,
        maxLength:  20,         
        showIfCritical: true,   
        showIfNormal: true      
    },

    force: {
        blue:     { distance: 200, strength: 0.40 },
        critical: { distance: 200, strength: 0.85 },
        high:     { distance: 200, strength: 0.65 },
        special:  { distance: 200, strength: 0.55 },
        normal:   { distance: 200, strength: 0.40 }
    },

    criticalRights: [
        'GenericAll',
        'WriteDACL',
        'WriteOwner',
        'All-Extended-Rights',
        'GenericWrite',
        'ForceChangePassword',
        'DS-Replication-Get-Changes',
        'DS-Replication-Get-Changes-All',
        'Read-gMSA-Password',
        'Write-msDS-KeyCredentialLink',
        'Write-msDS-AllowedToActOnBehalfOfOtherIdentity'
    ],

    highRights: [
        'WriteProperty',
        'Self',
        'CreateChild',
        'DeleteChild',
        'ReadLAPSPassword',
        'GetChangesAll',
        'Write-msDS-AllowedToDelegateTo',
        'Write-gPLink',
        'Write-gPOptions',
        'AddMember',
        'Self-Membership',
        'DS-Replication-Get-Changes-In-Filtered-Set'
    ],

    specialRights: [
        'WriteProperty',
        'Self',
        'Delete',
        'Validated-Write-SPN',
        'Send-As',
        'Receive-As',
        'Validated-DNS-Host-Name',
        'DS-Replication-Manage-Topology',
        'DS-Replication-Synchronize'
    ]
};

// UI overrides for specific extended-rights / object-type right names
// Ensure msDS-KeyCredentialLink is shown as "Shadow Credentials" in the graph
const EDGE_LABEL_OVERRIDES = {
    'write-msds-keycredentiallink': 'Shadow Credentials',
    'msds-keycredentiallink': 'Shadow Credentials',
    '5b47d60f-6051-40fb-99e0-ed3a78604e5d': 'Shadow Credentials'
};

function getEdgeCategory(d) {
    if (d.crit) return 'critical';
    const rights = Array.isArray(d.edge_rights) ? d.edge_rights : [];
    const rightsLower = rights.map(r => String(r).toLowerCase());
    if (rightsLower.some(r => r === 'kerberoastable' || r === 'asreproastable')) return 'blue';
    if (rights.some(r => EDGE_RULES.criticalRights.includes(r))) return 'critical';
    if (rights.some(r => EDGE_RULES.highRights.includes(r)))    return 'high';
    if (rights.some(r => EDGE_RULES.specialRights.includes(r)))  return 'special';
    return 'normal';
}

function getEdgeStroke(d) {
    return EDGE_RULES.colors[getEdgeCategory(d)].stroke;
}

function getEdgeWidth(d) {
    return EDGE_RULES.width[getEdgeCategory(d)];
}

function getEdgeMarker(d) {
    return `url(#arrow-${getEdgeCategory(d)})`;
}


function getEdgeLabelColor(d) {
    return EDGE_RULES.colors[getEdgeCategory(d)].labelFill || EDGE_RULES.colors[getEdgeCategory(d)].label_fill;
}

function getEdgeForce(d) {
    const force = EDGE_RULES.force[getEdgeCategory(d)];
    const sourceDegree = Number(d?.source?.edgeDegree || d?.source?.degree || 0);
    const targetDegree = Number(d?.target?.edgeDegree || d?.target?.degree || 0);
    const heavyNode = Math.max(sourceDegree, targetDegree) >= 10;

    if (!heavyNode) return force;

    return {
        distance: force.distance * 2,
        strength: force.strength
    };
}

function formatEdgeLabel(rel) {
    const max = EDGE_RULES.label.maxLength;
    if (!rel) return '';
    const key = String(rel).trim().toLowerCase();
    // Override key-credential related rights to a friendlier label
    if (key.includes('keycredential') || EDGE_LABEL_OVERRIDES[key]) {
        return EDGE_LABEL_OVERRIDES[key] || 'Shadow Credentials';
    }
    return rel.length > max ? rel.slice(0, max - 1) + '…' : rel;
}