from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional
import json

@dataclass
class EdgeColorScheme:
    stroke:        str
    stroke_active: str
    arrow_fill:    str
    label_fill:    str

@dataclass
class EdgeForce:
    distance: int
    strength: float

@dataclass
class EdgeWidth:
    default:     float
    highlighted: float
    dimmed:      float

EDGE_COLORS: dict[str, EdgeColorScheme] = {
    "critical": EdgeColorScheme(
        stroke="rgba(239, 68, 68, 0.75)",
        stroke_active="rgba(239, 68, 68, 1.0)",
        arrow_fill="#ef4444",
        label_fill="#f87171"
    ),
    "high": EdgeColorScheme(
        stroke="rgba(249, 115, 22, 0.75)",
        stroke_active="rgba(249, 115, 22, 1.0)",
        arrow_fill="#f97316",
        label_fill="#fb923c"
    ),
    "normal": EdgeColorScheme(
        stroke="rgba(51, 65, 85, 0.6)",
        stroke_active="rgba(100, 116, 139, 0.9)",
        arrow_fill="#334155",
        label_fill="#64748b"
    ),
}

EDGE_WIDTHS: dict[str, float] = {
    "critical":    2.0,
    "high":        1.5,
    "normal":      1.0,
    "highlighted": 2.5,
    "dimmed":      0.8,
}

EDGE_FORCES: dict[str, EdgeForce] = {
    "critical": EdgeForce(distance=90,  strength=0.85),
    "high":     EdgeForce(distance=110, strength=0.65),
    "normal":   EdgeForce(distance=145, strength=0.40),
}

EDGE_OPACITY: dict[str, float] = {
    "default":     0.7,
    "highlighted": 1.0,
    "dimmed":      0.1,
}
CRITICAL_RIGHTS: frozenset[str] = frozenset({
    "GenericAll",
    "WriteDacl",
    "WriteOwner",
    "DCSync",
    "AllExtendedRights",
    "Owns",
    "GenericWrite",
    "ForceChangePassword",
    "AddMember",
})

HIGH_RIGHTS: frozenset[str] = frozenset({
    "WriteProperty",
    "Self",
    "CreateChild",
    "DeleteChild",
    "ReadLAPSPassword",
    "GetChangesAll",
})

EDGE_LABEL_MAX_LENGTH: int = 20


def get_edge_category(edge_rights: list[str], crit_flag: bool = False) -> str:
    if crit_flag:
        return "critical"
    rights_set = set(edge_rights or [])
    if rights_set & CRITICAL_RIGHTS:
        return "critical"
    if rights_set & HIGH_RIGHTS:
        return "high"
    return "normal"


def get_edge_color(edge_rights: list[str], crit_flag: bool = False) -> EdgeColorScheme:
    return EDGE_COLORS[get_edge_category(edge_rights, crit_flag)]


def get_edge_width(edge_rights: list[str], crit_flag: bool = False) -> float:
    return EDGE_WIDTHS[get_edge_category(edge_rights, crit_flag)]


def get_edge_force(edge_rights: list[str], crit_flag: bool = False) -> EdgeForce:
    return EDGE_FORCES[get_edge_category(edge_rights, crit_flag)]


def truncate_label(label: str) -> str:
    if not label:
        return ""
    return label if len(label) <= EDGE_LABEL_MAX_LENGTH else label[: EDGE_LABEL_MAX_LENGTH - 1] + "…"


def build_rights_display(edge_rights: list[str]) -> str:
    if not edge_rights:
        return "ACE"
    if len(edge_rights) == 1:
        return edge_rights[0]
    if len(edge_rights) <= 3:
        return ", ".join(edge_rights)
    return f"{', '.join(edge_rights[:2])} +{len(edge_rights) - 2}"


def enrich_edge(edge: dict) -> dict:
    rights   = list(edge.get("edge_rights", []))
    crit     = bool(edge.get("crit", False))
    category = get_edge_category(rights, crit)
    color    = EDGE_COLORS[category]
    force    = EDGE_FORCES[category]

    edge.update({
        "crit":           category == "critical",
        "category":       category,
        "rights_display": build_rights_display(rights),
        "visual": {
            "stroke":      color.stroke,
            "strokeWidth": EDGE_WIDTHS[category],
            "arrowFill":   color.arrow_fill,
            "labelFill":   color.label_fill,
            "opacity":     EDGE_OPACITY["default"],
            "distance":    force.distance,
            "strength":    force.strength,
        }
    })
    return edge


def enrich_edges(edges: list[dict]) -> list[dict]:
    return [enrich_edge(e) for e in edges]

if __name__ == "__main__":
    sample_edges = [
        {
            "source": "s-1", "target": "s-2",
            "edge_rights": ["GenericAll"], "crit": False
        },
        {
            "source": "s-2", "target": "s-3",
            "edge_rights": ["WriteProperty", "ReadLAPSPassword"], "crit": False
        },
        {
            "source": "s-3", "target": "s-4",
            "edge_rights": ["ReadProperty"], "crit": False
        },
    ]
    enriched = enrich_edges(sample_edges)
    print(json.dumps(enriched, indent=2, ensure_ascii=False))