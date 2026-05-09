from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
import json

@dataclass
class NodeColorScheme:
    fill:   str
    stroke: str
    glow:   str
    label:  str

@dataclass
class RadiusRule:
    min_risk: int
    radius:   int

NODE_COLORS: dict[str, NodeColorScheme] = {
    "domain": NodeColorScheme(
        fill="#7c3aed", stroke="#a78bfa", glow="#c4b5fd", label="#c4b5fd"
    ),
    "user": NodeColorScheme(
        fill="#0ea5e9", stroke="#38bdf8", glow="#7dd3fc", label="#38bdf8"
    ),
    "computer": NodeColorScheme(
        fill="#10b981", stroke="#34d399", glow="#6ee7b7", label="#34d399"
    ),
    "group": NodeColorScheme(
        fill="#f59e0b", stroke="#fbbf24", glow="#fde68a", label="#fbbf24"
    ),
    "ou": NodeColorScheme(
        fill="#6366f1", stroke="#818cf8", glow="#a5b4fc", label="#818cf8"
    ),
    "gpo": NodeColorScheme(
        fill="#ec4899", stroke="#f472b6", glow="#fbcfe8", label="#f472b6"
    ),
    "container": NodeColorScheme(
        fill="#14b8a6", stroke="#2dd4bf", glow="#99f6e4", label="#2dd4bf"
    ),
    "object": NodeColorScheme(
        fill="#475569", stroke="#64748b", glow="#94a3b8", label="#64748b"
    ),
}

RISK_OVERRIDE: dict[str, NodeColorScheme] = {
    "critical": NodeColorScheme(
        fill="#ef4444", stroke="#f87171", glow="#fca5a5", label="#f87171"
    ),
    "high": NodeColorScheme(
        fill="#f97316", stroke="#fb923c", glow="#fdba74", label="#fb923c"
    ),
    "medium": NodeColorScheme(
        fill="#eab308", stroke="#facc15", glow="#fde047", label="#facc15"
    ),
}

RADIUS_RULES: list[RadiusRule] = [
    RadiusRule(min_risk=85, radius=18),
    RadiusRule(min_risk=70, radius=15),
    RadiusRule(min_risk=50, radius=12),
]

RADIUS_DOMAIN:  int = 24
RADIUS_DEFAULT: int = 10

GLOW_RING_TYPES:    list[str] = ["domain"]
GLOW_RING_MIN_RISK: int       = 85

LABEL_MAX_LENGTH:     int = 24
RISK_TEXT_MIN_RISK:   int = 70

ADMIN_HIGHLIGHT: NodeColorScheme = NodeColorScheme(
    fill="#ea580c", stroke="#f97316", glow="#fdba74", label="#f97316"
)

POTENTIAL_ADMIN_HIGHLIGHT: NodeColorScheme = NodeColorScheme(
    fill="#eab308", stroke="#facc15", glow="#fde047", label="#facc15"
)


def get_node_color(node_type: str, risk: int = 0) -> NodeColorScheme:
    if risk > 85:
        return RISK_OVERRIDE["critical"]
    if risk > 70:
        return RISK_OVERRIDE["high"]
    if risk > 50 and node_type != "domain":
        return RISK_OVERRIDE["medium"]
    return NODE_COLORS.get(node_type, NODE_COLORS["object"])


def get_node_radius(node_type: str, risk: int = 0) -> int:
    if node_type == "domain":
        return RADIUS_DOMAIN
    for rule in RADIUS_RULES:
        if risk > rule.min_risk:
            return rule.radius
    return RADIUS_DEFAULT


def should_show_glow(node_type: str, risk: int = 0) -> bool:
    return node_type in GLOW_RING_TYPES or risk > GLOW_RING_MIN_RISK


def truncate_label(label: str) -> str:
    if not label:
        return ""
    return label if len(label) <= LABEL_MAX_LENGTH else label[: LABEL_MAX_LENGTH - 1] + "…"


def should_highlight_as_admin(node: dict) -> bool:
    if node.get("type") != "user":
        return False
    attrs = node.get("target_attributes")
    if not attrs:
        return False
    
    if isinstance(attrs, dict):
        return attrs.get("is_admin") is True
    
    if isinstance(attrs, list):
        for key, val in attrs:
            if key == "is_admin" and val is True:
                return True
    
    return False


def should_highlight_as_potential_admin(node: dict) -> bool:
    if node.get("type") != "user":
        return False
    if should_highlight_as_admin(node):
        return False
    attrs = node.get("target_attributes")
    if not attrs:
        return False
    
    if isinstance(attrs, dict):
        return attrs.get("potential_admin") is True
    
    if isinstance(attrs, list):
        for key, val in attrs:
            if key == "potential_admin" and val is True:
                return True
    
    return False


def enrich_node(node: dict) -> dict:
    node_type = str(node.get("type", "object")).lower()
    risk      = int(node.get("risk", 0))

    color = get_node_color(node_type, risk)
    node.update({
        "visual": {
            "fill":         color.fill,
            "stroke":       color.stroke,
            "glow":         color.glow,
            "labelColor":   color.label,
            "radius":       get_node_radius(node_type, risk),
            "glowRing":     should_show_glow(node_type, risk),
            "showRiskText": risk > RISK_TEXT_MIN_RISK,
        }
    })
    return node


def enrich_nodes(nodes: list[dict]) -> list[dict]:
    return [enrich_node(n) for n in nodes]


def get_node_colors_js() -> str:
    result = {}
    for key, scheme in NODE_COLORS.items():
        result[key] = asdict(scheme)
    return f"const NODE_COLORS = {json.dumps(result, indent=2)};"

if __name__ == "__main__":
    sample_nodes = [
        {"id": "s-1", "label": "CORP.LOCAL", "type": "domain", "risk": 0},
        {"id": "s-2", "label": "Administrator", "type": "user",   "risk": 92},
        {"id": "s-3", "label": "SQL-SRV-01",   "type": "computer","risk": 55},
        {"id": "s-4", "label": "Domain Admins", "type": "group",   "risk": 78},
    ]
    enriched = enrich_nodes(sample_nodes)
    print(json.dumps(enriched, indent=2, ensure_ascii=False))
    print("\n--- NODE_COLORS JS snippet ---")
    print(get_node_colors_js())