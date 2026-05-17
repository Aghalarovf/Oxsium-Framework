"""
ESC1 checker entry point.

This module ties together LDAP discovery, template parsing, and ACL analysis
to determine whether a template is vulnerable to ESC1.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from .checker.acl_parser import ACLParser
from .checker.ldap_client import CAEntry, LDAPClient, LDAPConfig, TemplateEntry
from .checker.template_parser import TemplateParser

esc1_logger = logging.getLogger("certificate_service.esc1")


def _normalize_ca_server(ca_server: str) -> str:
    return ca_server.split("\\")[0].strip()


def _template_published_on(template: TemplateEntry, cas: Iterable[CAEntry]) -> list[str]:
    published_on: list[str] = []
    for ca in cas:
        if template.cn in ca.templates:
            published_on.append(ca.cn)
    return published_on


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    return value


def evaluate_esc1(
    domain: str,
    ca_server: str,
    username: str,
    password: str = "",
    templates: Optional[list[TemplateEntry]] = None,
    cas: Optional[list[CAEntry]] = None,
    ldap_port: int = 389,
) -> Dict[str, Any]:
    """Evaluate ESC1 using LDAP data and return a JSON-ready dictionary."""

    results: Dict[str, Any] = {
        "status": "disconnected",
        "domain": domain.lower().strip(),
        "ca_server": ca_server.strip(),
        "timestamp": datetime.now().isoformat(),
        "ca_list": [],
        "templates": [],
        "esc_findings": [],
        "statistics": {
            "total_cas": 0,
            "total_templates": 0,
            "vulnerable_templates": 0,
            "esc_count": {},
        },
    }

    ldap_client: Optional[LDAPClient] = None

    try:
        if templates is None or cas is None:
            ldap_client = LDAPClient(
                LDAPConfig(
                    host=_normalize_ca_server(ca_server),
                    domain=domain,
                    username=username,
                    password=password or "",
                    port=ldap_port,
                )
            )
            ldap_client.connect()
            cas = ldap_client.get_cas()
            templates = ldap_client.get_templates()

        cas = cas or []
        templates = templates or []

        template_parser = TemplateParser()
        acl_parser = ACLParser()
        findings: list[Dict[str, Any]] = []
        template_results: list[Dict[str, Any]] = []
        esc_count: dict[str, int] = {"ESC1": 0}

        for template in templates:
            published_on = _template_published_on(template, cas)
            template_analysis = template_parser.analyse(template, published_on=published_on)
            acl_analysis = acl_parser.parse(template.raw_sd)
            enroll_principals = acl_analysis.enroll_principals
            is_vulnerable = template_analysis.is_vulnerable and bool(enroll_principals)

            template_result = {
                "template_name": template_analysis.template_name,
                "display_name": template_analysis.display_name,
                "published_on": published_on,
                "conditions": [asdict(condition) for condition in template_analysis.conditions],
                "dangerous_ekus": template_analysis.dangerous_ekus,
                "acl": _serialize(acl_analysis),
                "is_vulnerable": is_vulnerable,
                "risk_notes": template_analysis.risk_notes,
                "name_flag": template_analysis.name_flag,
                "enrollment_flag": template_analysis.enrollment_flag,
                "ra_signature": template_analysis.ra_signature,
            }
            template_results.append(template_result)

            if is_vulnerable:
                findings.append(
                    {
                        "esc_type": "ESC1",
                        "template_name": template_analysis.template_name,
                        "display_name": template_analysis.display_name,
                        "severity": "CRITICAL",
                        "description": "ESC1 conditions met: enrollee-supplied subject, authentication EKU, no manager approval, and enroll rights.",
                        "recommendation": "Restrict template permissions, remove ENROLLEE_SUPPLIES_SUBJECT, and require manager approval.",
                        "published_on": published_on,
                        "conditions": [asdict(condition) for condition in template_analysis.conditions],
                        "acl": _serialize(acl_analysis),
                        "risk_notes": template_analysis.risk_notes,
                    }
                )
                esc_count["ESC1"] += 1

        results["status"] = "connected"
        results["ca_list"] = [
            {
                "name": ca.cn,
                "dns_name": ca.dns_hostname,
                "templates": ca.templates,
            }
            for ca in cas
        ]
        results["templates"] = template_results
        results["esc_findings"] = findings
        results["statistics"] = {
            "total_cas": len(cas),
            "total_templates": len(templates),
            "vulnerable_templates": len(findings),
            "esc_count": esc_count,
        }
        return results

    except Exception as exc:
        esc1_logger.error("[-] ESC1 evaluation failed: %s", exc)
        results["status"] = "error"
        results["error"] = str(exc)
        return results

    finally:
        if ldap_client is not None:
            ldap_client.disconnect()