"""
Oxsium Framework — Certificate Service Enumeration Module
Enumerates ADCS (Active Directory Certificate Services) for ESC vulnerabilities
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from threading import Lock

from flask import Flask, jsonify, request
from flask_cors import CORS

# ── Path setup ────────────────────────────────────────────────────────────────
_CERT_SERVICE_ROOT = Path(__file__).resolve().parents[1]  # /Main/Certificate Service
_MAIN_ROOT = Path(__file__).resolve().parents[2]  # /Main

for _path in (str(_CERT_SERVICE_ROOT), str(_MAIN_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# ── Imports ───────────────────────────────────────────────────────────────────
from ldap3 import Server, Connection, ALL, SUBTREE, BASE
from ldap3.core.exceptions import LDAPException

from connect.config import Config, logger
from connect.utils import domain_to_dn
from Modules.ESC1.esc1 import evaluate_esc1

# ── Logger setup ──────────────────────────────────────────────────────────────
cert_logger = logging.getLogger("certificate_service")
cert_logger.setLevel(logging.DEBUG)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

_SAVED_USERS_FILE = Path(__file__).resolve().parents[1] / "saved_users.json"
_SAVED_USERS_LOCK = Lock()


def _read_saved_users() -> list[dict[str, Any]]:
    if not _SAVED_USERS_FILE.exists():
        return []
    try:
        with _SAVED_USERS_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_saved_users(items: list[dict[str, Any]]) -> None:
    _SAVED_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _SAVED_USERS_FILE.open("w", encoding="utf-8") as handle:
        json.dump(items, handle, indent=2)


def _save_current_user(payload: Dict[str, Any]) -> Optional[dict[str, Any]]:
    domain = (payload.get("domain") or "").strip()
    ca_server = (payload.get("ca_server") or "").strip()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()

    if not domain or not ca_server or not username or not password:
        return None

    entry = {
        "domain": domain,
        "ca_server": ca_server,
        "username": username,
        "password": password,
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    with _SAVED_USERS_LOCK:
        users = _read_saved_users()
        dedup_key = (
            entry["domain"].lower(),
            entry["ca_server"].lower(),
            entry["username"].lower(),
            entry["password"],
        )

        filtered: list[dict[str, Any]] = []
        for item in users:
            item_key = (
                str(item.get("domain", "")).lower(),
                str(item.get("ca_server", "")).lower(),
                str(item.get("username", "")).lower(),
                str(item.get("password", "")),
            )
            if item_key != dedup_key:
                filtered.append(item)

        filtered.insert(0, entry)
        _write_saved_users(filtered)

    return entry


class CertificateServiceEnumerator:

    def __init__(self, domain: str, ca_server: str, username: str, password: str, 
                 ldap_port: int = 389):
        
        self.domain = domain.lower().strip()
        self.ca_server = ca_server.strip()
        self.username = username.strip()
        self.password = password
        self.ldap_port = ldap_port
        
        self.domain_dn = domain_to_dn(self.domain)
        self.ldap_connection = None
        self.enumeration_results = {
            "status": "disconnected",
            "domain": self.domain,
            "ca_server": self.ca_server,
            "timestamp": datetime.now().isoformat(),
            "ca_list": [],
            "templates": [],
            "esc_findings": [],
            "statistics": {
                "total_cas": 0,
                "total_templates": 0,
                "vulnerable_templates": 0,
                "esc_count": {}
            }
        }

    def _get_bind_dn(self) -> str:
        """Get proper bind DN based on domain and username"""
        return f"{self.username}@{self.domain}"

    def connect(self) -> bool:
        """
        Establish LDAP connection with provided credentials
        
        Returns:
            bool: True if connected successfully
        """
        try:
            # Normalize CA server (remove backslash if present)
            ldap_target = self.ca_server.split("\\")[0].strip()
            
            cert_logger.info(f"[*] Connecting to {ldap_target}:{self.ldap_port}")
            server = Server(ldap_target, port=self.ldap_port, get_info=ALL)
            
            bind_dn = self._get_bind_dn()
            
            cert_logger.info(f"[*] Authenticating with password")
            self.ldap_connection = Connection(
                server,
                user=bind_dn,
                password=self.password,
                authentication="SIMPLE",
                auto_bind=True,
                raise_exceptions=True
            )
            
            cert_logger.info(f"[+] Successfully connected to {ldap_target}")
            self.enumeration_results["status"] = "connected"
            return True
                
        except LDAPException as e:
            cert_logger.error(f"[-] LDAP connection error: {str(e)}")
            self.enumeration_results["status"] = "connection_error"
            return False
        except Exception as e:
            cert_logger.error(f"[-] Unexpected error during connection: {str(e)}")
            self.enumeration_results["status"] = "error"
            return False

    def enumerate_cas(self) -> List[Dict[str, Any]]:
        """
        Enumerate Certificate Authorities in the domain
        
        Returns:
            List of CA objects with details
        """
        if not self.ldap_connection:
            cert_logger.warn("[-] Not connected to LDAP")
            return []
        
        try:
            cert_logger.info("[*] Enumerating Certificate Authorities...")
            
            # Search for CA objects in CN=Certification Authorities
            ca_dn = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{self.domain_dn}"
            
            search_filter = "(objectClass=certificationAuthority)"
            
            self.ldap_connection.search(
                search_base=ca_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["cn", "name", "dNSHostName", "operatingSystem", "description"]
            )
            
            cas = []
            for entry in self.ldap_connection.entries:
                ca_obj = {
                    "name": str(entry.cn) if entry.cn else "Unknown",
                    "dns_name": str(entry.dNSHostName) if entry.dNSHostName else "",
                    "operating_system": str(entry.operatingSystem) if entry.operatingSystem else "",
                    "description": str(entry.description) if entry.description else "",
                    "dn": str(entry.entry_dn)
                }
                cas.append(ca_obj)
                cert_logger.info(f"[+] Found CA: {ca_obj['name']}")
            
            self.enumeration_results["ca_list"] = cas
            self.enumeration_results["statistics"]["total_cas"] = len(cas)
            return cas
            
        except LDAPException as e:
            cert_logger.error(f"[-] Error enumerating CAs: {str(e)}")
            return []
        except Exception as e:
            cert_logger.error(f"[-] Unexpected error: {str(e)}")
            return []

    def enumerate_certificate_templates(self) -> List[Dict[str, Any]]:
        """
        Enumerate Certificate Templates in the domain
        
        Returns:
            List of certificate template objects
        """
        if not self.ldap_connection:
            cert_logger.warn("[-] Not connected to LDAP")
            return []
        
        try:
            cert_logger.info("[*] Enumerating Certificate Templates...")
            
            # Search for certificate template objects
            templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.domain_dn}"
            
            search_filter = "(objectClass=pKICertificateTemplate)"
            
            self.ldap_connection.search(
                search_base=templates_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    "cn", "displayName", "msPKI-Cert-Template-OID", 
                    "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
                    "pKIExtendedKeyUsage", "pKIKeyUsage", "pKIMaxIssuingDepth",
                    "nTSecurityDescriptor", "description"
                ]
            )
            
            templates = []
            for entry in self.ldap_connection.entries:
                template_obj = {
                    "name": str(entry.cn) if entry.cn else "Unknown",
                    "display_name": str(entry.displayName) if entry.displayName else "",
                    "oid": str(entry['msPKI-Cert-Template-OID']) if 'msPKI-Cert-Template-OID' in entry else "",
                    "enrollment_flags": str(entry['msPKI-Enrollment-Flag']) if 'msPKI-Enrollment-Flag' in entry else "0",
                    "certificate_name_flags": str(entry['msPKI-Certificate-Name-Flag']) if 'msPKI-Certificate-Name-Flag' in entry else "0",
                    "extended_key_usage": [str(x) for x in entry['pKIExtendedKeyUsage']] if 'pKIExtendedKeyUsage' in entry else [],
                    "key_usage": [str(x) for x in entry['pKIKeyUsage']] if 'pKIKeyUsage' in entry else [],
                    "description": str(entry.description) if entry.description else "",
                    "dn": str(entry.entry_dn)
                }
                templates.append(template_obj)
                cert_logger.info(f"[+] Found Template: {template_obj['name']}")
            
            self.enumeration_results["templates"] = templates
            self.enumeration_results["statistics"]["total_templates"] = len(templates)
            return templates
            
        except LDAPException as e:
            cert_logger.error(f"[-] Error enumerating templates: {str(e)}")
            return []
        except Exception as e:
            cert_logger.error(f"[-] Unexpected error: {str(e)}")
            return []

    def check_esc_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Check for ESC (ADCS Escalation) vulnerabilities in enumerated data
        
        Returns:
            List of detected vulnerabilities
        """
        try:
            cert_logger.info("[*] Checking for ESC1 vulnerabilities...")

            esc1_results = evaluate_esc1(
                domain=self.domain,
                ca_server=self.ca_server,
                username=self.username,
                password=self.password,
            )

            findings = esc1_results.get("esc_findings", [])
            self.enumeration_results.update(esc1_results)

            return findings
            
        except Exception as e:
            cert_logger.error(f"[-] Error checking for ESC vulnerabilities: {str(e)}")
            return []

    def enumerate_all(self) -> Dict[str, Any]:
        """
        Run full enumeration: connect, discover CAs, templates, check vulnerabilities
        
        Returns:
            Complete enumeration results
        """
        esc1_results = evaluate_esc1(
            domain=self.domain,
            ca_server=self.ca_server,
            username=self.username,
            password=self.password,
        )

        self.enumeration_results.update(esc1_results)

        cert_logger.info(
            f"[+] Enumeration complete: {self.enumeration_results['statistics']['total_templates']} templates, "
            f"{len(self.enumeration_results['esc_findings'])} vulnerabilities found"
        )

        return self.enumeration_results

    def get_results_json(self) -> str:
        """Return enumeration results as JSON string"""
        return json.dumps(self.enumeration_results, indent=2, default=str)

    def close(self):
        """Close LDAP connection"""
        if self.ldap_connection:
            try:
                self.ldap_connection.unbind()
                cert_logger.info("[*] LDAP connection closed")
            except Exception as e:
                cert_logger.error(f"[-] Error closing connection: {str(e)}")


# ── API Function for Flask integration ────────────────────────────────────────
def enumerate_certificate_service(domain: str, ca_server: str, username: str, 
                                 password: str) -> Dict[str, Any]:
    """
    Main entry point for Certificate Service enumeration
    
    Args:
        domain: Target domain
        ca_server: CA server address
        username: Username
        password: Password
    
    Returns:
        Enumeration results dictionary
    """
    try:
        enumerator = CertificateServiceEnumerator(
            domain=domain,
            ca_server=ca_server,
            username=username,
            password=password,
        )
        
        results = enumerator.enumerate_all()
        enumerator.close()
        
        return results
    
    except Exception as e:
        cert_logger.error(f"[-] Error in certificate enumeration: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@app.route("/api/certificate/enumerate", methods=["POST"])
def api_certificate_enumerate():
    payload = request.get_json(silent=True) or {}
    _save_current_user(payload)
    results = enumerate_certificate_service(
        domain=payload.get("domain", ""),
        ca_server=payload.get("ca_server", ""),
        username=payload.get("username", ""),
        password=payload.get("password", ""),
    )
    status_code = 200 if results.get("status") == "connected" else 400
    return jsonify(results), status_code


@app.route("/api/esc1", methods=["POST"])
def api_esc1():
    payload = request.get_json(silent=True) or {}
    _save_current_user(payload)
    results = evaluate_esc1(
        domain=payload.get("domain", ""),
        ca_server=payload.get("ca_server", ""),
        username=payload.get("username", ""),
        password=payload.get("password", ""),
    )
    status_code = 200 if results.get("status") == "connected" else 400
    return jsonify(results), status_code


@app.route("/api/certificate/saved-users", methods=["GET", "POST"])
def api_certificate_saved_users():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        entry = _save_current_user(payload)
        if entry is None:
            return jsonify({"status": "error", "error": "Missing credential fields"}), 400
        return jsonify({"status": "saved", "entry": entry}), 200

    with _SAVED_USERS_LOCK:
        users = _read_saved_users()

    return jsonify({"status": "connected", "saved_users": users}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=True)
