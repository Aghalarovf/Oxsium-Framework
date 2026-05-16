# ESC (ADCS Escalation) Vulnerability Detection
# ESC1 - ESC15 vulnerability checks and analysis

ESC_MODULES = {
    'ESC1': 'Misconfigured Certificate Templates (Template-allows-SAN)',
    'ESC2': 'Misconfigured Certificate Templates (Any-Purpose EKU)',
    'ESC3': 'Misconfigured Enrollment Agent Templates (Certificate Agent EKU)',
    'ESC4': 'Access Control Vulnerabilities (Certificate Templates ACL)',
    'ESC5': 'Vulnerable PKI Object Access Control (Other PKI Objects)',
    'ESC6': 'EDITF_ATTRIBUTESUBJECTALTNAME2',
    'ESC7': 'Vulnerable Certificate Authority Access Control',
    'ESC8': 'Web Enrollment NTLM Relay (NTLM Relay to /certsrv)',
    'ESC9': 'No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)',
    'ESC10': 'Weak Certificate Mapping (UPN-based / registry misconfiguration)',
    'ESC11': 'NTLM Relay to ICPR (RPC Endpoint Relay)',
    'ESC12': 'Shell Access to ADCS CA with YubiHSM',
    'ESC13': 'Issuance Policy with Privileged Group Linked',
    'ESC14': 'Weak Explicit Mapping (altSecurityIdentities abuse)',
    'ESC15': 'Arbitrary Application Policies (EKUwu — CVE-2024-49019)',
}

def get_esc_modules():
    """Returns list of all ESC vulnerability modules"""
    return ESC_MODULES
