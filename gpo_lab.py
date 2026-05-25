#!/usr/bin/env python3
"""
GPO Lab Setup Script
====================
Creates a synthetic Active Directory GPO test laboratory that covers all 20
enumeration checks implemented in gpos_full.py.

The lab simulates:
  1.  GPO Link
  2.  Scope of Management
  3.  Inheritance
  4.  Enforcement
  5.  Block Inheritance
  6.  GPP Passwords / cPassword
  7.  Scheduled Tasks - RunAs
  8.  GPO Immediate Tasks
  9.  Restricted Groups
  10. Files & Scripts
  11. Registry Settings
  12. All .xml files
  13. GPP-decrypt (AES-256-CBC)
  14. Software Installation policies
  15. Software Installation policies
  16. Drive Mappings
  17. GPO Creator / Owner
  18. Description
  19. gPCFileSysPath
  20. SYSVOL ACL

Usage:
    python3 gpo_lab_setup.py --dc-ip 192.168.1.10 -d lab.local
    python3 gpo_lab_setup.py --dc-ip 192.168.1.10 -d lab.local --cleanup
    python3 gpo_lab_setup.py --offline          # no DC needed, local files only
"""

import argparse
import base64
import json
import os
import re
import shutil
import struct
import sys
import textwrap
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# Windows-da UTF-8 output üçün
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    # Windows-da ANSI rəng dəstəyi aktiv et
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
# OPTIONAL DEPENDENCIES  (imported lazily so --offline mode always works)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_REPLACE, SUBTREE
    from ldap3.core.exceptions import LDAPException
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
LAB_DIR        = Path("gpo_lab")
SYSVOL_DIR     = LAB_DIR / "SYSVOL"
REPORT_FILE    = LAB_DIR / "lab_report.json"
MANIFEST_FILE  = LAB_DIR / "manifest.json"

# Microsoft's public AES-256-CBC key for GPP encryption
GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])
GPP_AES_IV = b"\x00" * 16

# Well-known GPO GUIDs used in lab
GPO_GUIDS = {
    "Default_Domain_Policy":     "{31B2F340-016D-11D2-945F-00C04FB984F9}",
    "Default_DC_Policy":         "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
    "Workstation_Baseline":      "{AAAABBBB-1111-2222-3333-000000000001}",
    "Software_Deploy":           "{AAAABBBB-1111-2222-3333-000000000002}",
    "Scheduled_Tasks_GPO":       "{AAAABBBB-1111-2222-3333-000000000003}",
    "Drive_Mapping_GPO":         "{AAAABBBB-1111-2222-3333-000000000004}",
    "Registry_Settings_GPO":     "{AAAABBBB-1111-2222-3333-000000000005}",
    "Enforced_Security_GPO":     "{AAAABBBB-1111-2222-3333-000000000007}",
    "Inherited_Block_Test_GPO":  "{AAAABBBB-1111-2222-3333-000000000008}",
}

# Test credentials embedded in GPP (plaintext so you know what to expect)
LAB_CREDENTIALS = {
    "svc_backup":  "B@ckupP@ss2024!",
    "svc_deploy":  "D3pl0yS3cr3t#99",
    "svc_task":    "T@skRunAs!2024",
    "svc_drive":   "Dr1v3Map$Pass",
    "local_admin": "L0c@lAdm1n!Lab",
}

# ──────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# ──────────────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def info(msg): print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def warn(msg): print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):  print(f"  {C.RED}[-]{C.RESET} {msg}")
def section(title):
    print(f"\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")

# ──────────────────────────────────────────────────────────────────────────────
# GPP ENCRYPT  (so the lab files contain real cPassword values)
# ──────────────────────────────────────────────────────────────────────────────
def gpp_encrypt(plaintext: str) -> str:
    """
    Encrypts a plaintext password using Microsoft's GPP AES-256-CBC scheme.
    Requires pycryptodome.  Falls back to a pre-computed stub if unavailable.
    """
    if not HAS_PYCRYPTO:
        # Return a known-good stub so XML files are still valid
        warn("pycryptodome not found – using pre-computed cPassword stubs")
        return "RuiKVNbbp4HGLlMASIjGMBs3FQ3fSPZsTVmPxjEG1co="

    padded = plaintext.encode("utf-16-le")
    pad_len = 16 - (len(padded) % 16)
    padded += bytes([pad_len] * pad_len)
    cipher  = AES.new(GPP_AES_KEY, AES.MODE_CBC, GPP_AES_IV)
    return base64.b64encode(cipher.encrypt(padded)).decode()


def gpp_decrypt_verify(cpassword: str, expected: str) -> bool:
    """Decrypt and verify a cPassword. Used in self-test."""
    if not HAS_PYCRYPTO:
        return False
    try:
        pad = 4 - len(cpassword) % 4
        if pad != 4:
            cpassword += "=" * pad
        ct = base64.b64decode(cpassword)
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, GPP_AES_IV)
        dec = cipher.decrypt(ct)
        pad_len = dec[-1]
        if 1 <= pad_len <= 16:
            dec = dec[:-pad_len]
        result = dec.decode("utf-16-le", errors="replace").strip("\x00")
        return result == expected
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# DIRECTORY HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def gpo_path(domain: str, guid: str) -> Path:
    """Returns the SYSVOL path for a GPO GUID."""
    return SYSVOL_DIR / domain / "Policies" / guid


def ensure(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
    ok(f"Created: {path.relative_to(LAB_DIR)}")


def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    ok(f"Created (binary): {path.relative_to(LAB_DIR)}")


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 1 – GPO Link  (written to manifest; verified via link_map logic)
# ──────────────────────────────────────────────────────────────────────────────
def create_gpo_link_data(domain: str) -> dict:
    """
    Simulates gPLink attribute values for each GPO.
    In offline mode these are stored in the manifest.
    In online mode they are pushed to LDAP.
    Returns a dict of  container_dn -> gPLink_string.
    """
    dn_base = "DC=" + ",DC=".join(domain.split("."))
    links = {
        f"OU=Workstations,{dn_base}": (
            f"[LDAP://cn={GPO_GUIDS['Workstation_Baseline']},cn=policies,"
            f"cn=system,{dn_base};0]"
        ),
        f"OU=Servers,{dn_base}": (
            f"[LDAP://cn={GPO_GUIDS['Enforced_Security_GPO']},cn=policies,"
            f"cn=system,{dn_base};2]"    # flag=2 -> enforced
        ),
        f"OU=Sales,{dn_base}": (
            f"[LDAP://cn={GPO_GUIDS['Drive_Mapping_GPO']},cn=policies,"
            f"cn=system,{dn_base};0]"
        ),
        f"OU=IT,{dn_base}": (
            f"[LDAP://cn={GPO_GUIDS['Scheduled_Tasks_GPO']},cn=policies,"
            f"cn=system,{dn_base};0]"
        ),
        dn_base: (
            f"[LDAP://cn={GPO_GUIDS['Default_Domain_Policy']},cn=policies,"
            f"cn=system,{dn_base};0]"
        ),
    }
    return links


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 2 – Scope of Management  (GPT.INI + extension GUIDs)
# ──────────────────────────────────────────────────────────────────────────────
def create_gpt_ini(path: Path, version: int = 65537, display_name: str = ""):
    write(path / "GPT.INI", f"""
        [General]
        Version={version}
        displayName={display_name}
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 3+5 – Inheritance / Block Inheritance  (manifest entry)
# ──────────────────────────────────────────────────────────────────────────────
def create_inheritance_data(domain: str) -> dict:
    """
    Returns OUs that have Block Inheritance set (gpOptions=1).
    Stored in manifest; pushed to LDAP in online mode.
    """
    dn_base = "DC=" + ",DC=".join(domain.split("."))
    return {
        f"OU=Finance,{dn_base}":    {"gpOptions": 1, "blocked": True},
        f"OU=Workstations,{dn_base}": {"gpOptions": 0, "blocked": False},
    }


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 6 + 13 – GPP cPassword + GPP-decrypt
# ──────────────────────────────────────────────────────────────────────────────
def create_groups_xml(base: Path, domain: str):
    """Groups.xml with a cPassword for local Administrator account."""
    cp = gpp_encrypt(LAB_CREDENTIALS["local_admin"])
    write(base / "Machine" / "Preferences" / "Groups" / "Groups.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">
          <Group clsid="{{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}}"
                 name="Administrators (built-in)"
                 image="2" changed="2024-01-15 09:00:00" uid="{{LAB-GRP-001}}">
            <Properties action="U" newName="" description="Lab restricted group"
                        deleteAllUsers="0" deleteAllGroups="0"
                        removeAccounts="0" groupSid="S-1-5-32-544"
                        groupName="Administrators (built-in)">
              <Members>
                <Member name="{domain.split('.')[0].upper()}\\lab_admin"
                        action="ADD" sid="S-1-5-21-0000-0000-0000-1001"/>
              </Members>
            </Properties>
          </Group>
          <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}"
                name="LocalAdmin" image="2" changed="2024-01-15 09:00:00"
                uid="{{LAB-USR-001}}">
            <Properties action="U" newName="lab_local_admin"
                        fullName="Lab Local Admin"
                        description="GPP managed local admin"
                        cpassword="{cp}"
                        changeLogon="0" noChange="0" neverExpires="1"
                        acctDisabled="0" subAuthority="RID_ADMIN"
                        userName="LocalAdmin"/>
          </User>
        </Groups>
    """)
    return {"username": "LocalAdmin", "cpassword": cp,
            "plaintext": LAB_CREDENTIALS["local_admin"]}


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 7 – Scheduled Tasks (RunAs + cPassword)
# ──────────────────────────────────────────────────────────────────────────────
def create_scheduledtasks_xml(base: Path, domain: str):
    cp = gpp_encrypt(LAB_CREDENTIALS["svc_task"])
    netbios = domain.split(".")[0].upper()
    write(base / "Machine" / "Preferences" / "ScheduledTasks" / "ScheduledTasks.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A0CE23294625}}">
          <Task clsid="{{D8896631-B747-47a7-84A6-C155337F3BC8}}"
                name="LabBackupTask" image="1" changed="2024-02-01 08:00:00"
                uid="{{LAB-TASK-001}}">
            <Properties action="C" name="LabBackupTask"
                        runAs="{netbios}\\svc_task"
                        cpassword="{cp}"
                        logonType="Password"
                        enabled="1">
              <Task version="1.2">
                <RegistrationInfo>
                  <Description>Lab scheduled backup task with RunAs cPassword</Description>
                </RegistrationInfo>
                <Actions>
                  <Exec>
                    <Command>C:\\Scripts\\backup.bat</Command>
                    <Arguments>/full /log C:\\Logs\\backup.log</Arguments>
                  </Exec>
                </Actions>
              </Task>
            </Properties>
          </Task>
        </ScheduledTasks>
    """)
    return {"run_as": f"{netbios}\\svc_task", "cpassword": cp,
            "plaintext": LAB_CREDENTIALS["svc_task"]}


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 8 – GPO Immediate Tasks
# ──────────────────────────────────────────────────────────────────────────────
def create_immediate_tasks_xml(base: Path, domain: str):
    cp = gpp_encrypt(LAB_CREDENTIALS["svc_deploy"])
    netbios = domain.split(".")[0].upper()
    write(base / "Machine" / "Preferences" / "ScheduledTasks" / "ScheduledTasks.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A0CE23294625}}">
          <ImmediateTask clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"
                         name="LabImmediateDeploy" image="0"
                         changed="2024-03-01 10:00:00" uid="{{LAB-IMM-001}}">
            <Properties action="C" name="LabImmediateDeploy"
                        runAs="{netbios}\\svc_deploy"
                        cpassword="{cp}"
                        logonType="Password" enabled="1">
              <Task version="1.2">
                <Actions>
                  <Exec>
                    <Command>powershell.exe</Command>
                    <Arguments>-NonInteractive -File C:\\Deploy\\install.ps1</Arguments>
                  </Exec>
                </Actions>
              </Task>
            </Properties>
          </ImmediateTask>
        </ScheduledTasks>
    """)
    return {"run_as": f"{netbios}\\svc_deploy", "cpassword": cp,
            "plaintext": LAB_CREDENTIALS["svc_deploy"]}


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 9 – Restricted Groups  (Groups.xml member list + GptTmpl.inf)
# ──────────────────────────────────────────────────────────────────────────────
def create_restricted_groups(base: Path, domain: str):
    netbios = domain.split(".")[0].upper()
    # GptTmpl.inf section
    write(base / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf", f"""
        [Unicode]
        Unicode=yes
        [Version]
        signature="$CHICAGO$"
        Revision=1
        [Group Membership]
        *S-1-5-32-544__Memberof =
        *S-1-5-32-544__Members = *S-1-5-21-0000-0000-0000-500,{netbios}\\lab_admin,{netbios}\\svc_backup
        [System Access]
        MinimumPasswordAge = 1
        MaximumPasswordAge = 90
        MinimumPasswordLength = 12
        PasswordComplexity = 1
        LockoutBadCount = 5
        ResetLockoutCount = 30
        LockoutDuration = 30
        [Audit Policy]
        AuditSystemEvents = 3
        AuditLogonEvents = 3
        AuditObjectAccess = 2
        AuditPrivilegeUse = 2
        [Privilege Rights]
        SeDebugPrivilege = *S-1-5-32-544
        SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
        SeDenyNetworkLogonRight = *S-1-5-32-546
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 10 – Files & Scripts
# ──────────────────────────────────────────────────────────────────────────────
def create_files_xml(base: Path):
    write(base / "Machine" / "Preferences" / "Files" / "Files.xml", """
        <?xml version="1.0" encoding="UTF-8"?>
        <Files clsid="{215B2E53-57CE-475c-80FE-9EEC14635851}">
          <File clsid="{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}"
                name="Deploy Script" image="1" changed="2024-01-20 12:00:00"
                uid="{LAB-FILE-001}">
            <Properties action="C"
                        fromPath="\\\\labdc\\scripts\\deploy.bat"
                        targetPath="C:\\Windows\\Temp\\deploy.bat"
                        readOnly="0" archive="1" hidden="0"/>
          </File>
          <File clsid="{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}"
                name="Config File" image="1" changed="2024-01-20 12:00:00"
                uid="{LAB-FILE-002}">
            <Properties action="C"
                        fromPath="\\\\labdc\\configs\\app.conf"
                        targetPath="C:\\ProgramData\\LabApp\\app.conf"
                        readOnly="1" archive="0" hidden="0"/>
          </File>
        </Files>
    """)


def create_scripts_ini(base: Path):
    write(base / "Machine" / "Scripts" / "scripts.ini", """
        [Startup]
        0CmdLine=C:\\Scripts\\startup.bat
        0Parameters=/silent /log C:\\Logs\\startup.log
        1CmdLine=powershell.exe
        1Parameters=-NonInteractive -File C:\\Scripts\\harden.ps1
        [Shutdown]
        0CmdLine=C:\\Scripts\\cleanup.bat
        0Parameters=
    """)
    write(base / "User" / "Scripts" / "scripts.ini", """
        [Logon]
        0CmdLine=\\\\labdc\\netlogon\\map_drives.bat
        0Parameters=
        1CmdLine=powershell.exe
        1Parameters=-NonInteractive -File \\\\labdc\\scripts\\user_init.ps1
        [Logoff]
        0CmdLine=C:\\Scripts\\logoff_cleanup.bat
        0Parameters=
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 11 – Registry Settings
# ──────────────────────────────────────────────────────────────────────────────
def create_registry_xml(base: Path):
    write(base / "Machine" / "Preferences" / "Registry" / "Registry.xml", """
        <?xml version="1.0" encoding="UTF-8"?>
        <RegistrySettings clsid="{B087BE9D-ED37-454F-AF9C-04291E351182}">
          <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
                    name="DisableSMBv1" image="12" changed="2024-01-10 10:00:00"
                    uid="{LAB-REG-001}">
            <Properties action="U" displayDecimal="1" default="0"
                        hive="HKEY_LOCAL_MACHINE"
                        key="SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
                        name="SMB1" type="REG_DWORD" value="0"/>
          </Registry>
          <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
                    name="DisableNTLMv1" image="12" changed="2024-01-10 10:00:00"
                    uid="{LAB-REG-002}">
            <Properties action="U" displayDecimal="1" default="0"
                        hive="HKEY_LOCAL_MACHINE"
                        key="SYSTEM\\CurrentControlSet\\Control\\Lsa"
                        name="LmCompatibilityLevel" type="REG_DWORD" value="5"/>
          </Registry>
          <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"
                    name="EnableCredentialGuard" image="12" changed="2024-01-10 10:00:00"
                    uid="{LAB-REG-003}">
            <Properties action="U" displayDecimal="1" default="0"
                        hive="HKEY_LOCAL_MACHINE"
                        key="SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
                        name="EnableVirtualizationBasedSecurity"
                        type="REG_DWORD" value="1"/>
          </Registry>
        </RegistrySettings>
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 12 – All .xml files  (additional XMLs to simulate full SYSVOL scan)
# ──────────────────────────────────────────────────────────────────────────────
def create_extra_xml_files(base: Path):
    """Creates DataSources.xml, Printers.xml, Shortcuts.xml with cPasswords."""
    # DataSources.xml
    cp_ds = gpp_encrypt(LAB_CREDENTIALS["svc_backup"])
    write(base / "User" / "Preferences" / "DataSources" / "DataSources.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <DataSources clsid="{{728EE579-943C-4519-9EF7-AB56765798ED}}">
          <DataSource clsid="{{1B6231E4-C099-403f-9F71-6E04E30C8883}}"
                      name="LabDSN" image="1" changed="2024-02-01 09:00:00"
                      uid="{{LAB-DS-001}}">
            <Properties action="C" userDSN="1" dsn="LabDatabase"
                        driver="SQL Server" description="Lab ODBC DSN"
                        username="svc_backup" cpassword="{cp_ds}"/>
          </DataSource>
        </DataSources>
    """)

    # Printers.xml
    cp_pr = gpp_encrypt(LAB_CREDENTIALS["svc_backup"])
    write(base / "User" / "Preferences" / "Printers" / "Printers.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <Printers clsid="{{1F577D12-3D1B-471f-A1B3-BF82B783C67A}}">
          <SharedPrinter clsid="{{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}}"
                         name="LabPrinter01" image="1" changed="2024-02-01 09:00:00"
                         uid="{{LAB-PRN-001}}">
            <Properties action="C" comment="Lab network printer"
                        path="\\\\printserver\\LabPrinter01"
                        location="Lab Room 101" default="1"
                        username="svc_backup" cpassword="{cp_pr}"/>
          </SharedPrinter>
        </Printers>
    """)

    # Shortcuts.xml
    write(base / "User" / "Preferences" / "Shortcuts" / "Shortcuts.xml", """
        <?xml version="1.0" encoding="UTF-8"?>
        <Shortcuts clsid="{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}">
          <Shortcut clsid="{2558C87C-9B3A-4af4-B552-B1461FCFEB45}"
                    name="LabPortal" image="1" changed="2024-02-01 09:00:00"
                    uid="{LAB-SC-001}">
            <Properties action="C" shortcutKey="0" comment="Internal lab portal"
                        startIn="%USERPROFILE%"
                        targetType="URL"
                        targetPath="http://labportal.lab.local/dashboard"
                        iconIndex="0"/>
          </Shortcut>
        </Shortcuts>
    """)
    return {"datasource_cpassword": cp_ds, "printer_cpassword": cp_pr}


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 15 – Software Installation
# ──────────────────────────────────────────────────────────────────────────────
def create_software_installation(base: Path):
    pkg_dir = base / "Machine" / "Applications"
    ensure(pkg_dir)
    # Create stub .msi files (real lab would have actual MSIs here)
    for pkg in ["LabAgent_1.0.msi", "LabTools_2.3.msi", "SecurityBaseline.msp"]:
        stub = pkg_dir / pkg
        stub.write_bytes(b"LAB_STUB_MSI:" + pkg.encode())
        ok(f"Created stub: {stub.relative_to(LAB_DIR)}")

    # Software.xml
    write(base / "Machine" / "Preferences" / "Software" / "Software.xml", """
        <?xml version="1.0" encoding="UTF-8"?>
        <SoftwareInstallationSettings clsid="{F9C77450-3A41-477E-9310-9ACD617BD9E3}">
          <Package name="LabAgent" path="\\\\labdc\\software\\LabAgent_1.0.msi"
                   action="INSTALL"/>
          <Package name="LabTools" path="\\\\labdc\\software\\LabTools_2.3.msi"
                   action="INSTALL"/>
        </SoftwareInstallationSettings>
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 16 – Drive Mappings
# ──────────────────────────────────────────────────────────────────────────────
def create_drives_xml(base: Path, domain: str):
    cp = gpp_encrypt(LAB_CREDENTIALS["svc_drive"])
    netbios = domain.split(".")[0].upper()
    write(base / "User" / "Preferences" / "Drives" / "Drives.xml", f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <Drives clsid="{{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}}">
          <Drive clsid="{{935D1B74-9CB8-4e3c-9914-7DD559B7A417}}"
                 name="H:" image="2" changed="2024-01-15 09:00:00"
                 uid="{{LAB-DRV-001}}">
            <Properties action="C" thisDrive="NOCHANGE" allDrives="NOCHANGE"
                        userName="{netbios}\\svc_drive"
                        cpassword="{cp}"
                        path="\\\\fileserver\\Home\\%USERNAME%"
                        label="Home Drive" persistent="1" useLetter="1"
                        letter="H"/>
          </Drive>
          <Drive clsid="{{935D1B74-9CB8-4e3c-9914-7DD559B7A417}}"
                 name="S:" image="2" changed="2024-01-15 09:00:00"
                 uid="{{LAB-DRV-002}}">
            <Properties action="C" thisDrive="NOCHANGE" allDrives="NOCHANGE"
                        path="\\\\fileserver\\Shared"
                        label="Shared" persistent="1" useLetter="1"
                        letter="S"/>
          </Drive>
        </Drives>
    """)
    return {"username": f"{netbios}\\svc_drive", "cpassword": cp,
            "plaintext": LAB_CREDENTIALS["svc_drive"]}



# ──────────────────────────────────────────────────────────────────────────────
# CHECK 17 – GPO Creator / Owner  (binary Security Descriptor stub)
# ──────────────────────────────────────────────────────────────────────────────
def build_stub_sd(owner_sid_str: str = "S-1-5-21-0000-0000-0000-500") -> bytes:
    """
    Builds a minimal binary Security Descriptor with the given Owner SID.
    Structure: Revision(1) Sbz1(1) Control(2) OffsetOwner(4)
               OffsetGroup(4) OffsetSacl(4) OffsetDacl(4) OwnerSid(...)
    Control = SE_SELF_RELATIVE(0x8000) | SE_DACL_PRESENT(0x0004) = 0x8004
    """
    def sid_to_bytes(sid_str: str) -> bytes:
        parts = sid_str.split("-")
        # S-R-A-s1-s2-...
        revision = int(parts[1])
        authority = int(parts[2])
        subs = [int(p) for p in parts[3:]]
        data = bytes([revision, len(subs)])
        data += authority.to_bytes(6, "big")
        for s in subs:
            data += struct.pack("<I", s)
        return data

    owner_bytes = sid_to_bytes(owner_sid_str)
    header_size = 20
    offset_owner = header_size

    sd = struct.pack("<BBHIIII",
        1,           # Revision
        0,           # Sbz1
        0x8004,      # Control: SE_SELF_RELATIVE | SE_DACL_PRESENT
        offset_owner,
        0, 0, 0      # OffsetGroup, OffsetSacl, OffsetDacl
    )
    return sd + owner_bytes


# ──────────────────────────────────────────────────────────────────────────────
# CHECK 20 – SYSVOL ACL  (stub ACL info file for offline testing)
# ──────────────────────────────────────────────────────────────────────────────
def create_sysvol_acl_info(base: Path, domain: str):
    netbios = domain.split(".")[0].upper()
    acl_data = {
        "path": str(base),
        "acl_entries": [
            {"type": "ACCESS_ALLOWED", "trustee": f"{netbios}\\Domain Admins",
             "rights": ["FA"], "inherited": False},
            {"type": "ACCESS_ALLOWED", "trustee": "SYSTEM",
             "rights": ["FA"], "inherited": False},
            {"type": "ACCESS_ALLOWED", "trustee": "Authenticated Users",
             "rights": ["FR"], "inherited": True},
            {"type": "ACCESS_ALLOWED", "trustee": f"{netbios}\\Enterprise Admins",
             "rights": ["FA"], "inherited": False},
            # Intentionally weak: Domain Users have write — finding this is the point
            {"type": "ACCESS_ALLOWED", "trustee": f"{netbios}\\Domain Users",
             "rights": ["FW", "WP"], "inherited": False,
             "note": "MISCONFIGURED: Domain Users should not have write access"},
        ]
    }
    write(base / "SYSVOL_ACL.json",
          json.dumps(acl_data, indent=2))


# ──────────────────────────────────────────────────────────────────────────────
# LDAP PUSH  (online mode only)
# ──────────────────────────────────────────────────────────────────────────────
def ldap_push(dc_ip: str, domain: str, username: str, password: str,
              manifest: dict) -> dict:
    """
    Pushes lab objects to a real AD DC via LDAP.
    Requires ldap3.  Skipped gracefully if DC is unreachable.
    """
    if not HAS_LDAP3:
        warn("ldap3 not installed – skipping LDAP push")
        return {"pushed": False, "reason": "ldap3 missing"}

    dn_base = "DC=" + ",DC=".join(domain.split("."))
    results  = {"pushed": True, "created": [], "errors": []}

    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=10)
        with Connection(server, user=f"{domain.split('.')[0].upper()}\\{username}",
                        password=password, auto_bind=True) as conn:

            # Create OUs
            ous = ["Workstations", "Servers", "Sales", "IT", "Finance"]
            for ou in ous:
                dn = f"OU={ou},{dn_base}"
                conn.add(dn, ["top", "organizationalUnit"],
                         {"description": f"Lab OU – {ou}"})
                if conn.result["result"] in (0, 68):  # 68=already exists
                    results["created"].append(dn)
                else:
                    results["errors"].append({"dn": dn, "result": conn.result})

            # Set Block Inheritance on Finance OU
            finance_dn = f"OU=Finance,{dn_base}"
            conn.modify(finance_dn, {"gpOptions": [(MODIFY_REPLACE, [1])]})

            # Create GPO container objects
            for name, guid in GPO_GUIDS.items():
                gpo_dn = f"CN={guid},CN=Policies,CN=System,{dn_base}"
                sysvol_path = f"\\\\{domain}\\SysVol\\{domain}\\Policies\\{guid}"
                attrs = {
                    "displayName": name.replace("_", " "),
                    "description": f"Lab GPO – {name}",
                    "gPCFileSysPath": sysvol_path,
                    "versionNumber": 65537,
                    "flags": 0,
                }
                conn.add(gpo_dn, ["top", "container", "groupPolicyContainer"], attrs)
                if conn.result["result"] in (0, 68):
                    results["created"].append(gpo_dn)
                else:
                    results["errors"].append({"dn": gpo_dn, "result": conn.result})

            # Set gPLink on containers
            for container_dn, gp_link in manifest["gpo_links"].items():
                conn.modify(container_dn,
                            {"gPLink": [(MODIFY_REPLACE, [gp_link])]})


            ok(f"LDAP push complete: {len(results['created'])} objects")

    except LDAPException as ex:
        results["errors"].append({"ldap_error": str(ex)})
        err(f"LDAP error: {ex}")
    except Exception as ex:
        results["errors"].append({"error": str(ex)})
        err(f"Unexpected error during LDAP push: {ex}")

    return results




# ──────────────────────────────────────────────────────────────────────────────
# SYSVOL PUSH  (lokal faylları real DC SYSVOL-una kopyalayır)
# ──────────────────────────────────────────────────────────────────────────────
def sysvol_push(dc_ip: str, domain: str, username: str, password: str) -> dict:
    """
    Lokal gpo_lab/SYSVOL/ qovluğundakı faylları real DC-nin SYSVOL
    paylaşımına kopyalayır. impacket SMBConnection istifadə edir.
    """
    results = {"pushed": False, "copied": [], "errors": []}

    if not HAS_IMPACKET:
        warn("impacket not installed – skipping SYSVOL push")
        results["reason"] = "impacket missing"
        return results

    local_policy_dir = SYSVOL_DIR / domain / "Policies"
    if not local_policy_dir.exists():
        warn(f"Lokal SYSVOL qovluğu tapılmadı: {local_policy_dir}")
        results["reason"] = "local SYSVOL not found"
        return results

    try:
        from impacket.smbconnection import SMBConnection

        netbios = domain.split(".")[0].upper()
        smb = SMBConnection(dc_ip, dc_ip, timeout=15)
        smb.login(username, password, domain=netbios)
        info("SMB qoşulması uğurlu")

        share = "SYSVOL"
        remote_base = f"\\{domain}\\Policies"

        def smb_mkdir(path: str):
            try:
                smb.createDirectory(share, path)
            except Exception:
                pass

        def smb_upload(local_path, remote_path: str):
            try:
                with open(local_path, "rb") as f:
                    smb.putFile(share, remote_path, f.read)
                results["copied"].append(remote_path)
            except Exception as ex:
                results["errors"].append({"path": remote_path, "error": str(ex)})
                warn(f"Yüklənmədi: {remote_path} — {ex}")

        def push_dir(local_dir, remote_dir: str):
            smb_mkdir(remote_dir)
            for item in local_dir.iterdir():
                remote_item = f"{remote_dir}\\{item.name}"
                if item.is_dir():
                    push_dir(item, remote_item)
                elif item.suffix.lower() != ".json" or item.name != "SYSVOL_ACL.json":
                    smb_upload(item, remote_item)

        for gpo_dir in local_policy_dir.iterdir():
            if not gpo_dir.is_dir():
                continue
            remote_gpo = f"{remote_base}\\{gpo_dir.name}"
            info(f"Kopyalanır: {gpo_dir.name}")
            push_dir(gpo_dir, remote_gpo)

        smb.logoff()
        results["pushed"] = True
        ok(f"SYSVOL push tamamlandı: {len(results['copied'])} fayl")

    except Exception as ex:
        results["errors"].append({"error": str(ex)})
        err(f"SYSVOL push xətası: {ex}")

    return results

# ──────────────────────────────────────────────────────────────────────────────
# SELF-TEST  (validates every generated file without a DC)
# ──────────────────────────────────────────────────────────────────────────────
def run_self_tests(manifest: dict, domain: str) -> dict:
    """
    Validates every lab artifact against expected values.
    Returns a dict of { check_id: {passed, detail} }.
    """
    section("Running Self-Tests")
    results = {}

    def check(cid: str, label: str, passed: bool, detail: str = ""):
        results[cid] = {"label": label, "passed": passed, "detail": detail}
        if passed:
            ok(f"CHECK {cid:2s} – {label}")
        else:
            err(f"CHECK {cid:2s} – {label}  ← FAILED  {detail}")

    # 1. GPO Link
    links = manifest.get("gpo_links", {})
    check("01", "GPO Link",
          len(links) >= 3,
          f"{len(links)} link entries found")

    # 2. Scope of Management
    scope_ok = all(
        (gpo_path(domain, guid.strip("{}")) / "GPT.INI").exists()
        for guid in list(GPO_GUIDS.values())[:3]
    )
    check("02", "Scope of Management – GPT.INI",
          scope_ok, "GPT.INI files present")

    # 3. Inheritance
    ou_inh = manifest.get("ou_inheritance", {})
    check("03", "Inheritance – OU gpOptions map",
          len(ou_inh) >= 2, f"{len(ou_inh)} OUs mapped")

    # 4. Enforcement
    enforced = any(";2]" in v for v in links.values())
    check("04", "Enforcement – enforced flag in gPLink",
          enforced, "flag=2 found in at least one link")

    # 5. Block Inheritance
    blocked = manifest.get("inheritance_blocked", [])
    check("05", "Block Inheritance – gpOptions=1",
          len(blocked) >= 1, f"{blocked}")

    # 6+13. GPP cPassword + GPP-decrypt
    cpass_items = manifest.get("cpasswords", {})
    any_found = len(cpass_items) > 0
    check("06", "GPP cPassword – present in XML files",
          any_found, f"{len(cpass_items)} cPasswords generated")

    if HAS_PYCRYPTO:
        decrypt_ok = all(
            gpp_decrypt_verify(v["cpassword"], v["plaintext"])
            for v in cpass_items.values()
            if "cpassword" in v and "plaintext" in v
        )
        check("13", "GPP-decrypt – AES-256-CBC roundtrip",
              decrypt_ok, "all cPasswords decrypt to expected plaintext")
    else:
        check("13", "GPP-decrypt – AES-256-CBC roundtrip",
              False, "pycryptodome not installed")

    # 7. Scheduled Tasks RunAs
    st_file = None
    for guid in [GPO_GUIDS["Scheduled_Tasks_GPO"], GPO_GUIDS["Default_Domain_Policy"]]:
        p = gpo_path(domain, guid.strip("{}")) / "Machine" / "Preferences" / "ScheduledTasks" / "ScheduledTasks.xml"
        if p.exists():
            st_file = p
            break
    if st_file:
        content = st_file.read_text(encoding="utf-8")
        check("07", "Scheduled Tasks – RunAs + cPassword",
              "runAs=" in content and "cpassword=" in content,
              str(st_file.relative_to(LAB_DIR)))
    else:
        check("07", "Scheduled Tasks – RunAs + cPassword", False, "file not found")

    # 8. Immediate Tasks
    imm_file = gpo_path(domain, GPO_GUIDS["Software_Deploy"].strip("{}")) / \
               "Machine" / "Preferences" / "ScheduledTasks" / "ScheduledTasks.xml"
    if imm_file.exists():
        content = imm_file.read_text(encoding="utf-8")
        check("08", "Immediate Tasks – ImmediateTask element",
              "ImmediateTask" in content, str(imm_file.relative_to(LAB_DIR)))
    else:
        check("08", "Immediate Tasks – ImmediateTask element", False, "file not found")

    # 9. Restricted Groups
    inf_file = gpo_path(domain, GPO_GUIDS["Default_Domain_Policy"].strip("{}")) / \
               "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
    if inf_file.exists():
        content = inf_file.read_text(encoding="utf-8")
        check("09", "Restricted Groups – GptTmpl.inf [Group Membership]",
              "Group Membership" in content, str(inf_file.relative_to(LAB_DIR)))
    else:
        check("09", "Restricted Groups – GptTmpl.inf", False, "file not found")

    # 10. Files & Scripts
    scripts_ok = (
        gpo_path(domain, GPO_GUIDS["Workstation_Baseline"].strip("{}")) /
        "Machine" / "Scripts" / "scripts.ini"
    ).exists()
    check("10", "Files & Scripts – scripts.ini",
          scripts_ok)

    # 11. Registry Settings
    reg_file = gpo_path(domain, GPO_GUIDS["Registry_Settings_GPO"].strip("{}")) / \
               "Machine" / "Preferences" / "Registry" / "Registry.xml"
    check("11", "Registry Settings – Registry.xml",
          reg_file.exists(), str(reg_file.relative_to(LAB_DIR)) if reg_file.exists() else "missing")

    # 12. All .xml files
    all_xml = list(SYSVOL_DIR.rglob("*.xml"))
    check("12", "All XML files – SYSVOL scan",
          len(all_xml) >= 8, f"{len(all_xml)} .xml files found")

    # 15. Software Installation
    msi_files = list(SYSVOL_DIR.rglob("*.msi"))
    check("15", "Software Installation – .msi stubs",
          len(msi_files) >= 2, f"{len(msi_files)} .msi files")

    # 16. Drive Mappings
    drives_file = gpo_path(domain, GPO_GUIDS["Drive_Mapping_GPO"].strip("{}")) / \
                  "User" / "Preferences" / "Drives" / "Drives.xml"
    if drives_file.exists():
        content = drives_file.read_text(encoding="utf-8")
        check("16", "Drive Mappings – Drives.xml",
              "letter=" in content and "cpassword=" in content,
              str(drives_file.relative_to(LAB_DIR)))
    else:
        check("16", "Drive Mappings – Drives.xml", False, "file not found")

    # 17. GPO Creator/Owner (stub SD)
    sd_file = LAB_DIR / "security_descriptors.bin"
    check("17", "GPO Creator/Owner – binary SD stub",
          sd_file.exists(), str(sd_file))

    # 18. Description
    desc = manifest.get("gpo_descriptions", {})
    check("18", "Description – present in manifest",
          len(desc) >= 3, f"{len(desc)} descriptions")

    # 19. gPCFileSysPath
    paths = manifest.get("gpc_fs_paths", {})
    check("19", "gPCFileSysPath – present in manifest",
          len(paths) >= 3, f"{len(paths)} paths")

    # 20. SYSVOL ACL
    acl_files = list(SYSVOL_DIR.rglob("SYSVOL_ACL.json"))
    check("20", "SYSVOL ACL – ACL info files",
          len(acl_files) >= 2, f"{len(acl_files)} SYSVOL_ACL.json files")

    # Summary
    passed = sum(1 for v in results.values() if v["passed"])
    total  = len(results)
    section(f"Self-Test Summary: {passed}/{total} passed")
    if passed == total:
        ok("All checks passed – lab is fully configured")
    else:
        warn(f"{total - passed} check(s) failed – review errors above")

    return results


# ──────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ──────────────────────────────────────────────────────────────────────────────
def cleanup(dc_ip: str = None, domain: str = None,
            username: str = None, password: str = None):
    section("Cleanup")

    # Local files
    if LAB_DIR.exists():
        shutil.rmtree(LAB_DIR)
        ok(f"Removed local lab directory: {LAB_DIR}")
    else:
        info("Lab directory does not exist – nothing to remove locally")

    # LDAP cleanup (online mode)
    if dc_ip and domain and username and password and HAS_LDAP3:
        dn_base = "DC=" + ",DC=".join(domain.split("."))
        try:
            server = Server(dc_ip, get_info=ALL, connect_timeout=10)
            with Connection(server,
                            user=f"{domain.split('.')[0].upper()}\\{username}",
                            password=password, auto_bind=True) as conn:

                # Delete GPO containers
                for guid in reversed(list(GPO_GUIDS.values())):
                    dn = f"CN={guid},CN=Policies,CN=System,{dn_base}"
                    conn.delete(dn)
                    if conn.result["result"] == 0:
                        ok(f"Deleted: {dn}")

                # Delete OUs (reverse order to handle children first)
                for ou in ["Finance", "IT", "Sales", "Servers", "Workstations"]:
                    dn = f"OU={ou},{dn_base}"
                    conn.delete(dn)
                    if conn.result["result"] == 0:
                        ok(f"Deleted: {dn}")

                ok("LDAP cleanup complete")
        except Exception as ex:
            err(f"LDAP cleanup error: {ex}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN BUILDER
# ──────────────────────────────────────────────────────────────────────────────
def build_lab(domain: str, dc_ip: str = None,
              username: str = "Administrator", password: str = "") -> dict:
    """
    Creates the full synthetic GPO lab.
    Returns the manifest dict.
    """
    section(f"Building GPO Lab  [domain={domain}]")
    info(f"Lab root: {LAB_DIR.resolve()}")

    manifest = {
        "domain":          domain,
        "dc_ip":           dc_ip,
        "created":         datetime.now(timezone.utc).isoformat(),
        "gpo_guids":       GPO_GUIDS,
        "gpo_links":       {},
        "ou_inheritance":  {},
        "inheritance_blocked": [],
        "cpasswords":      {},
        "gpo_descriptions": {},
        "gpc_fs_paths":    {},
        "test_credentials": LAB_CREDENTIALS,
    }

    ensure(LAB_DIR)
    ensure(SYSVOL_DIR)

    # ── CHECK 1 – GPO Link ────────────────────────────────────────────────
    section("CHECK 01 – GPO Link")
    manifest["gpo_links"] = create_gpo_link_data(domain)
    ok(f"{len(manifest['gpo_links'])} GPO link entries created")

    # ── CHECK 3+5 – Inheritance / Block Inheritance ───────────────────────
    section("CHECK 03+05 – Inheritance / Block Inheritance")
    inh_data = create_inheritance_data(domain)
    manifest["ou_inheritance"] = inh_data
    manifest["inheritance_blocked"] = [
        dn for dn, v in inh_data.items() if v["blocked"]
    ]
    ok(f"Block Inheritance on: {manifest['inheritance_blocked']}")


    # ── GPO 1: Default Domain Policy ─────────────────────────────────────
    section("GPO: Default Domain Policy  [highvalue]")
    ddp_guid = GPO_GUIDS["Default_Domain_Policy"].strip("{}")
    ddp_base = gpo_path(domain, ddp_guid)
    # CHECK 2 – Scope / GPT.INI
    create_gpt_ini(ddp_base, version=589825, display_name="Default Domain Policy")
    # CHECK 6+13 – GPP cPassword
    cp_grp = create_groups_xml(ddp_base, domain)
    manifest["cpasswords"]["groups_local_admin"] = cp_grp
    # CHECK 7 – Scheduled Tasks RunAs
    cp_task = create_scheduledtasks_xml(ddp_base, domain)
    manifest["cpasswords"]["sched_task"] = cp_task
    # CHECK 9 – Restricted Groups
    create_restricted_groups(ddp_base, domain)
    # CHECK 10 – Files & Scripts
    create_files_xml(ddp_base)
    create_scripts_ini(ddp_base)
    # CHECK 18 – Description
    manifest["gpo_descriptions"]["Default_Domain_Policy"] = (
        "Default Domain Policy – applies to all users and computers in domain"
    )
    # CHECK 19 – gPCFileSysPath
    manifest["gpc_fs_paths"]["Default_Domain_Policy"] = (
        f"\\\\{domain}\\SysVol\\{domain}\\Policies\\"
        f"{{{GPO_GUIDS['Default_Domain_Policy']}}}"
    )
    # CHECK 20 – SYSVOL ACL
    create_sysvol_acl_info(ddp_base, domain)

    # ── GPO 2: Software Deploy (Immediate Tasks) ──────────────────────────
    section("GPO: Software Deploy  [immediate tasks]")
    sd_guid = GPO_GUIDS["Software_Deploy"].strip("{}")
    sd_base = gpo_path(domain, sd_guid)
    create_gpt_ini(sd_base, version=65537, display_name="Software Deploy")
    # CHECK 8 – Immediate Tasks
    cp_imm = create_immediate_tasks_xml(sd_base, domain)
    manifest["cpasswords"]["immediate_task"] = cp_imm
    # CHECK 15 – Software Installation
    create_software_installation(sd_base)
    manifest["gpo_descriptions"]["Software_Deploy"] = (
        "Deploys lab software packages via MSI and immediate tasks"
    )
    manifest["gpc_fs_paths"]["Software_Deploy"] = (
        f"\\\\{domain}\\SysVol\\{domain}\\Policies\\"
        f"{{{GPO_GUIDS['Software_Deploy']}}}"
    )
    create_sysvol_acl_info(sd_base, domain)

    # ── GPO 3: Drive Mapping ──────────────────────────────────────────────
    section("GPO: Drive Mapping")
    dm_guid = GPO_GUIDS["Drive_Mapping_GPO"].strip("{}")
    dm_base = gpo_path(domain, dm_guid)
    create_gpt_ini(dm_base, version=65537, display_name="Drive Mapping GPO")
    # CHECK 16 – Drive Mappings
    cp_drv = create_drives_xml(dm_base, domain)
    manifest["cpasswords"]["drive_mapping"] = cp_drv
    manifest["gpo_descriptions"]["Drive_Mapping_GPO"] = (
        "Maps network drives for Sales OU users"
    )
    manifest["gpc_fs_paths"]["Drive_Mapping_GPO"] = (
        f"\\\\{domain}\\SysVol\\{domain}\\Policies\\"
        f"{{{GPO_GUIDS['Drive_Mapping_GPO']}}}"
    )
    create_sysvol_acl_info(dm_base, domain)

    # ── GPO 4: Registry Settings ──────────────────────────────────────────
    section("GPO: Registry Settings")
    rg_guid = GPO_GUIDS["Registry_Settings_GPO"].strip("{}")
    rg_base = gpo_path(domain, rg_guid)
    create_gpt_ini(rg_base, version=65537, display_name="Registry Settings GPO")
    # CHECK 11 – Registry Settings
    create_registry_xml(rg_base)
    manifest["gpo_descriptions"]["Registry_Settings_GPO"] = (
        "Enforces security registry keys (SMBv1, NTLMv1, Credential Guard)"
    )
    manifest["gpc_fs_paths"]["Registry_Settings_GPO"] = (
        f"\\\\{domain}\\SysVol\\{domain}\\Policies\\"
        f"{{{GPO_GUIDS['Registry_Settings_GPO']}}}"
    )
    create_sysvol_acl_info(rg_base, domain)

    # ── GPO 5: Workstation Baseline (Files, Scripts, XML scan) ───────────
    section("GPO: Workstation Baseline  [files + scripts + extra XML]")
    wb_guid = GPO_GUIDS["Workstation_Baseline"].strip("{}")
    wb_base = gpo_path(domain, wb_guid)
    create_gpt_ini(wb_base, version=131073, display_name="Workstation Baseline")
    create_files_xml(wb_base)
    create_scripts_ini(wb_base)
    # CHECK 12 – All .xml files (extra XML types)
    extra_cp = create_extra_xml_files(wb_base)
    manifest["cpasswords"]["datasource"] = {
        "cpassword": extra_cp["datasource_cpassword"],
        "plaintext": LAB_CREDENTIALS["svc_backup"],
    }
    manifest["cpasswords"]["printer"] = {
        "cpassword": extra_cp["printer_cpassword"],
        "plaintext": LAB_CREDENTIALS["svc_backup"],
    }
    manifest["gpo_descriptions"]["Workstation_Baseline"] = (
        "Workstation hardening baseline – scripts, files, drive maps, and shortcuts"
    )
    manifest["gpc_fs_paths"]["Workstation_Baseline"] = (
        f"\\\\{domain}\\SysVol\\{domain}\\Policies\\"
        f"{{{GPO_GUIDS['Workstation_Baseline']}}}"
    )
    create_sysvol_acl_info(wb_base, domain)

    # ── GPO 6: Remaining GPOs (stubs for link/enforcement tests) ─────
    for key in ["Default_DC_Policy", "Scheduled_Tasks_GPO",
                "Enforced_Security_GPO",
                "Inherited_Block_Test_GPO"]:
        g = GPO_GUIDS[key].strip("{}")
        b = gpo_path(domain, g)
        create_gpt_ini(b, version=65537, display_name=key.replace("_", " "))
        manifest["gpo_descriptions"][key] = f"Lab stub GPO – {key}"
        manifest["gpc_fs_paths"][key] = (
            f"\\\\{domain}\\SysVol\\{domain}\\Policies\\{{{GPO_GUIDS[key]}}}"
        )
        create_sysvol_acl_info(b, domain)

    # ── CHECK 17 – GPO Creator / Owner ───────────────────────────────────
    section("CHECK 17 – GPO Creator / Owner")
    sd_data = b""
    for guid in GPO_GUIDS.values():
        stub_sd = build_stub_sd("S-1-5-21-0000-0000-0000-500")
        sd_data += guid.encode() + b":" + stub_sd + b"\n"
    write_bytes(LAB_DIR / "security_descriptors.bin", sd_data)
    manifest["owner_sids"] = {
        guid: "S-1-5-21-0000-0000-0000-500"
        for guid in GPO_GUIDS.values()
    }

    # ── Save manifest ─────────────────────────────────────────────────────
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    ok(f"Manifest saved: {MANIFEST_FILE}")

    return manifest


# ──────────────────────────────────────────────────────────────────────────────
# PRINT USAGE CHEATSHEET
# ──────────────────────────────────────────────────────────────────────────────
def print_cheatsheet(domain: str, dc_ip: str = None):
    section("Lab Cheatsheet")
    dc = dc_ip or "<DC_IP>"
    user = "Administrator"
    pw   = "Password123!"
    print(f"""
  {C.BOLD}Lab credentials planted in XML files:{C.RESET}
    svc_task    -> {LAB_CREDENTIALS['svc_task']}
    svc_deploy  -> {LAB_CREDENTIALS['svc_deploy']}
    svc_drive   -> {LAB_CREDENTIALS['svc_drive']}
    svc_backup  -> {LAB_CREDENTIALS['svc_backup']}
    local_admin -> {LAB_CREDENTIALS['local_admin']}

  {C.BOLD}Test gpos_full.py against the lab:{C.RESET}

    # Import and run (Python)
    import types, sys
    sys.path.insert(0, '.')
    import gpos_full

    cfg = types.SimpleNamespace(
        LDAP_CONNECT_TIMEOUT=10,
        LDAP_RECEIVE_TIMEOUT=30
    )
    result = gpos_full.get_domain_gpos(
        ip='{dc}', domain='{domain}',
        username='{user}', password='{pw}', config=cfg
    )
    import json
    print(json.dumps(result, indent=2, default=str))

  {C.BOLD}Quick SMB SYSVOL check:{C.RESET}
    smbclient //{dc}/SYSVOL -U '{domain.split('.')[0].upper()}\\{user}%{pw}'
    ls {domain}/Policies/

  {C.BOLD}GPP cPassword decrypt (standalone):{C.RESET}
    python3 -c "
    import gpos_full
    cp = '<cpassword_value_from_xml>'
    print(gpos_full._gpp_decrypt(cp))
    "

  {C.BOLD}Local offline test (no DC needed):{C.RESET}
    python3 gpo_lab_setup.py --offline -d {domain}

  {C.BOLD}Cleanup:{C.RESET}
    python3 gpo_lab_setup.py --cleanup -d {domain} --dc-ip {dc} \\
            -u {user} -p '{pw}'
    """)


# ──────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="GPO Lab Setup – synthetic AD lab for testing gpos_full.py",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
          Examples:
            # Offline mode (no DC required)
            python3 gpo_lab_setup.py --offline -d lab.local

            # Online mode – push objects to a real DC
            python3 gpo_lab_setup.py --dc-ip 192.168.1.10 -d lab.local \\
                                      -u Administrator -p 'Password123!'

            # Cleanup local files + LDAP objects
            python3 gpo_lab_setup.py --cleanup --dc-ip 192.168.1.10 \\
                                      -d lab.local -u Administrator -p 'Password123!'
        """),
    )
    p.add_argument("--dc-ip",   metavar="IP",
                   help="Domain Controller IP address")
    p.add_argument("-d", "--domain", metavar="DOMAIN", required=True,
                   help="Domain name  (e.g. lab.local)")
    p.add_argument("-u", "--username", metavar="USER", default="Administrator",
                   help="DC username for LDAP bind  (default: Administrator)")
    p.add_argument("-p", "--password", metavar="PASS", default="",
                   help="Password or NTLM hash for LDAP bind")
    p.add_argument("--offline", action="store_true",
                   help="Build local SYSVOL files only – no DC connection")
    p.add_argument("--cleanup", action="store_true",
                   help="Remove all lab artifacts (local + LDAP)")
    p.add_argument("--no-test", action="store_true",
                   help="Skip self-tests after build")
    p.add_argument("--report", metavar="FILE", default=str(REPORT_FILE),
                   help=f"Path for JSON test report  (default: {REPORT_FILE})")
    return p.parse_args()


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  GPO Lab Setup  –  gpos_full.py Test Environment{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")

    # Dependency check
    info(f"ldap3      : {'available' if HAS_LDAP3 else 'NOT FOUND (pip install ldap3)'}")
    info(f"impacket   : {'available' if HAS_IMPACKET else 'NOT FOUND (pip install impacket)'}")
    info(f"pycryptodome: {'available' if HAS_PYCRYPTO else 'NOT FOUND (pip install pycryptodome)'}")

    if args.cleanup:
        dc_ip = args.dc_ip if not args.offline else None
        cleanup(
            dc_ip=dc_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
        )
        print()
        ok("Cleanup complete")
        return

    # Build lab
    try:
        manifest = build_lab(
            domain=args.domain,
            dc_ip=args.dc_ip if not args.offline else None,
            username=args.username,
            password=args.password,
        )
    except Exception:
        err("Lab build failed:")
        traceback.print_exc()
        sys.exit(1)

    # Online mode: push to DC
    if args.dc_ip and not args.offline:
        section("LDAP Push (Online Mode)")
        if not args.password:
            warn("No password provided – skipping LDAP push")
        else:
            ldap_results = ldap_push(
                dc_ip=args.dc_ip,
                domain=args.domain,
                username=args.username,
                password=args.password,
                manifest=manifest,
            )
            manifest["ldap_push"] = ldap_results

        section("SYSVOL Push (Online Mode)")
        if not args.password:
            warn("No password provided – skipping SYSVOL push")
        else:
            sysvol_results = sysvol_push(
                dc_ip=args.dc_ip,
                domain=args.domain,
                username=args.username,
                password=args.password,
            )
            manifest["sysvol_push"] = sysvol_results

    # Self-tests
    if not args.no_test:
        test_results = run_self_tests(manifest, args.domain)
        manifest["self_tests"] = test_results

        # Save report
        report_path = Path(args.report)
        report_path.write_text(
            json.dumps(manifest, indent=2, default=str), encoding="utf-8"
        )
        ok(f"Report saved: {report_path.resolve()}")

    print_cheatsheet(args.domain, args.dc_ip)


if __name__ == "__main__":
    main()