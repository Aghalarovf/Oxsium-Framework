GENERIC_ALL_RAW      = 0x10000000
GENERIC_ALL_COMPOSED = 0x000F01FF   # AD-də expand edilmiş GenericAll

RAW_GENERIC_WRITE      = 0x40000000
GENERIC_WRITE_COMPOSED = 0x00000028  # WriteProperty(0x20) | Self(0x08)

SELF_BIT           = 0x00000008
WRITE_PROPERTY_BIT = 0x00000020
READ_PROPERTY_BIT  = 0x00000010

ACE_FLAG_INHERITED         = 0x10
ACE_FLAG_CONTAINER_INHERIT = 0x02
ACE_FLAG_OBJECT_INHERIT    = 0x01
ACE_FLAG_INHERIT_ONLY      = 0x08

INDIVIDUAL_RIGHTS: dict[str, int] = {
    "WriteDACL":        0x00040000,
    "WriteOwner":       0x00080000,
    "WriteProperty":    0x00000020,
    "ReadProperty":     0x00000010,
    "Self":             0x00000008,
    "ListChildObjects": 0x00000004,
    "DeleteChild":      0x00000002,
    "CreateChild":      0x00000001,
    "Delete":           0x00010000,
    "DeleteTree":       0x00000040,
    "ListObject":       0x00000080,
}

CONTROL_ACCESS_RIGHT = 0x00000100

ACE_TYPE_ALLOWED        = 0x00
ACE_TYPE_DENIED         = 0x01
ACE_TYPE_ALLOWED_OBJECT = 0x05
ACE_TYPE_DENIED_OBJECT  = 0x06
_ALLOWED_ACE_TYPES      = frozenset({ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT})


OBJECT_TYPE_RIGHTS: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "ChangePassword",
    "00299572-246d-11d0-a768-00aa006e0529": "Reanimate-Tombstone",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "Email-Information",

    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-In-Filtered-Set",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "1131f6af-9c07-11d1-f79f-00c04fc2dcd2": "DS-Check-Stale-Phantoms",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set-Alt",

    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-DNS-Host-Name",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-Write-SPN",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "Validated-Write-Computer",
    "05c74c5e-4deb-43b4-bf69-fa65ac53a05e": "Self-Membership",
    "bf967950-0de6-11d0-a285-00aa003049e2": "General-Information",
    "3e0abfd0-126a-11d0-a060-00aa006c33ed": "Personal-Information",
    "4c164200-20c0-11d0-a768-00aa006e0529": "Write-Account-Restrictions",
    "bf967a7f-0de6-11d0-a285-00aa003049e2": "Public-Information",

    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "Write-msDS-KeyCredentialLink",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
    "800d94d7-b7a1-42a1-b14d-7cae1423d07f": "Write-msDS-AllowedToDelegateTo",
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "Write-gPLink",
    "f30e3bbf-9ff0-11d1-b603-0000f80367c1": "Write-gPOptions",
    "bf967953-0de6-11d0-a285-00aa003049e2": "Write-logonHours",
    "bf967a0a-0de6-11d0-a285-00aa003049e2": "Write-accountExpires",
    "46a9b11d-60ae-405a-b7e8-ff8a58d456d2": "Key-Credential-Link-Roaming",
    "bf967aa8-0de6-11d0-a285-00aa003049e2": "Write-userAccountControl",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership (Property Set)",

    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",

    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "771727b1-31b8-4281-b546-253150959f4c": "Read-gMSA-Password",

    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "Reload-SSL-Certificate",

    # Qeyd: 00000000...0000 GUID real ACE-də görünmür.
    # All-Extended-Rights CONTROL_ACCESS_RIGHT biti ilə obj_guid olmadan gəlir.

    "1f298a89-de98-47b8-b5cd-572ad53d267e": "ms-Mcs-AdmPwd",
    "d3676f01-8e45-45a3-8f1a-8b2de2563a24": "ms-Mcs-AdmPwdExpirationTime",
    "e081f117-4944-4367-bb67-d5e2b56e3571": "msLAPS-Password",
    "3ff5040d-fed4-4fd0-8b83-9b9e57a76e4b": "msLAPS-PasswordExpirationTime",
    "f3531ec6-6330-4f8e-8d39-7a671fbac605": "msLAPS-EncryptedPassword",
}

EXTENDED_RIGHT_NAMES = frozenset({
    "AddMember", "ForceChangePassword", "ChangePassword",
    "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set",
    "DS-Replication-Manage-Topology", "DS-Replication-Synchronize",
    "Write-msDS-KeyCredentialLink",
    "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
    "Write-msDS-AllowedToDelegateTo",
    "Write-gPLink", "Write-gPOptions",
    "Validated-Write-SPN", "Validated-DNS-Host-Name",
    "Send-As", "Receive-As",
    "Apply-Group-Policy", "Self-Membership",
    "Validated-Write-Computer", "Read-gMSA-Password", "All-Extended-Rights",
})

# OCP: INTERESTING_RIGHTS OBJECT_TYPE_RIGHTS-dan avtomatik türədilir.
INTERESTING_RIGHTS = frozenset(
    {
        "GenericAll", "GenericWrite",
        "WriteDACL", "WriteOwner",
        "WriteProperty", "Self", "CreateChild", "DeleteChild",
        "ListChildObjects", "Delete",
        "All-Extended-Rights", "ExtendedRights", "Other Rights",
    }
    | set(INDIVIDUAL_RIGHTS)
    | set(OBJECT_TYPE_RIGHTS.values())
)

DANGEROUS_RIGHTS = frozenset({
    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
    "WriteProperty", "CreateChild", "DeleteChild", "Delete", "Self",
    "ForceChangePassword", "ChangePassword", "AddMember",
    "Write-msDS-KeyCredentialLink",
    "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
    "Write-msDS-AllowedToDelegateTo",
    "Write-gPLink", "Write-gPOptions",
    "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set",
    "DS-Replication-Manage-Topology", "DS-Replication-Synchronize",
    "Validated-Write-SPN", "Validated-Write-Computer", "Validated-DNS-Host-Name",
    "Send-As", "Receive-As",
    "All-Extended-Rights", "ExtendedRights",
    "Self-Membership", "Read-gMSA-Password",
    "Apply-Group-Policy", "Reanimate-Tombstone",
})

# OCP: AD obyekt tipləri — yeni tip üçün yalnız bu sözlüyü genişləndir
AD_OBJECT_TYPE_MAP: dict[str, str] = {
    "group":                "Group",
    "computer":             "Computer",
    "user":                 "User",
    "organizationalunit":   "OU",
    "grouppolicycontainer": "GPO",
    "domaindns":            "Domain",
}

TARGET_FILTER = "(objectClass=*)"

WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-1-0":      "Everyone",
    "S-1-5-7":      "Anonymous Logon",
    "S-1-5-10":     "Principal Self",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-18":     "NT AUTHORITY\\SYSTEM",
    "S-1-5-19":     "NT AUTHORITY\\Local Service",
    "S-1-5-20":     "NT AUTHORITY\\Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-9":      "Enterprise Domain Controllers",
    "S-1-3-0":      "Creator Owner",
    "S-1-3-1":      "Creator Group",
    # CN=System konteyneri altındakı əsas obyekt
    "CN=System":    "System Container",
}

_PRIVILEGED_RIDS = frozenset({
    "-500", "-502", "-512", "-516", "-517",
    "-518", "-519", "-520", "-544",
})
_BROAD_RIDS = frozenset({"-513", "-515", "-545"})
_BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11"})

_DEFAULT_TRUSTEE_SIDS = frozenset({
    "S-1-5-18", "S-1-5-32-544", "S-1-5-32-548",
    "S-1-5-9",  "S-1-5-10",    "S-1-1-0",
    "S-1-5-11", "S-1-5-32-554","S-1-5-32-560",
    "S-1-5-32-561", "S-1-3-0",
})
_DEFAULT_TRUSTEE_RIDS = frozenset({
    "-512", "-516", "-517", "-519", "-526", "-548",
})

_PAGED_CTRL_OID = "1.2.840.113556.1.4.319"
_SD_FLAGS       = 0x04   # DACL — ümumi sorğular üçün
_SD_FLAGS_FULL  = 0x07   # Owner + Group + DACL — sensitive template-lər üçün

# AdminSDHolder + digər kritik AD konteynerləri.
# {template_key: (dn_template, açıqlama)}
# dn_template-də {base_dn} placeholder domain üçün doldurulur.
_AD_SENSITIVE_TEMPLATES: dict[str, tuple[str, str]] = {
    "AdminSDHolder": (
        "CN=AdminSDHolder,CN=System,{base_dn}",
        "SDProp hər saatda bu template-in ACL-larını privileged obyektlərə kopyalayır. "
        "Buraya yazma hüququ olan hər principal domain-ə kalıcı backdoor qura bilər.",
    ),
    "DomainRoot": (
        "{base_dn}",
        "Domain root-un ACL-ı. DCSync, GenericAll, WriteDACL kimi hüquqlar "
        "domain-in tam kompromissinə yol aça bilər.",
    ),
    "Domain Policy": (
        "CN=Policies,CN=System,{base_dn}",
        "Qrup Policy Container. GPO-lara nəzarət domain-ə geniş nüfuz imkanı verir.",
    ),
    "AdminUsers Container": (
        "CN=Users,{base_dn}",
        "Default Users konteyneri. Privileged hesabların böyük hissəsi buradadır.",
    ),
    "Domain Controllers OU": (
        "OU=Domain Controllers,{base_dn}",
        "DC-lər bu OU-dadır. Buraya yazma hüququ DC-lərin konfiqurasiyasını dəyişdirə bilər.",
    ),
    "Schema": (
        "CN=Schema,CN=Configuration,{base_dn}",
        "AD sxemi. Sxem dəyişiklikləri bütün forest-ə təsir edir.",
    ),
    "Configuration": (
        "CN=Configuration,{base_dn}",
        "Configuration partition. Sites, Services, Subnets buradadır.",
    ),
    "RID Manager": (
        "CN=RID Manager$,CN=System,{base_dn}",
        "RID pool-unu idarə edir. Manipulyasiya SID forgery-ə yol aça bilər.",
    ),
    "Infrastructure": (
        "CN=Infrastructure,{base_dn}",
        "Infrastructure Master rolu. Cross-domain referans bütünlüyü üçün kritikdir.",
    ),
    "Password Policy": (
        "CN=Password Settings Container,CN=System,{base_dn}",
        "Fine-Grained Password Policy (PSO) konteyneri. "
        "Dəyişiklik zəif parol siyasəti tətbiq etməyə imkan verə bilər.",
    ),
    "Deleted Objects": (
        "CN=Deleted Objects,{base_dn}",
        "Silindi-obyektlər konteyneri. Tombstone reanimasiyası üçün hüquq lazımdır.",
    ),
    "Domain DNS Zones": (
        "DC=DomainDnsZones,{base_dn}",
        "AD-integrated DNS zonası. DNS qeydlərinə yazma hüququ MITM hücumuna yol aça bilər.",
    ),
    "Forest DNS Zones": (
        "DC=ForestDnsZones,{base_dn}",
        "Forest-miqyaslı DNS zonası. Bütün forest-ə MITM riski var.",
    ),
    # Yeni əlavə: CN=System konteyneri
    "System Container": (
        "CN=System,{base_dn}",
        "AdminSDHolder, RID Manager, Password Settings və Domain Policy-nin "
        "ana obyektidir. Buraya WriteDACL/GenericAll olan principal bütün "
        "uşaq konteynerləri dolayı manipulyasiya edə bilər.",
    ),
}

# Bu template-lər üçün xüsusilə təhlükəli sayılan hüquqlar
_TEMPLATE_CRITICAL_RIGHTS = frozenset({
    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
    "WriteProperty", "CreateChild", "DeleteChild",
    "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
    "Self-Membership", "ForceChangePassword",
    "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
    "Write-msDS-KeyCredentialLink",
    "All-Extended-Rights",
})

# ══════════════════════════════════════════════════════════════════════════════
# DEEP_SCAN: Tam örtüm üçün SUBTREE search bazaları
# ══════════════════════════════════════════════════════════════════════════════

# Hər biri SUBTREE ilə axtarılır; ardıcıl sıra qorunur.
# Qeyd: Schema NC, Configuration NC-nin alt-ağacıdır — ayrıca əlavə edilmir.
_DEEP_SCAN_BASES: tuple[str, ...] = (
    "{base_dn}",                    # Domain NC  — CN=System, CN=Users, OU-lar, GPO-lar
    "CN=Configuration,{base_dn}",   # Config NC  — Partitions, Services, Sites, daxil olmaqla
    "DC=DomainDnsZones,{base_dn}", # App partition — AD-integrated DNS (domain)
    "DC=ForestDnsZones,{base_dn}", # App partition — AD-integrated DNS (forest)
)

# İstifadəçi tərəfindən xüsusi qeyd edilən kritik alt-ağaclar.
# ALL_WITH_ACL-dan fərqli olaraq, DEEP_SCAN bu path-ları metadata olaraq
# izləyir və hər birinin SUBTREE-si ata-bazadan ayrı paged_search ilə
# doğrulanır — ata-baza adminLimitExceeded qaytarsa belə.
_DEEP_SCAN_CRITICAL_SUBTREES: tuple[tuple[str, str], ...] = (
    # (dn_template, açıqlama)
    (
        "CN=System,{base_dn}",
        "CN=System — AdminSDHolder, Password Settings Container, MicrosoftDNS",
    ),
    (
        "CN=Policies,CN=System,{base_dn}",
        "CN=Policies — GPO-ların struktur icazələri",
    ),
    (
        "CN=Partitions,CN=Configuration,{base_dn}",
        "CN=Partitions — naming context cross-reference-ləri",
    ),
    (
        "CN=Services,CN=Configuration,{base_dn}",
        "CN=Services — PublicKeyServices, RRAS, NTDS daxil olmaqla",
    ),
    (
        "CN=Sites,CN=Configuration,{base_dn}",
        "CN=Sites — replication topology və site link ACL-ları",
    ),
)