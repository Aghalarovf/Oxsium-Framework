import json
import platform
import subprocess


def _normalize_result_list(data):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


def _run_ps_json(script: str, timeout: int = 90):
    if platform.system().lower() != 'windows':
        raise RuntimeError('Local Active Directory enumeration is only supported on Windows')

    proc = subprocess.run(
        ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or 'PowerShell execution failed').strip()
        raise RuntimeError(error)

    output = (proc.stdout or '').strip()
    if not output:
        return []
    return _normalize_result_list(json.loads(output))


def _handle_local_error(exc: Exception):
    return {
        'success': False,
        'error': str(exc),
        'code': 500,
    }


def get_local_domain_users(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try {
    $ticks = [Int64]$value
    if ($ticks -le 0 -or $ticks -eq 9223372036854775807) { return $null }
    return [datetime]::FromFileTimeUtc($ticks).ToString('o')
  } catch {
    try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
  }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$($root.defaultNamingContext)"))
$searcher.PageSize = 1000
$searcher.Filter = '(&(objectClass=user)(objectCategory=person))'
@('samaccountname','distinguishedname','displayname','objectsid','userprincipalname','description','useraccountcontrol','memberof','serviceprincipalname','pwdlastset','whencreated','whenchanged','lastlogontimestamp','logoncount') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$adminGroups = @('DOMAIN ADMINS','ENTERPRISE ADMINS','SCHEMA ADMINS','ADMINISTRATORS','ACCOUNT OPERATORS','BACKUP OPERATORS')
$items = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $uac = if ($p['useraccountcontrol'].Count) { [int64]$p['useraccountcontrol'][0] } else { 0 }
  $groups = @($p['memberof'] | ForEach-Object { if ($_ -match '^CN=([^,]+)') { $matches[1] } else { [string]$_ } })
  $spn = @($p['serviceprincipalname'] | ForEach-Object { [string]$_ })
  $sam = if ($p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { '' }
  $isAdmin = $false
  foreach ($group in $groups) {
    if ($adminGroups -contains $group.ToUpper()) { $isAdmin = $true; break }
  }
  [pscustomobject]@{
    username = $sam
    dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
    display_name = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
    sid = if ($p['objectsid'].Count) { [string]$p['objectsid'][0] } else { '' }
    upn = if ($p['userprincipalname'].Count) { [string]$p['userprincipalname'][0] } else { '' }
    description = if ($p['description'].Count) { [string]$p['description'][0] } else { '' }
    disabled = [bool]($uac -band 0x0002)
    is_admin = $isAdmin
    asrep = [bool](($uac -band 0x400000) -and $sam)
    spn = $spn
    preauth_required = -not [bool]($uac -band 0x400000)
    pwd_never_expires = [bool]($uac -band 0x10000)
    pwd_not_required = [bool]($uac -band 0x0020)
    locked_out = [bool]($uac -band 0x0010)
    must_change_pwd = if ($p['pwdlastset'].Count) { ([int64]$p['pwdlastset'][0] -eq 0) } else { $false }
    trusted_for_delegation = [bool]($uac -band 0x80000)
    member_of = $groups
    when_created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    when_changed = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
    last_logon = if ($p['lastlogontimestamp'].Count) { Convert-AdDate $p['lastlogontimestamp'][0] } else { $null }
    pwd_last_set = if ($p['pwdlastset'].Count) { Convert-AdDate $p['pwdlastset'][0] } else { $null }
    logon_count = if ($p['logoncount'].Count) { [int]$p['logoncount'][0] } else { 0 }
  }
}
@($items) | ConvertTo-Json -Depth 6 -Compress
'''
    try:
        users = _run_ps_json(script)
        return {'success': True, 'users': users, 'count': len(users)}
    except Exception as exc:
        return _handle_local_error(exc)


def get_local_domain_computers(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try {
    $ticks = [Int64]$value
    if ($ticks -le 0 -or $ticks -eq 9223372036854775807) { return $null }
    return [datetime]::FromFileTimeUtc($ticks).ToString('o')
  } catch {
    try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
  }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$($root.defaultNamingContext)"))
$searcher.PageSize = 1000
$searcher.Filter = '(objectClass=computer)'
@('samaccountname','distinguishedname','displayname','objectsid','dnshostname','description','useraccountcontrol','serviceprincipalname','operatingsystem','operatingsystemversion','pwdlastset','whencreated','whenchanged','lastlogontimestamp','location','msds-allowedtodelegateto','primarygroupid') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$cutoff = (Get-Date).ToUniversalTime().AddDays(-45)
$items = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $uac = if ($p['useraccountcontrol'].Count) { [int64]$p['useraccountcontrol'][0] } else { 0 }
  $spn = @($p['serviceprincipalname'] | ForEach-Object { [string]$_ })
  $allowed = @($p['msds-allowedtodelegateto'] | ForEach-Object { [string]$_ })
  $pwdLastSet = if ($p['pwdlastset'].Count) { Convert-AdDate $p['pwdlastset'][0] } else { $null }
  $lastLogon = if ($p['lastlogontimestamp'].Count) { Convert-AdDate $p['lastlogontimestamp'][0] } else { $null }
  $pwdDate = if ($pwdLastSet) { [datetime]::Parse($pwdLastSet) } else { $null }
  $logonDate = if ($lastLogon) { [datetime]::Parse($lastLogon) } else { $null }
  $staleByPwd = ($null -eq $pwdDate) -or ($pwdDate -lt $cutoff)
  $staleByLogon = ($null -eq $logonDate) -or ($logonDate -lt $cutoff)
  $dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
  $primaryGroupId = if ($p['primarygroupid'].Count) { [int]$p['primarygroupid'][0] } else { 0 }
  $isDC = ($dn -like '*OU=Domain Controllers*') -or ($primaryGroupId -eq 516) -or [bool]($uac -band 0x2000)
  $os = if ($p['operatingsystem'].Count) { [string]$p['operatingsystem'][0] } else { '' }
  $osBucket = if ($os.ToLower().Contains('server')) { 'server' } elseif ($os) { 'workstation' } else { 'unknown' }
  [pscustomobject]@{
    computer_name = if ($p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { '' }
    dns_name = if ($p['dnshostname'].Count) { [string]$p['dnshostname'][0] } else { '' }
    dn = $dn
    display_name = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
    sid = if ($p['objectsid'].Count) { [string]$p['objectsid'][0] } else { '' }
    description = if ($p['description'].Count) { [string]$p['description'][0] } else { '' }
    disabled = [bool]($uac -band 0x0002)
    os = $os
    os_version = if ($p['operatingsystemversion'].Count) { [string]$p['operatingsystemversion'][0] } else { '' }
    os_bucket = $osBucket
    spn = $spn
    has_spn = ($spn.Count -gt 0)
    trusted_for_delegation = [bool]($uac -band 0x80000)
    trusted_to_auth_for_delegation = [bool]($uac -band 0x1000000)
    unconstrained_delegation = [bool]($uac -band 0x80000)
    constrained_delegation = ($allowed.Count -gt 0)
    allowed_to_delegate_to = $allowed
    is_workstation = [bool]($uac -band 0x1000)
    is_server = [bool]($uac -band 0x2000)
    is_domain_controller = $isDC
    is_stale = ($staleByPwd -and $staleByLogon)
    stale_by_pwd = $staleByPwd
    stale_by_logon = $staleByLogon
    location = if ($p['location'].Count) { [string]$p['location'][0] } else { '' }
    when_created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    when_changed = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
    last_logon = $lastLogon
    pwd_last_set = $pwdLastSet
  }
}
@($items) | ConvertTo-Json -Depth 6 -Compress
'''
    try:
        computers = _run_ps_json(script)
        return {'success': True, 'computers': computers, 'count': len(computers)}
    except Exception as exc:
        return _handle_local_error(exc)


def get_local_domain_ous(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$($root.defaultNamingContext)"))
$searcher.PageSize = 1000
$searcher.Filter = '(objectClass=organizationalUnit)'
@('name','distinguishedname','description','ou','managedby','whencreated','whenchanged','gplink','gpoptions') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$items = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $gplink = if ($p['gplink'].Count) { [string]$p['gplink'][0] } else { '' }
  $gpOptions = if ($p['gpoptions'].Count) { [int]$p['gpoptions'][0] } else { 0 }
  [pscustomobject]@{
    name = if ($p['name'].Count) { [string]$p['name'][0] } else { 'Unknown OU' }
    path = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
    description = if ($p['description'].Count) { [string]$p['description'][0] } else { '' }
    type = if ($p['ou'].Count) { [string]$p['ou'][0] } else { 'OU' }
    managed_by = if ($p['managedby'].Count) { [string]$p['managedby'][0] } else { '' }
    created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    modified = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
    dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
    gpo_links = if ($gplink) { @($gplink -split '\]\[' | ForEach-Object { $_.Trim('[', ']') } | Where-Object { $_ }) } else { @() }
    has_gpo_links = [bool]$gplink
    inheritance_blocked = [bool]($gpOptions -band 1)
    delegated_permissions = [bool](if ($p['managedby'].Count) { $p['managedby'][0] } else { $null })
    is_protected = $false
  }
}
@($items) | ConvertTo-Json -Depth 6 -Compress
'''
    try:
        ous = _run_ps_json(script)
        return {'success': True, 'ous': ous, 'count': len(ous)}
    except Exception as exc:
        return _handle_local_error(exc)


def get_local_domain_gpos(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$domainDn = [string]$root.defaultNamingContext
$gpoBase = "LDAP://CN=Policies,CN=System,$domainDn"
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$gpoBase)
$searcher.PageSize = 1000
$searcher.Filter = '(objectClass=groupPolicyContainer)'
@('name','displayname','gpcfilesyspath','whencreated','whenchanged','versionnumber','flags','objectguid','managedby','gpcuserextensionnames','gpcmachineextensionnames') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$gpos = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $version = if ($p['versionnumber'].Count) { [int]$p['versionnumber'][0] } else { 0 }
  $guid = if ($p['objectguid'].Count) { ([guid]$p['objectguid'][0]).Guid } else { '' }
  $userExt = if ($p['gpcuserextensionnames'].Count) { [string]$p['gpcuserextensionnames'][0] } else { '' }
  $machineExt = if ($p['gpcmachineextensionnames'].Count) { [string]$p['gpcmachineextensionnames'][0] } else { '' }
  [pscustomobject]@{
    name = if ($p['name'].Count) { [string]$p['name'][0] } else { '' }
    guid = $guid
    display_name = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
    dn = [string]$res.Path.Replace('LDAP://', '')
    path = if ($p['gpcfilesyspath'].Count) { [string]$p['gpcfilesyspath'][0] } else { '' }
    created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    modified = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
    version = $version
    user_version = (($version -shr 16) -band 0xFFFF)
    computer_version = ($version -band 0xFFFF)
    flags = if ($p['flags'].Count) { [int]$p['flags'][0] } else { 0 }
    linked_containers = @()
    linked_count = 0
    managed_by = if ($p['managedby'].Count) { [string]$p['managedby'][0] } else { '' }
    vulnerable = [bool](if ($p['managedby'].Count) { $p['managedby'][0] } else { $null })
    has_settings_markers = [bool](($userExt + ' ' + $machineExt) -match 'script|registry|password')
    user_extensions = $userExt
    machine_extensions = $machineExt
    has_security_descriptor = $false
    gpos_data = @{}
  }
}
$linkSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainDn"))
$linkSearcher.PageSize = 1000
$linkSearcher.Filter = '(gPLink=*)'
@('distinguishedname','gplink') | ForEach-Object { [void]$linkSearcher.PropertiesToLoad.Add($_) }
$linkMap = @{}
foreach ($res in $linkSearcher.FindAll()) {
  $dn = if ($res.Properties['distinguishedname'].Count) { [string]$res.Properties['distinguishedname'][0] } else { '' }
  $gplink = if ($res.Properties['gplink'].Count) { [string]$res.Properties['gplink'][0] } else { '' }
  if (-not $gplink) { continue }
  foreach ($m in [regex]::Matches($gplink, '\{([0-9A-Fa-f\-]{36})\}')) {
    $guid = $m.Groups[1].Value
    if (-not $linkMap.ContainsKey($guid)) { $linkMap[$guid] = New-Object System.Collections.ArrayList }
    [void]$linkMap[$guid].Add($dn)
  }
}
foreach ($gpo in $gpos) {
  if ($linkMap.ContainsKey($gpo.guid)) {
    $gpo.linked_containers = @($linkMap[$gpo.guid])
    $gpo.linked_count = $gpo.linked_containers.Count
  }
}
@($gpos) | ConvertTo-Json -Depth 7 -Compress
'''
    try:
        gpos = _run_ps_json(script)
        return {'success': True, 'gpos': gpos, 'count': len(gpos)}
    except Exception as exc:
        return _handle_local_error(exc)


def get_local_domain_groups(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$($root.defaultNamingContext)"))
$searcher.PageSize = 1000
$searcher.Filter = '(objectClass=group)'
@('cn','samaccountname','distinguishedname','description','objectsid','grouptype','member','managedby','admincount','whencreated','whenchanged','memberof') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$privNames = @('DOMAIN ADMINS','ENTERPRISE ADMINS','SCHEMA ADMINS','ADMINISTRATORS','ACCOUNT OPERATORS','SERVER OPERATORS','BACKUP OPERATORS','PRINT OPERATORS')
$items = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $members = @($p['member'] | ForEach-Object { [string]$_ })
  $memberOf = @($p['memberof'] | ForEach-Object { [string]$_ })
  $sid = if ($p['objectsid'].Count) { [string]$p['objectsid'][0] } else { '' }
  $name = if ($p['cn'].Count) { [string]$p['cn'][0] } else { '' }
  $sam = if ($p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { '' }
  $groupType = if ($p['grouptype'].Count) { [int]$p['grouptype'][0] } else { 0 }
  $scope = if ($groupType -band 0x2) { 'Global' } elseif ($groupType -band 0x4) { 'Domain Local' } elseif ($groupType -band 0x8) { 'Universal' } else { 'Unknown' }
  $category = if ($groupType -band 0x80000000) { 'Security' } else { 'Distribution' }
  $isPrivileged = ($privNames -contains $name.ToUpper()) -or ($privNames -contains $sam.ToUpper()) -or ($sid -match '-(512|518|519|520|544|548|549|550)$')
  [pscustomobject]@{
    name = $name
    sam_name = $sam
    dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
    description = if ($p['description'].Count) { [string]$p['description'][0] } else { '' }
    sid = $sid
    group_type = "$category / $scope"
    group_type_raw = $groupType
    member_count = $members.Count
    members = $members
    member_of = $memberOf
    member_of_count = $memberOf.Count
    is_empty = ($members.Count -eq 0)
    is_nested = ($memberOf.Count -gt 0)
    is_privileged = $isPrivileged
    managed_by = if ($p['managedby'].Count) { [string]$p['managedby'][0] } else { '' }
    is_protected = if ($p['admincount'].Count) { [int]$p['admincount'][0] -eq 1 } else { $false }
    when_created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    when_changed = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
  }
}
@($items) | ConvertTo-Json -Depth 6 -Compress
'''
    try:
        groups = _run_ps_json(script)
        return {'success': True, 'groups': groups, 'count': len(groups)}
    except Exception as exc:
        return _handle_local_error(exc)


def get_local_domain_trusts(_config):
    script = r'''
$ErrorActionPreference = 'Stop'
function Convert-AdDate($value) {
  if ($null -eq $value -or $value -eq '') { return $null }
  if ($value -is [datetime]) { return ([datetime]$value).ToUniversalTime().ToString('o') }
  try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return [string]$value }
}
$root = [ADSI]'LDAP://RootDSE'
if (-not $root.defaultNamingContext) { throw 'No Active Directory domain context found for local session' }
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$($root.defaultNamingContext)"))
$searcher.PageSize = 1000
$searcher.Filter = '(objectClass=trustedDomain)'
@('cn','distinguishedname','flatname','trustpartner','trustdirection','trusttype','trustattributes','securityidentifier','whencreated','whenchanged') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$items = foreach ($res in $searcher.FindAll()) {
  $p = $res.Properties
  $direction = if ($p['trustdirection'].Count) { [int]$p['trustdirection'][0] } else { 0 }
  $type = if ($p['trusttype'].Count) { [int]$p['trusttype'][0] } else { 0 }
  $attr = if ($p['trustattributes'].Count) { [int]$p['trustattributes'][0] } else { 0 }
  $directionText = switch ($direction) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { 'Unknown' } }
  $typeText = switch ($type) { 1 { 'Downlevel' } 2 { 'Uplevel (Active Directory)' } 3 { 'MIT (Kerberos Realm)' } 4 { 'DCE' } default { 'Unknown' } }
  $isForest = [bool](($attr -band 0x00000008) -or ($type -eq 2))
  [pscustomobject]@{
    name = if ($p['cn'].Count) { [string]$p['cn'][0] } else { '' }
    dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
    flat_name = if ($p['flatname'].Count) { [string]$p['flatname'][0] } else { '' }
    partner = if ($p['trustpartner'].Count) { [string]$p['trustpartner'][0] } else { '' }
    direction = $directionText
    direction_raw = $direction
    trust_type = $typeText
    trust_type_raw = $type
    attributes = $attr
    inbound = ($direction -eq 1 -or $direction -eq 3)
    outbound = ($direction -eq 2 -or $direction -eq 3)
    transitive = -not [bool]($attr -band 0x00000001) -or $isForest
    forest = $isForest
    sid = if ($p['securityidentifier'].Count) { [string]$p['securityidentifier'][0] } else { '' }
    when_created = if ($p['whencreated'].Count) { Convert-AdDate $p['whencreated'][0] } else { $null }
    when_changed = if ($p['whenchanged'].Count) { Convert-AdDate $p['whenchanged'][0] } else { $null }
  }
}
@($items) | ConvertTo-Json -Depth 6 -Compress
'''
    try:
        trusts = _run_ps_json(script)
        return {'success': True, 'trusts': trusts, 'count': len(trusts)}
    except Exception as exc:
        return _handle_local_error(exc)
