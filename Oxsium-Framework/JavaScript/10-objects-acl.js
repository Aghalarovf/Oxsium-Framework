let aclSearch          = '';
let aclTargetSearch    = '';
let aclPrincipalSearch = '';
let aclFilter          = 'all';
let aclObjectFilter    = 'all';
let aclRightsSort      = 'none';
let aclDataSource      = 'live';
let aclSessionLoaded   = {
  all: false,
  dangerous: false,
  'extended-rights': false,
};
let aclKnownPrincipalSIDs = new Set();
let aclKnownPrincipalSIDsLoaded = false;

function _normSid(value) {
  return String(value || '').trim().toUpperCase();
}

async function ensureACLKnownPrincipalSIDs() {
  const memSids = [
    ...(Array.isArray(usersData) ? usersData.map(u => _normSid(u?.sid)) : []),
    ...(Array.isArray(computersData) ? computersData.map(c => _normSid(c?.sid)) : []),
    ...(Array.isArray(groupsData) ? groupsData.map(g => _normSid(g?.sid)) : []),
  ].filter(Boolean);

  if (memSids.length > 0) {
    aclKnownPrincipalSIDs = new Set(memSids);
    aclKnownPrincipalSIDsLoaded = true;
    return;
  }

  if (aclKnownPrincipalSIDsLoaded && aclKnownPrincipalSIDs.size > 0) return;
  try {
    const resp = await fetch(`${API_BASE}/api/domain-object-sids`, { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'SID catalog fetch failed');

    const merged = Array.isArray(data.all_sids)
      ? data.all_sids
      : [
          ...(Array.isArray(data.user_sids) ? data.user_sids : []),
          ...(Array.isArray(data.computer_sids) ? data.computer_sids : []),
          ...(Array.isArray(data.group_sids) ? data.group_sids : []),
        ];

    aclKnownPrincipalSIDs = new Set(merged.map(_normSid).filter(Boolean));
    aclKnownPrincipalSIDsLoaded = aclKnownPrincipalSIDs.size > 0;
  } catch (err) {
    addLog(`ACL SID catalog: ${err.message}`, 'warn');
    aclKnownPrincipalSIDsLoaded = false;
  }
}

function isKnownPrincipalSIDForDangerous(item) {
  const sid = _normSid(item?.principal_sid);
  if (!sid) return false;
  if (!aclKnownPrincipalSIDsLoaded || aclKnownPrincipalSIDs.size === 0) return false;
  return aclKnownPrincipalSIDs.has(sid);
}

const ACE_FLAG_INHERITED         = 0x10;
const ACE_FLAG_CONTAINER_INHERIT = 0x02;
const ACE_FLAG_OBJECT_INHERIT    = 0x01;
const ACE_FLAG_INHERIT_ONLY      = 0x08;
const ACE_FLAG_NO_PROPAGATE      = 0x04;

const _PV_INTERESTING_SID_RE = /^S-1-5-.*-[1-9]\d{3,}$/;

function _pvSidIsInteresting(sid) {
  return _PV_INTERESTING_SID_RE.test(sid || '');
}

const _DANGEROUS_EXCL_SIDS = new Set([
  'S-1-5-18',
  'S-1-5-19',
  'S-1-5-32-544',
]);
const _DANGEROUS_EXCL_RIDS  = new Set([500, 502, 512, 516, 519, 520, 526, 527]);
const _DOMAIN_RID_RE         = /^S-1-5-21(?:-\d+){3}-(\d+)$/;

function isDangerousExcludedPrincipal(item) {
  const sid = (item.principal_sid || '').trim();
  if (_DANGEROUS_EXCL_SIDS.has(sid)) return true;
  const m = sid.match(_DOMAIN_RID_RE);
  if (m && _DANGEROUS_EXCL_RIDS.has(parseInt(m[1], 10))) return true;
  if (sid === 'S-1-5-32-548' && item.is_inherited === true) return true;
  return false;
}

const _EXTENDED_RIGHTS_EXCLUDED_PRINCIPALS = [
  'RAS and IAS Servers',
  'Pre-Windows 2000 Compatible Access',
  'Cert Publishers',
  'Windows Authorization Access Group',
  'Terminal Server License Servers',
  'Domain Admins',
  'Administrators',
  'Domain Controllers',
  'Enterprise Admins',
  'Schema Admins',
  'Key Admins',
  'Enterprise Key Admins',
  'Hyper-V Administrators',
  'Storage Replica Administrators',
  'Print Operators',
  'Server Operators',
  'Backup Operators',
  'Group Policy Creator Owners',
  'Cryptographic Operators',
  'DnsAdmins',
  'Remote Management Users',
  'Enterprise Read-Only Domain Controllers',
  'Only Domain Controllers',
  'Read-only Domain Controllers',
  'Protected Users',
  'Cert Admins',
  'Enterprise Cert Admins',
  'Allowed RODC Password Replication Group',
  'Denied RODC Password Replication Group',
  'Cloneable Domain Controllers',
].map(v => String(v || '').toLowerCase());

function isExtendedRightsExcludedPrincipal(item) {
  const principal = String(item?.principal || '').trim().toLowerCase();
  if (!principal) return false;
  return _EXTENDED_RIGHTS_EXCLUDED_PRINCIPALS.some(name => principal.includes(name));
}

function canonicalRightName(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function aclRightsSet(item) {
  const s = new Set();
  const addKey = (v) => { const k = canonicalRightName(v); if (k) s.add(k); };
  (Array.isArray(item?.rights) ? item.rights : []).forEach(addKey);
  const display = Array.isArray(item?.rights_display)
    ? item.rights_display
    : String(item?.rights_display || '').split(/[,;|]/);
  display.forEach(addKey);
  return s;
}

function hasAnyRight(rightsSet, variants) {
  const blob = Array.from(rightsSet).join(' ');
  return variants.some(v => {
    const k = canonicalRightName(v);
    return k && (rightsSet.has(k) || blob.includes(k));
  });
}

const _EXTENDED_RIGHT_VARIANTS = [
  'extendedrights', 'all-extended-rights',
  'addmember', 'forcechangepassword', 'user-force-change-password', 'changepassword',
  'dsreplicationgetchangesall', 'dsreplicationgetchanges',
  'dsreplicationgetchangesinfilteredset', 'dsreplicationmanagetopology', 'dsreplicationsynchronize',
  'writemsdskeycredential', 'writemsdskeycredentiallink',
  'writemsdsallowedtoactonbehalfofotheridentity',
  'readgmsapassword', 'readlapspassword',
  'validatedwritespn', 'validatednsdnsname',
  'sendas', 'receiveas', 'applygrouppolicy',
  'selfmembership', 'validatedwritecomputer'
];

function _hasExtendedRight(item) {
  const rights = aclRightsSet(item);
  return hasAnyRight(rights, _EXTENDED_RIGHT_VARIANTS);
}

function _hasObjectAceType(item) {
  const value = item?.object_ace_type || item?.object_acetype || '';
  const text = String(value).trim();
  return !!text && text !== '00000000-0000-0000-0000-000000000000' && text.toLowerCase() !== 'none';
}

function _pvAclRightsLabel(item) {
  if (aclFilter === 'extended-rights' || aclFilter === 'force-change-password') {
    return _pvObjectAceType(item);
  }
  return item.rights_display || '—';
}

const _EXTENDED_RIGHT_PRIORITY_ORDER = [
  'All-Extended-Rights',
  'DS-Replication-Get-Changes',
  'DS-Replication-Get-Changes-All',
  'DS-Replication-Get-Changes-In-Filtered-Set',
  'ForceChangePassword',
  'AddMember',
  'Self-Membership',
  'Write-msDS-KeyCredentialLink',
  'Write-msDS-AllowedToActOnBehalfOfOtherIdentity',
  'Write-msDS-AllowedToActOnBehalf',
  'Write-userAccountControl',
  'Read-gMSA-Password',
  'ms-Mcs-AdmPwd',
  'msLAPS-Password',
  'msLAPS-EncryptedPassword',
  'Validated-Write-SPN',
  'Apply-Group-Policy',
  'Key-Credential-Link-Roaming',
  'Validated-DNS-Host-Name',
  'Send-As',
  'Receive-As',
  'DS-Install-Replica',
];

const _EXTENDED_RIGHT_PRIORITY_RANK = new Map(
  _EXTENDED_RIGHT_PRIORITY_ORDER.map((name, index) => [canonicalRightName(name), index + 1])
);

const _EXTENDED_RIGHT_HIGHLIGHT_SET = new Set([
  'All-Extended-Rights',
  'DS-Replication-Get-Changes',
  'DS-Replication-Get-Changes-All',
  'DS-Replication-Get-Changes-In-Filtered-Set',
  'ForceChangePassword',
  'AddMember',
  'ChangePassword',
  'Self-Membership',
  'Write-msDS-KeyCredentialLink',
  'Write-msDS-AllowedToActOnBehalfOfOtherIdentity',
  'Write-msDS-AllowedToActOnBehalf',
  'Write-userAccountControl',
  'Read-gMSA-Password',
  'ms-Mcs-AdmPwd',
  'msLAPS-Password',
  'msLAPS-EncryptedPassword',
  'Validated-Write-SPN',
  'Apply-Group-Policy',
  'Key-Credential-Link-Roaming',
  'Validated-DNS-Host-Name',
  'Send-As',
  'Receive-As',
  'DS-Install-Replica',
].map(name => canonicalRightName(name)));

function _pvExtendedRightRank(item) {
  const label = _pvObjectAceType(item);
  const rank = _EXTENDED_RIGHT_PRIORITY_RANK.get(canonicalRightName(label));
  return rank || 999;
}

function _pvExtendedRightTopTier(item) {
  return _EXTENDED_RIGHT_HIGHLIGHT_SET.has(canonicalRightName(_pvObjectAceType(item)));
}

function _pvIsInterestingRight(item) {
  const rights = aclRightsSet(item);
  if (hasAnyRight(rights, [
    'genericall', 'genericwrite', 'writedacl', 'writeowner', 'writeproperty',
    'createchild', 'deletechild', 'delete',
  ])) return true;
  if (hasAnyRight(rights, [
    'addmember', 'forcechangepassword', 'changepassword',
    'dsreplicationgetchangesall', 'dsreplicationgetchanges',
    'dsreplicationgetchangesinfilteredset', 'dsreplicationmanageto',
    'dsreplicationsynchronize',
    'writemsdskeycredential', 'writemsdskeyCredentialLink',
    'writemsdsa',
    'selfmembership',
    'validatedwritespn', 'validatednsdnsname',
  ])) return true;
  return false;
}

function isDangerousACEVisible(item) {
  const rights = aclRightsSet(item);
  if (hasAnyRight(rights, [
    'dsreplicationgetchangesall', 'dsreplicationgetchanges',
    'dsreplicationgetchangesinfilteredset', 'dsreplicationmanageto',
    'dsreplicationsynchronize',
  ])) return true;
  if (rights.has('selfmembership')) return true;
  const hasRealDanger = hasAnyRight(rights, [
    'genericall', 'genericwrite', 'writedacl', 'writeowner', 'writeproperty',
    'addmember', 'forcechangepassword',
  ]);
  if (!hasRealDanger && rights.has('self')) return false;
  if (!hasRealDanger && hasAnyRight(rights, ['readproperty'])) return false;
  if (hasAnyRight(rights, ['writeproperty'])) {
    const sid        = (item.principal_sid || '').trim();
    const targetType = (item.target_type   || '').toLowerCase();
    if (targetType === 'domain') return true;
    if (sid === 'S-1-5-10') {
      const onlyKeyCredSelf =
        hasAnyRight(rights, ['writemsdskeyCredentialLink', 'writemsdskeycredential']) &&
        !hasAnyRight(rights, ['genericall', 'genericwrite', 'writedacl', 'writeowner',
                              'addmember', 'forcechangepassword']);
      if (onlyKeyCredSelf) return false;
      return true;
    }
    return true;
  }
  return true;
}

function _pvUniqueKey(item) {
  const rightsKey = [...(Array.isArray(item.rights) ? item.rights : [])]
    .map(r => canonicalRightName(r)).sort().join(',');
  return [
    (item.target_dn    || '').toLowerCase(),
    (item.principal_sid || '').toLowerCase(),
    rightsKey,
  ].join('\x00');
}

function _pvDangerousUniqueKey(item) {
  const rightsKey = [...(Array.isArray(item.rights) ? item.rights : [])]
    .map(r => canonicalRightName(r)).sort().join(',');
  return [
    (item.target_name   || '').toLowerCase(),
    (item.principal_sid || '').toLowerCase(),
    rightsKey,
    (item.target_type   || '').toLowerCase(),
  ].join('\x00');
}

function aclSeverityScore(item) {
  const rights = aclRightsSet(item);
  const has    = (key) => hasAnyRight(rights, [key]);
  let score    = 0;
  if (has('genericall'))   score += 1000;
  if (hasAnyRight(rights, ['dsreplicationgetchangesall', 'dsreplicationgetchangesinfilteredset'])) score += 950;
  if (hasAnyRight(rights, ['forcechangepassword', 'user-force-change-password'])) score += 850;
  if (has('changepassword')) score += 820;
  if (has('genericwrite'))  score += 800;
  if (has('writedacl'))     score += 700;
  if (has('writeowner'))    score += 650;
  if (has('dsreplicationgetchanges'))  score += 600;
  if (has('addmember'))     score += 600;
  if (has('selfmembership'))score += 580;
  if (has('writeproperty')) score += 450;
  if (has('writemsdskeyCredentialLink') || has('writemsdskeyCredential')) score += 420;
  if (has('self'))          score += 300;
  if (has('other rights'))  score += 100;
  return score;
}

function aclUnifiedCriticalScore(item) {
  const dangerousScore = aclSeverityScore(item);
  const hasExtended = _hasObjectAceType(item);
  if (!hasExtended) return dangerousScore;
  const rank = _pvExtendedRightRank(item);
  const maxRank = _EXTENDED_RIGHT_PRIORITY_ORDER.length + 1;
  const extendedScore = Math.max(1, (maxRank - Math.min(rank, maxRank)) * 100);
  return dangerousScore + extendedScore;
}

function _pvAceFlagsLabel(aceFlags) {
  const f = parseInt(aceFlags, 10) || 0;
  const parts = [];
  if (f & ACE_FLAG_INHERITED)         parts.push('Inherited');
  if (f & ACE_FLAG_CONTAINER_INHERIT) parts.push('ContainerInherit');
  if (f & ACE_FLAG_OBJECT_INHERIT)    parts.push('ObjectInherit');
  if (f & ACE_FLAG_INHERIT_ONLY)      parts.push('InheritOnly');
  if (f & ACE_FLAG_NO_PROPAGATE)      parts.push('NoPropagateInherit');
  return parts.length ? parts.join(', ') : 'None';
}

function _pvHowAssigned(item) {
  const f = parseInt(item.ace_flags, 10) || 0;
  const isInherited = !!(f & ACE_FLAG_INHERITED);
  const isCiOi     = !!(f & (ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_OBJECT_INHERIT));

  if (isInherited && isCiOi) return 'Inherited (propagated from parent)';
  if (isInherited)            return 'Inherited';
  if (isCiOi)                 return 'Direct + propagates to children';
  return 'Direct (non-inherited)';
}

function _pvHowAssignedClass(item) {
  const f = parseInt(item.ace_flags, 10) || 0;
  if (f & ACE_FLAG_INHERITED) return 'dim';
  return 'amber';
}

function _pvInheritanceFlags(aceFlags) {
  const f = parseInt(aceFlags, 10) || 0;
  if (!f) return 'None';
  const parts = [];
  if (f & ACE_FLAG_CONTAINER_INHERIT) parts.push('ContainerInherit');
  if (f & ACE_FLAG_OBJECT_INHERIT)    parts.push('ObjectInherit');
  if (f & ACE_FLAG_INHERIT_ONLY)      parts.push('InheritOnly');
  if (f & ACE_FLAG_NO_PROPAGATE)      parts.push('NoPropagateInherit');
  return parts.length ? parts.join(', ') : 'None';
}

function _pvAceQualifier(item) {
  return item.ace_qualifier || 'AccessAllowed';
}

function _pvObjectAceType(item) {
  const rights = Array.isArray(item.rights) ? item.rights : [];
  const genericRights = new Set([
    'genericall', 'genericwrite', 'writedacl', 'writeowner',
    'writeproperty', 'readproperty', 'self',
    'createchild', 'deletechild', 'listchildobjects',
    'delete', 'readcontrol', 'otherrights',
  ]);

  const found = rights.find(r => {
    const k = canonicalRightName(r);
    if (!k) return false;
    if (k === 'extendedrights') return false;
    return !genericRights.has(k);
  });
  return found || item.object_ace_type || 'None';
}

function _pvIdentityReferenceClass(item) {
  return item.identity_reference_class || item.principal_class || item.principal_scope || '—';
}

function matchesACLFilter(item) {
  if (aclFilter === 'all') return true;
  if (aclFilter === 'dangerous') {
    if (!_pvIsInterestingRight(item)) return false;

    // If principal is disabled, show its dangerous ACEs regardless of SID filters
    const disabled = !!item.principal_is_disabled;
    if (!disabled) {
      if (!_pvSidIsInteresting(item.principal_sid)) return false;
      if (isDangerousExcludedPrincipal(item))    return false;
      if (!isKnownPrincipalSIDForDangerous(item)) return false;
    }
    if (!isDangerousACEVisible(item)) return false;
    return true;
  }
  if (aclFilter === 'extended-rights') {
    if (isExtendedRightsExcludedPrincipal(item)) return false;
    if (!isKnownPrincipalSIDForDangerous(item)) return false;
    return _hasObjectAceType(item);
  }
  if (aclFilter === 'force-change-password') {
    return _hasObjectAceType(item) && hasAnyRight(aclRightsSet(item), ['forcechangepassword', 'user-force-change-password']);
  }
  return true;
}

async function loadACLs(source = 'live') {
  if (!state.connected) { addLog('ACL: domain connection required', 'warn'); return; }
  document.getElementById('acl-loading').style.display = 'flex';
  document.getElementById('acl-table-body').innerHTML = '';
  closeACLDetail();
  await ensureACLKnownPrincipalSIDs();
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), 120000);
  try {
    const resp = await fetch(`${API_BASE}/api/acl`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        ...buildEnumerationPayload(),
        acl_source: String(source || 'live').toLowerCase(),
      }),
      signal:  controller.signal,
    });
    clearTimeout(timeout);
    const data = await resp.json();
    if (!resp.ok || !data.success) throw new Error(data.error || 'Failed to load ACL entries');

    aclData             = data.acls || [];
    aclDataSource       = String(source || 'live').toLowerCase();
    enumCacheLoaded.acl = true;

    document.getElementById('nav-acl-count').textContent = aclData.length;
    const meta = data.meta || {};
    document.getElementById('acl-meta').textContent =
      `${aclData.length} ACEs · Objects: ${meta.objects_with_sd ?? 0} · Total ACEs: ${meta.aces_seen ?? 0} · Exported: ${meta.aces_exported ?? aclData.length}`;

    renderACLObjectFilters();
    renderACLs();
    addLog(String(source || '').toLowerCase().includes('snapshot')
      ? `ACL snapshot loaded: ${aclData.length} ACEs from ${meta.snapshot_path || 'cache'} (${meta.snapshot_filtered_rows ?? meta.snapshot_rows ?? aclData.length} cached rows)`
      : `Get-DomainObjectAcl: ${aclData.length} ACEs enumerated (${meta.objects_with_sd ?? 0} objects, ${meta.aces_seen ?? 0} raw ACEs)`, 'ok');
    return true;
  } catch (err) {
    clearTimeout(timeout);
    const msg = err.name === 'AbortError'
      ? 'ACL request timed out (120s). Try narrowing scope or retry.'
      : err.message;
    addLog(`ACL: ${msg}`, 'err');
    document.getElementById('acl-table-body').innerHTML = `<div class="acl-empty"><p>${msg}</p></div>`;
    return false;
  } finally {
    document.getElementById('acl-loading').style.display = 'none';
  }
}

function filterACLs() {
  aclSearch          = (document.getElementById('acl-search')?.value           || '').toLowerCase();
  aclTargetSearch    = (document.getElementById('acl-target-search')?.value    || '').toLowerCase();
  aclPrincipalSearch = (document.getElementById('acl-principal-search')?.value || '').toLowerCase();
  renderACLs();
}

async function setACLFilter(filter, btn) {
  aclFilter = filter || 'all';
  const wrap = document.getElementById('acl-filter-chips');
  if (wrap) wrap.querySelectorAll('.chip').forEach(ch => ch.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const sourceMap = {
    all: 'snapshot-all',
    dangerous: 'snapshot-dangerous',
    'extended-rights': 'snapshot-extended',
  };
  const expectedSource = sourceMap[aclFilter];
  if (expectedSource && aclSessionLoaded[aclFilter] && aclDataSource === expectedSource && Array.isArray(aclData) && aclData.length >= 0) {
    renderACLs();
    return;
  }
  if (aclFilter === 'extended-rights') {
    const ok = await loadACLs('snapshot-extended');
    if (ok) aclSessionLoaded['extended-rights'] = true;
    return;
  }
  if (aclFilter === 'all') {
    const ok = await loadACLs('snapshot-all');
    if (ok) aclSessionLoaded.all = true;
    return;
  }
  if (aclFilter === 'dangerous') {
    const ok = await loadACLs('snapshot-dangerous');
    if (ok) aclSessionLoaded.dangerous = true;
    return;
  }
  if (aclFilter === 'force-change-password') {
    await ensureACLKnownPrincipalSIDs();
  }
  renderACLs();
}

function setACLObjectFilter(filter, btn) {
  aclObjectFilter = String(filter || 'all').toLowerCase();
  const wrap = document.getElementById('acl-object-filter-scroll');
  if (wrap) wrap.querySelectorAll('.chip').forEach(ch => ch.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderACLs();
}

function setACLRightsSort(btn) {
  aclRightsSort = aclRightsSort === 'critical-desc' ? 'none' : 'critical-desc';
  const sortBtn = btn || document.getElementById('acl-rights-sort-btn');
  if (sortBtn) sortBtn.classList.toggle('active', aclRightsSort === 'critical-desc');
  if (sortBtn) sortBtn.textContent = aclRightsSort === 'critical-desc' ? '↓' : '↕';
  renderACLs();
}

function renderACLObjectFilters() {
  const wrap = document.getElementById('acl-object-filter-scroll');
  if (!wrap) return;
  const types   = Array.from(new Set(aclData.map(item => String(item?.target_type || '').trim()).filter(Boolean))).sort();
  const options = ['all', ...types];
  if (!options.some(opt => String(opt).toLowerCase() === aclObjectFilter)) aclObjectFilter = 'all';
  wrap.innerHTML = '';
  options.forEach(opt => {
    const key = opt.toLowerCase();
    const btn = document.createElement('button');
    btn.className        = `chip${key === aclObjectFilter ? ' active' : ''}`;
    btn.type             = 'button';
    btn.dataset.objFilter = key;
    btn.textContent      = opt === 'all' ? 'All' : opt;
    btn.onclick          = () => setACLObjectFilter(key, btn);
    wrap.appendChild(btn);
  });
}

function renderACLs() {
  const body = document.getElementById('acl-table-body');
  body.innerHTML = '';
  let list = aclData.filter(matchesACLFilter);
  if (aclSearch) {
    const q = aclSearch;
    list = list.filter(i =>
      (i.target_name   || '').toLowerCase().includes(q) ||
      (i.target_dn     || '').toLowerCase().includes(q) ||
      (i.principal     || '').toLowerCase().includes(q) ||
      _pvAclRightsLabel(i).toLowerCase().includes(q) ||
      (i.target_type   || '').toLowerCase().includes(q)
    );
  }
  if (aclTargetSearch) {
    list = list.filter(i =>
      (i.target_name || '').toLowerCase().includes(aclTargetSearch) ||
      (i.target_dn   || '').toLowerCase().includes(aclTargetSearch)
    );
  }
  if (aclPrincipalSearch) {
    list = list.filter(i =>
      (i.principal     || '').toLowerCase().includes(aclPrincipalSearch) ||
      (i.principal_sid || '').toLowerCase().includes(aclPrincipalSearch)
    );
  }
  if (aclObjectFilter !== 'all') {
    list = list.filter(i => String(i.target_type || '').toLowerCase() === aclObjectFilter);
  }
  if (aclRightsSort === 'critical-desc') {
    list = [...list].sort((a, b) => {
      if (aclFilter === 'dangerous') {
        const aIsExtended = _hasObjectAceType(a);
        const bIsExtended = _hasObjectAceType(b);
        if (aIsExtended !== bIsExtended) {
          return aIsExtended ? 1 : -1;
        }
      }
      const leftScore  = aclUnifiedCriticalScore(a);
      const rightScore = aclUnifiedCriticalScore(b);
      const d = rightScore - leftScore;
      return d !== 0 ? d : String(a.target_name || '').localeCompare(String(b.target_name || ''));
    });
  }
  if (aclFilter === 'dangerous') {
    const seen = new Set();
    list = list.filter(i => {
      const k = _pvDangerousUniqueKey(i);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  filteredACLs = list;
  if (!filteredACLs.length) {
    const emptyMsg = aclData.length === 0
      ? 'No ACL entries returned by server. Check bind user permissions (nTSecurityDescriptor read required).'
      : aclFilter === 'dangerous'
        ? 'No interesting ACEs found (Find-InterestingDomainAcl: no non-builtin principals with modification rights)'
        : 'No matching ACL entries.';
    body.innerHTML = `<div class="acl-empty"><p>${emptyMsg}</p></div>`;
    return;
  }
  filteredACLs.forEach(item => {
    const row      = document.createElement('div');
    const aceFlags = parseInt(item.ace_flags, 10) || 0;
    const isDirect = !(aceFlags & ACE_FLAG_INHERITED);
    const isDanger = _pvIsInterestingRight(item) && !isDangerousExcludedPrincipal(item);
    const markDanger = aclFilter !== 'extended-rights' && isDanger && isDirect;
    const markExtendedTop = aclFilter === 'extended-rights' && _pvExtendedRightTopTier(item);
    row.className = 'acl-row' + (markDanger ? ' dangerous' : '') + (markExtendedTop ? ' extended-critical' : '');
    row.onclick   = () => showACLDetail(item, row);
    const rightsLabel = _pvAclRightsLabel(item);
    const inheritBadge = '';
    row.innerHTML = `
      <div class="acl-cell acl-cell-target"
           title="${escapeHtml(item.target_dn || '')}"
      >${escapeHtml(item.target_name || '—')}${inheritBadge}</div>
      <div class="acl-cell acl-cell-principal"
           title="${escapeHtml(item.principal_sid || '')}"
      >${escapeHtml(item.principal || '—')}</div>
      <div class="acl-cell acl-cell-rights"
         title="${escapeHtml(rightsLabel || '')}"
       >${escapeHtml(rightsLabel || '—')}</div>
      <div class="acl-cell acl-cell-type">${escapeHtml(item.target_type || '—')}</div>
    `;
    body.appendChild(row);
  });
}

function showACLDetail(item, row) {
  document.querySelectorAll('.acl-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('ad-avatar').textContent = (item.target_type || 'AC').slice(0, 2).toUpperCase();
  document.getElementById('ad-name').textContent   = item.target_name || '—';
  document.getElementById('ad-dn').textContent     = item.target_dn   || '—';
  const detailBody = document.getElementById('acl-detail-body');
  detailBody.innerHTML = '';
  detailBody.innerHTML += detailSection('ObjectDN / Target', [
    ['ObjectDN',  item.target_dn   || '—', 'accent'],
    ['Name',      item.target_name || '—', ''],
    ['Type',      item.target_type || '—', ''],
    ['Modified',  fmtDate(item.modified), item.modified ? '' : 'dim'],
  ]);
  const aceFlags       = parseInt(item.ace_flags, 10) || 0;
  const aceQualifier   = _pvAceQualifier(item);
  const objectAceType  = _pvObjectAceType(item);
  const aceType        = item.ace_type || (aceFlags & ACE_FLAG_INHERITED ? 'AccessAllowed' : 'AccessAllowed');
  const inheritFlags   = _pvInheritanceFlags(aceFlags);
  const howAssigned    = _pvHowAssigned(item);
  const howAssignedCls = _pvHowAssignedClass(item);
  const aceFlagsLabel  = _pvAceFlagsLabel(aceFlags);
  detailBody.innerHTML += detailSection('ACE Properties', [
    ['AceQualifier',     aceQualifier,                  aceQualifier === 'AccessAllowed' ? 'green' : 'red'],
    ['AceType',          aceType,                        ''],
    ['AceFlags',         aceFlagsLabel || 'None',        aceFlags ? '' : 'dim'],
    ['InheritanceFlags', inheritFlags,                   inheritFlags !== 'None' ? '' : 'dim'],
    ['ObjectAceType',    objectAceType,                  objectAceType !== 'None' ? 'amber' : 'dim'],
    ['Inherited',        howAssigned,                    howAssignedCls],
  ]);
  const iRefClass = _pvIdentityReferenceClass(item);
  detailBody.innerHTML += detailSection('IdentityReference (Principal)', [
    ['IdentityReferenceName',   item.principal           || '—', 'accent'],
    ['SecurityIdentifier',      item.principal_sid       || '—', item.principal_sid ? '' : 'dim'],
    ['IdentityReferenceDomain', item.principal_domain    || (state.domain || '—'), ''],
    ['IdentityReferenceClass',  iRefClass,                       iRefClass !== '—' ? '' : 'dim'],
    ['Scope',                   item.principal_scope     || '—', ''],
  ]);
  const rights = Array.isArray(item.rights) ? item.rights : [];
  const _rightColor = (r) => {
    const k = canonicalRightName(r);
    if (['genericall','writedacl','writeowner','genericwrite',
         'dsreplicationgetchangesall','dsreplicationgetchangesinfilteredset',
         'forcechangepassword'].some(d => k.includes(canonicalRightName(d)))) return 'red';
    if (['addmember','writeproperty','selfmembership','dsreplicationgetchanges',
         'writemsdskeyCredentialLink','writemsdskeyCredential'].some(d => k.includes(canonicalRightName(d)))) return 'amber';
    return '';
  };
  detailBody.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">ActiveDirectoryRights</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">
        ${rights.length > 0
          ? rights.map(r => {
              const c = _rightColor(r);
              const style = c === 'red' ? 'background:rgba(255,80,80,.18);color:var(--red);border:1px solid var(--red);'
                          : c === 'amber' ? 'background:rgba(255,160,0,.15);color:var(--amber);border:1px solid var(--amber);'
                          : 'background:rgba(0,212,255,.1);color:var(--accent);border:1px solid var(--accent);';
              return `<div style="padding:3px 8px;border-radius:4px;font-size:11px;font-family:var(--font-mono);${style}">${escapeHtml(r)}</div>`;
            }).join('')
          : '<span class="d-val dim">—</span>'}
      </div>
    </div>`;
  const pvNotes = _pvPentestNote(item);
  if (pvNotes) {
    detailBody.innerHTML += `
      <div class="detail-section">
        <div class="detail-section-title">Pentest Note</div>
        <div style="padding:8px 0;font-size:11px;color:var(--amber);line-height:1.6;">${pvNotes}</div>
      </div>`;
  }
  document.getElementById('acl-detail').style.display = 'flex';
}

function _pvPentestNote(item) {
  const rights   = aclRightsSet(item);
  const target   = item.target_type || '';
  const has      = (v) => hasAnyRight(rights, [v]);
  const notes    = [];
  if (has('genericall'))
    notes.push('⚡ GenericAll → Full control over the object. Can reset password, modify group membership, write any attribute, or take ownership.');
  if (has('genericwrite'))
    notes.push('⚡ GenericWrite → Can write any non-protected attribute (e.g. scriptPath, servicePrincipalName for SPN-jacking).');
  if (has('writedacl'))
    notes.push('⚡ WriteDACL → Can modify the object\'s DACL, grant yourself GenericAll, then fully control the object.');
  if (has('writeowner'))
    notes.push('⚡ WriteOwner → Can take ownership of the object, then grant yourself WriteDACL → GenericAll.');
  if (hasAnyRight(rights, ['forcechangepassword', 'user-force-change-password']))
    notes.push('⚡ ForceChangePassword → Can reset the account password without knowing the current password.');
  if (has('addmember') || has('selfmembership'))
    notes.push('⚡ AddMember / Self-Membership → Can add any account (or yourself) to this group, potentially elevating privileges.');
  if (hasAnyRight(rights, ['dsreplicationgetchangesall', 'dsreplicationgetchanges']))
    notes.push('⚡ DCSync rights → Can replicate domain secrets (NTLM hashes, Kerberos keys). Run: secretsdump.py / mimikatz lsadump::dcsync.');
  if (has('writemsdskeyCredentialLink') || has('writemsdskeyCredential'))
    notes.push('⚠ Write-msDS-KeyCredentialLink → Shadow Credentials attack: inject a certificate for PKINIT authentication, obtain TGT without the password.');
  if (has('writeproperty') && target.toLowerCase() === 'domain')
    notes.push('⚠ WriteProperty on Domain → Can modify msDS-AllowedToActOnBehalfOfOtherIdentity or other critical domain attributes (RBCD, etc.).');
  return notes.join('<br>');
}

function closeACLDetail() {
  document.getElementById('acl-detail').style.display = 'none';
  document.querySelectorAll('.acl-row').forEach(r => r.classList.remove('selected'));
}
