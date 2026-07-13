let aclSearch          = '';
let aclTargetSearch    = '';
let aclPrincipalSearch = '';
let aclFilter          = 'all';
let aclObjectFilter    = 'all';
let aclRightsSort      = 'none';

let _aclOffset        = 0;       
const ACL_PAGE_SIZE   = 2000;
let _aclTotalInDB     = 0;       
let _aclLoading       = false;  

const ACL_FILTER_TABLE_MAP = {
  'dangerous':        'dangerous_ace',
  'extended-rights':  'extended_rights',
};
let _aclFullFetchData      = [];  
let _aclFullFetchActive    = false; 
let _aclFullFetchLoading   = false;
let _aclFullFetchToken     = 0;   

const ACL_FILTER_DEBOUNCE_MS = 450;
let _aclTargetDebounceTimer    = null;
let _aclPrincipalDebounceTimer = null;

let aclKnownPrincipalSIDs       = new Set();
let aclKnownPrincipalSIDsLoaded = false;

let aclDomainsSelected     = null;   
let aclDomainsDropdownOpen = false;

function aclItemBelongsToDomain(item, domain) {
  const dn  = item.target_dn || '';
  const sid = item.principal_sid || '';
  if (domain.sid && sid) {
    const s  = String(sid).trim().toUpperCase();
    const ds = domain.sid.toUpperCase();
    if (s === ds || s.startsWith(ds + '-')) return true;
  }
  const suffix = domainNameToDcSuffix(domain.name);
  if (!suffix) return false;
  return dn.toLowerCase().endsWith(suffix);
}

async function toggleACLDomainsDropdown(e) {
  e && e.stopPropagation();
  const dd = document.getElementById('acl-domains-dropdown');
  if (!dd) return;

  if (aclDomainsDropdownOpen) {
    closeACLDomainsDropdown();
    return;
  }

  aclDomainsDropdownOpen = true;
  dd.classList.add('show');

  const listEl = document.getElementById('acl-domains-dropdown-list');
  if (listEl) listEl.innerHTML = '<div class="domains-dropdown-loading">Loading domains…</div>';

  try {
    await ensureDomainsListLoaded();
    if (!aclDomainsSelected) {
      aclDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
    }
    renderACLDomainsDropdownList();
  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="domains-dropdown-empty">${escapeHtml(err.message)}</div>`;
  }

  document.addEventListener('click', handleACLDomainsDropdownOutsideClick);
  document.addEventListener('keydown', handleACLDomainsDropdownEscape);
}

function closeACLDomainsDropdown() {
  aclDomainsDropdownOpen = false;
  const dd = document.getElementById('acl-domains-dropdown');
  if (dd) dd.classList.remove('show');
  document.removeEventListener('click', handleACLDomainsDropdownOutsideClick);
  document.removeEventListener('keydown', handleACLDomainsDropdownEscape);
}

function handleACLDomainsDropdownOutsideClick(e) {
  const wrap = document.getElementById('acl-domains-select-wrap');
  if (wrap && !wrap.contains(e.target)) closeACLDomainsDropdown();
}

function handleACLDomainsDropdownEscape(e) {
  if (e.key === 'Escape') closeACLDomainsDropdown();
}

function renderACLDomainsDropdownList() {
  const listEl = document.getElementById('acl-domains-dropdown-list');
  if (!listEl) return;

  if (!domainsListCache || domainsListCache.length === 0) {
    listEl.innerHTML = '<div class="domains-dropdown-empty">No domains found</div>';
    return;
  }

  listEl.innerHTML = domainsListCache.map(d => {
    const key = d.name.toLowerCase();
    const checked = aclDomainsSelected.has(key);
    const sidLine = d.sid
      ? `<div class="domains-dropdown-item-sid">${escapeHtml(d.sid)}</div>`
      : `<div class="domains-dropdown-item-sid dim">SID unresolved · filtering by DN</div>`;
    return `
      <label class="domains-dropdown-item${d.isCurrent ? ' current' : ''}" data-domain="${escapeHtml(key)}">
        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleACLDomainSelected('${key.replace(/'/g, "\\'")}', this.checked)">
        <div class="domains-dropdown-item-main">
          <div class="domains-dropdown-item-top">
            <span class="domains-dropdown-item-name">${escapeHtml(d.name)}</span>
            ${d.isCurrent ? '<span class="domains-dropdown-badge">Current</span>' : '<span class="domains-dropdown-badge trust">Trust</span>'}
          </div>
          ${sidLine}
        </div>
      </label>`;
  }).join('');

  updateACLDomainsSelectCount();
}

function updateACLDomainsSelectCount() {
  const countEl = document.getElementById('acl-domains-select-count');
  if (!countEl || !domainsListCache) return;
  const total = domainsListCache.length;
  const selected = aclDomainsSelected ? aclDomainsSelected.size : total;
  if (selected >= total) {
    countEl.style.display = 'none';
  } else {
    countEl.style.display = 'inline-flex';
    countEl.textContent = `${selected}/${total}`;
  }
}

function toggleACLDomainSelected(domainKey, checked) {
  if (!aclDomainsSelected) aclDomainsSelected = new Set();
  if (checked) aclDomainsSelected.add(domainKey);
  else aclDomainsSelected.delete(domainKey);
  updateACLDomainsSelectCount();
  renderACLs();
}

function resetACLDomainsSelection() {
  if (!domainsListCache) return;
  aclDomainsSelected = new Set(domainsListCache.map(d => d.name.toLowerCase()));
  renderACLDomainsDropdownList();
  renderACLs();
}

function _normSid(value) {
  return String(value || '').trim().toUpperCase();
}

async function ensureACLKnownPrincipalSIDs() {
  const memSids = [
    ...(Array.isArray(usersData)     ? usersData.map(u     => _normSid(u?.sid))  : []),
    ...(Array.isArray(computersData) ? computersData.map(c => _normSid(c?.sid))  : []),
    ...(Array.isArray(groupsData)    ? groupsData.map(g    => _normSid(g?.sid))  : []),
  ].filter(Boolean);

  if (memSids.length > 0) {
    aclKnownPrincipalSIDs       = new Set(memSids);
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
          ...(Array.isArray(data.user_sids)     ? data.user_sids     : []),
          ...(Array.isArray(data.computer_sids) ? data.computer_sids : []),
          ...(Array.isArray(data.group_sids)    ? data.group_sids    : []),
        ];
    aclKnownPrincipalSIDs       = new Set(merged.map(_normSid).filter(Boolean));
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
function _pvSidIsInteresting(sid) { return _PV_INTERESTING_SID_RE.test(sid || ''); }

const ACL_EXCLUDED_DEFAULT_PRINCIPALS = [
  { name: 'NT AUTHORITY\\SYSTEM',                        sid: 'S-1-5-18' },
  { name: 'NT AUTHORITY\\Local Service',                 sid: 'S-1-5-19' },
  { name: 'BUILTIN\\Administrators',                     sid: 'S-1-5-32-544', rid: '-544' },
  { name: 'BUILTIN\\Account Operators',                  sid: 'S-1-5-32-548', rid: '-548' },
  { name: 'Enterprise Domain Controllers',               sid: 'S-1-5-9' },
  { name: 'Principal Self',                              sid: 'S-1-5-10' },
  { name: 'Everyone',                                    sid: 'S-1-1-0' },
  { name: 'Authenticated Users',                         sid: 'S-1-5-11' },
  { name: 'BUILTIN\\Pre-Windows 2000 Compatible Access',  sid: 'S-1-5-32-554' },
  { name: 'BUILTIN\\Windows Authorization Access Group',  sid: 'S-1-5-32-560' },
  { name: 'BUILTIN\\Terminal Server License Servers',     sid: 'S-1-5-32-561' },
  { name: 'Creator Owner',                               sid: 'S-1-3-0' },

  { name: 'Administrator',                    rid: '-500' },
  { name: 'krbtgt',                           rid: '-502' },
  { name: 'Domain Admins',                    rid: '-512' },
  { name: 'Domain Controllers',               rid: '-516' },
  { name: 'Cert Publishers',                  rid: '-517' },
  { name: 'Schema Admins',                    rid: '-518' },
  { name: 'Enterprise Admins',                rid: '-519' },
  { name: 'Group Policy Creator Owners',      rid: '-520' },
  { name: 'Key Admins',                       rid: '-526' },
  { name: 'Enterprise Key Admins',            rid: '-527' },
  { name: 'DnsAdmins',                        rid: '-1101' },
  { name: 'RAS and IAS Servers',              rid: '-553' },
  { name: 'Enterprise Read-Only Domain Controllers', rid: '-498' },

  { name: 'Administrators' },
  { name: 'Hyper-V Administrators' },
  { name: 'Storage Replica Administrators' },
  { name: 'Print Operators' },
  { name: 'Server Operators' },
  { name: 'Backup Operators' },
  { name: 'Cryptographic Operators' },
  { name: 'Remote Management Users' },
  { name: 'Only Domain Controllers' },
  { name: 'Read-only Domain Controllers' },
  { name: 'Protected Users' },
  { name: 'Cert Admins' },
  { name: 'Enterprise Cert Admins' },
  { name: 'Allowed RODC Password Replication Group' },
  { name: 'Denied RODC Password Replication Group' },
  { name: 'Cloneable Domain Controllers' },
  { name: 'Incoming Forest Trust Builders' },
  { name: 'Network Configuration Operators' },
  { name: 'Performance Log Users' },
  { name: 'Performance Monitor Users' },
];

const _ACL_EXCL_SIDS  = new Set(
  ACL_EXCLUDED_DEFAULT_PRINCIPALS.map(p => p.sid).filter(Boolean)
);
const _ACL_EXCL_RIDS  = new Set(
  ACL_EXCLUDED_DEFAULT_PRINCIPALS.map(p => p.rid).filter(Boolean)
);
const _ACL_EXCL_NAMES = new Set(
  ACL_EXCLUDED_DEFAULT_PRINCIPALS.map(p => p.name).filter(Boolean).map(n => n.toLowerCase())
);

function _matchesRidSuffix(sid, ridSet) {
  if (!sid) return false;
  for (const rid of ridSet) {
    if (sid.endsWith(rid)) return true;
  }
  return false;
}

function isExcludedDefaultPrincipal(item) {
  const sid = (item?.principal_sid || '').trim();
  if (sid && _ACL_EXCL_SIDS.has(sid)) return true;
  if (_matchesRidSuffix(sid, _ACL_EXCL_RIDS)) return true;
  const principal = String(item?.principal || '').trim().toLowerCase();
  if (principal) {
    for (const name of _ACL_EXCL_NAMES) {
      if (principal.includes(name)) return true;
    }
  }
  return false;
}

function isDangerousExcludedPrincipal(item) {
  return isExcludedDefaultPrincipal(item);
}

function isExtendedRightsExcludedPrincipal(item) {
  return isExcludedDefaultPrincipal(item);
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
  'extendedrights', 'all-extended-rights', 'addmember', 'forcechangepassword',
  'user-force-change-password', 'changepassword', 'dsreplicationgetchangesall',
  'dsreplicationgetchanges', 'dsreplicationgetchangesinfilteredset',
  'dsreplicationmanagetopology', 'dsreplicationsynchronize',
  'writemsdskeycredential', 'writemsdskeycredentiallink',
  'writemsdsallowedtoactonbehalfofotheridentity',
  'readgmsapassword', 'readlapspassword', 'validatedwritespn', 'validatednsdnsname',
  'sendas', 'receiveas', 'applygrouppolicy', 'selfmembership', 'validatedwritecomputer',
];
function _hasExtendedRight(item) {
  return hasAnyRight(aclRightsSet(item), _EXTENDED_RIGHT_VARIANTS);
}

function _hasObjectAceType(item) {
  const value = item?.object_ace_type || item?.object_acetype || '';
  const text  = String(value).trim();
  return !!text && text !== '00000000-0000-0000-0000-000000000000' && text.toLowerCase() !== 'none';
}

const _EXTENDED_RIGHT_PRIORITY_ORDER = [
  'All-Extended-Rights', 'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All',
  'DS-Replication-Get-Changes-In-Filtered-Set', 'ForceChangePassword', 'AddMember',
  'Self-Membership', 'Write-msDS-KeyCredentialLink',
  'Write-msDS-AllowedToActOnBehalfOfOtherIdentity', 'Write-msDS-AllowedToActOnBehalf',
  'Write-userAccountControl', 'Read-gMSA-Password', 'ms-Mcs-AdmPwd',
  'msLAPS-Password', 'msLAPS-EncryptedPassword', 'Validated-Write-SPN',
  'Apply-Group-Policy', 'Key-Credential-Link-Roaming', 'Validated-DNS-Host-Name',
  'Send-As', 'Receive-As', 'DS-Install-Replica',
];
const _EXTENDED_RIGHT_PRIORITY_RANK = new Map(
  _EXTENDED_RIGHT_PRIORITY_ORDER.map((name, i) => [canonicalRightName(name), i + 1])
);
const _EXTENDED_RIGHT_HIGHLIGHT_SET = new Set([
  'All-Extended-Rights', 'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All',
  'DS-Replication-Get-Changes-In-Filtered-Set', 'ForceChangePassword', 'AddMember',
  'ChangePassword', 'Self-Membership', 'Write-msDS-KeyCredentialLink',
  'Write-msDS-AllowedToActOnBehalfOfOtherIdentity', 'Write-msDS-AllowedToActOnBehalf',
  'Write-userAccountControl', 'Read-gMSA-Password', 'ms-Mcs-AdmPwd',
  'msLAPS-Password', 'msLAPS-EncryptedPassword', 'Validated-Write-SPN',
  'Apply-Group-Policy', 'Key-Credential-Link-Roaming', 'Validated-DNS-Host-Name',
  'Send-As', 'Receive-As', 'DS-Install-Replica',
].map(canonicalRightName));

function _pvExtendedRightRank(item) {
  const label = _pvObjectAceType(item);
  return _EXTENDED_RIGHT_PRIORITY_RANK.get(canonicalRightName(label)) || 999;
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
    'dsreplicationsynchronize', 'writemsdskeycredential', 'writemsdskeyCredentialLink',
    'writemsdsa', 'selfmembership', 'validatedwritespn', 'validatednsdnsname',
  ])) return true;
  return false;
}

function isDangerousACEVisible(item) {
  const rights = aclRightsSet(item);
  if (hasAnyRight(rights, [
    'dsreplicationgetchangesall', 'dsreplicationgetchanges',
    'dsreplicationgetchangesinfilteredset', 'dsreplicationmanageto', 'dsreplicationsynchronize',
  ])) return true;
  if (rights.has('selfmembership')) return true;
  const hasRealDanger = hasAnyRight(rights, [
    'genericall', 'genericwrite', 'writedacl', 'writeowner',
    'writeproperty', 'addmember', 'forcechangepassword',
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
      return !onlyKeyCredSelf;
    }
    return true;
  }
  return true;
}

function _pvUniqueKey(item) {
  const rightsKey = [...(Array.isArray(item.rights) ? item.rights : [])]
    .map(r => canonicalRightName(r)).sort().join(',');
  return [(item.target_dn || '').toLowerCase(), (item.principal_sid || '').toLowerCase(), rightsKey].join('\x00');
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
  let score = 0;
  if (has('genericall'))   score += 1000;
  if (hasAnyRight(rights, ['dsreplicationgetchangesall', 'dsreplicationgetchangesinfilteredset'])) score += 950;
  if (hasAnyRight(rights, ['forcechangepassword', 'user-force-change-password'])) score += 850;
  if (has('changepassword'))  score += 820;
  if (has('genericwrite'))    score += 800;
  if (has('writedacl'))       score += 700;
  if (has('writeowner'))      score += 650;
  if (has('dsreplicationgetchanges')) score += 600;
  if (has('addmember'))       score += 600;
  if (has('selfmembership'))  score += 580;
  if (has('writeproperty'))   score += 450;
  if (has('writemsdskeyCredentialLink') || has('writemsdskeyCredential')) score += 420;
  if (has('self'))            score += 300;
  if (has('other rights'))    score += 100;
  return score;
}

function aclUnifiedCriticalScore(item) {
  const dangerousScore = aclSeverityScore(item);
  if (!_hasObjectAceType(item)) return dangerousScore;
  const rank     = _pvExtendedRightRank(item);
  const maxRank  = _EXTENDED_RIGHT_PRIORITY_ORDER.length + 1;
  const extScore = Math.max(1, (maxRank - Math.min(rank, maxRank)) * 100);
  return dangerousScore + extScore;
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
  const isCiOi      = !!(f & (ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_OBJECT_INHERIT));
  if (isInherited && isCiOi) return 'Inherited (propagated from parent)';
  if (isInherited)            return 'Inherited';
  if (isCiOi)                 return 'Direct + propagates to children';
  return 'Direct (non-inherited)';
}
function _pvHowAssignedClass(item) {
  return (parseInt(item.ace_flags, 10) || 0) & ACE_FLAG_INHERITED ? 'dim' : 'amber';
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
function _pvAceQualifier(item) { return item.ace_qualifier || 'AccessAllowed'; }
function _pvObjectAceType(item) {
  const rights = Array.isArray(item.rights) ? item.rights : [];
  const genericRights = new Set([
    'genericall', 'genericwrite', 'writedacl', 'writeowner', 'writeproperty',
    'readproperty', 'self', 'createchild', 'deletechild', 'listchildobjects',
    'delete', 'readcontrol', 'otherrights',
  ]);
  const found = rights.find(r => {
    const k = canonicalRightName(r);
    return k && k !== 'extendedrights' && !genericRights.has(k);
  });
  return found || item.object_ace_type || 'None';
}
function _pvAclRightsLabel(item) {
  if (aclFilter === 'extended-rights' || aclFilter === 'force-change-password') {
    return _pvObjectAceType(item);
  }
  return item.rights_display || '—';
}
function _pvIdentityReferenceClass(item) {
  return item.identity_reference_class || item.principal_class || item.principal_scope || '—';
}

function matchesACLFilter(item) {
  if (aclFilter === 'all') return true;
  if (aclFilter === 'dangerous') {
    if (!_pvIsInterestingRight(item)) return false;
    const disabled = !!item.principal_is_disabled;
    if (!disabled) {
      if (!_pvSidIsInteresting(item.principal_sid))  return false;
      if (isDangerousExcludedPrincipal(item))        return false;
      if (!isKnownPrincipalSIDForDangerous(item))    return false;
    }
    return isDangerousACEVisible(item);
  }
  if (aclFilter === 'extended-rights') {
    if (isExtendedRightsExcludedPrincipal(item)) return false;
    if (!isKnownPrincipalSIDForDangerous(item))  return false;
    return _hasObjectAceType(item);
  }
  if (aclFilter === 'force-change-password') {
    return _hasObjectAceType(item) &&
           hasAnyRight(aclRightsSet(item), ['forcechangepassword', 'user-force-change-password']);
  }
  return true;
}

function _updateLoadMoreBtn() {
  const btn  = document.getElementById('acl-load-more-btn');
  const wrap = document.getElementById('acl-load-more-wrap');

  if (_aclFullFetchActive) {
    if (wrap) wrap.style.display = 'none';
    return;
  }

  const remaining = _aclTotalInDB - _aclOffset;

  if (btn && wrap) {
    if (remaining <= 0 || _aclTotalInDB === 0) {
      wrap.style.display = 'none';
    } else {
      wrap.style.display  = 'block';
      btn.style.display   = 'inline-flex';
      const nextBatch = Math.min(ACL_PAGE_SIZE, remaining);
      const fromRow   = _aclOffset + 1;
      const toRow     = _aclOffset + nextBatch;
      btn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.2"/>
          <path d="M6 3.5v5M3.5 6.5l2.5 2.5 2.5-2.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Load ${nextBatch.toLocaleString()} more ACEs
        <span style="opacity:.6;font-size:10px;">(${fromRow.toLocaleString()}\u2013${toRow.toLocaleString()} / ${_aclTotalInDB.toLocaleString()})</span>
      `;
      btn.disabled = _aclLoading;
    }
  }
}

function _updateACLDbStat() {
  const panel    = document.getElementById('acl-db-stat');
  const elTotal  = document.getElementById('acl-db-total');
  const elLoaded = document.getElementById('acl-db-loaded');
  const elPct    = document.getElementById('acl-db-pct');
  if (!panel) return;

  if (_aclTotalInDB === 0) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'flex';
  if (elTotal)  elTotal.textContent  = _aclTotalInDB.toLocaleString();
  if (elLoaded) elLoaded.textContent = _aclOffset.toLocaleString();
  if (elPct) {
    const pct = Math.round((_aclOffset / _aclTotalInDB) * 100);
    elPct.textContent = `${pct}% loaded`;
  }
}

async function prefetchACECount() {
  // Do not show any count unless the user is connected to a domain
  if (!state || !state.domain) return;

  if (_aclTotalInDB > 0) return;

  try {
    const h = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!h.ok) return;
  } catch (_) { return; }

  try {
    const resp = await fetch(`${DB_READER_BASE}/api/list/aces?offset=0&limit=1`, { method: 'GET' });
    if (!resp.ok) return;
    const data = await resp.json();
    const total = typeof data.total === 'number' ? data.total : 0;
    if (total > 0 && _aclTotalInDB === 0) {
      _aclTotalInDB = total;
      const badge = document.getElementById('nav-acl-count');
      if (badge) badge.textContent = total;
    }
  } catch (_) {  }
}

async function loadACLs() {
  if (_aclLoading) return;
  _aclLoading = true;

  document.getElementById('acl-loading').style.display = 'flex';
  document.getElementById('acl-table-body').innerHTML = '';
  closeACLDetail();

  aclData    = [];
  _aclOffset = 0;
  _aclTotalInDB = 0;
  aclDomainsSelected = null;

  // Always reset the badge when loading starts; it will be repopulated only on success
  const _aclBadge = document.getElementById('nav-acl-count');
  if (_aclBadge) _aclBadge.textContent = '—';

  _updateLoadMoreBtn();

  try {
    const h = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!h.ok) throw new Error('offline');
  } catch (_) {
    document.getElementById('acl-table-body').innerHTML =
      '<div class="acl-empty"><p>sqlite_reader.py (port 8800) is not available.</p></div>';
    document.getElementById('acl-loading').style.display = 'none';
    addLog('ACL: sqlite_reader.py (8800) is not available', 'warn');
    _aclLoading = false;
    return;
  }

  await ensureACLKnownPrincipalSIDs();

  try {
    const url  = `${DB_READER_BASE}/api/list/aces?offset=0&limit=${ACL_PAGE_SIZE}`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();

    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);

    const rows = Array.isArray(data.rows) ? data.rows : [];
    _aclTotalInDB = typeof data.total === 'number' ? data.total : rows.length;
    _aclOffset    = rows.length;

    aclData             = rows;
    enumCacheLoaded.acl = true;

    document.getElementById('nav-acl-count').textContent = _aclTotalInDB;
    document.getElementById('acl-meta').textContent =
      `${rows.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs loaded · source: domain_data.db`;

    renderACLObjectFilters();
    renderACLs();
    addLog(`Loaded from ACL DB: ${rows.length} ACE (total in DB: ${_aclTotalInDB})`, 'ok');
  } catch (err) {
    addLog(`ACL: ${err.message}`, 'err');
    document.getElementById('acl-table-body').innerHTML =
      `<div class="acl-empty"><p>${err.message}</p></div>`;
  } finally {
    document.getElementById('acl-loading').style.display = 'none';
    _aclLoading = false;
    _updateLoadMoreBtn();
    _updateACLDbStat();
  }
}

async function loadMoreACLs() {
  if (_aclLoading) return;
  if (_aclOffset >= _aclTotalInDB) {
    addLog('ACL: all ACEs are already loaded', 'info');
    _updateLoadMoreBtn();
    return;
  }

  _aclLoading = true;
  _updateLoadMoreBtn();

  const loadingIndicator = document.createElement('div');
  loadingIndicator.id        = 'acl-loadmore-indicator';
  loadingIndicator.className = 'acl-empty';
  loadingIndicator.style.padding = '12px';
  loadingIndicator.textContent   = `Loading… (${_aclOffset + 1}–${Math.min(_aclOffset + ACL_PAGE_SIZE, _aclTotalInDB)})`;
  document.getElementById('acl-table-body').appendChild(loadingIndicator);

  try {
    const url  = `${DB_READER_BASE}/api/list/aces?offset=${_aclOffset}&limit=${ACL_PAGE_SIZE}`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();

    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);

    const rows = Array.isArray(data.rows) ? data.rows : [];
    aclData   = aclData.concat(rows);
    _aclOffset += rows.length;

    if (typeof data.total === 'number') _aclTotalInDB = data.total;

    document.getElementById('nav-acl-count').textContent = _aclTotalInDB;
    document.getElementById('acl-meta').textContent =
      `${aclData.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs loaded · source: domain_data.db`;

    _appendACLRows(rows);
    renderACLObjectFilters();

    addLog(`ACL: loaded ${rows.length} more ACEs (Total: ${aclData.length} / ${_aclTotalInDB})`, 'ok');
  } catch (err) {
    addLog(`ACL loadMore: ${err.message}`, 'err');
  } finally {
    const ind = document.getElementById('acl-loadmore-indicator');
    if (ind) ind.remove();

    _aclLoading = false;
    _updateLoadMoreBtn();
    _updateACLDbStat();
  }
}

function _appendACLRows(newRows) {
  const body = document.getElementById('acl-table-body');

  const emptyEl = body.querySelector('.acl-empty');
  if (emptyEl) emptyEl.remove();

  const seen = new Set();
  if (aclFilter === 'dangerous') {
    document.querySelectorAll('.acl-row').forEach(r => {
      seen.add(r.dataset.uniqueKey || '');
    });
  }

  const frag = document.createDocumentFragment();
  newRows.forEach(item => {
    if (!matchesACLFilter(item)) return;

    if (aclFilter === 'dangerous') {
      const k = _pvDangerousUniqueKey(item);
      if (seen.has(k)) return;
      seen.add(k);
    }

    if (aclSearch && ![
      (item.target_name || ''), (item.target_dn || ''),
      (item.principal   || ''), _pvAclRightsLabel(item), (item.target_type || ''),
    ].some(s => s.toLowerCase().includes(aclSearch))) return;

    if (aclObjectFilter !== 'all' &&
        String(item.target_type || '').toLowerCase() !== aclObjectFilter) return;

    frag.appendChild(_buildACLRow(item));
  });

  body.appendChild(frag);
}

function _buildACLRow(item) {
  const row      = document.createElement('div');
  const aceFlags = parseInt(item.ace_flags, 10) || 0;
  const isDirect = !(aceFlags & ACE_FLAG_INHERITED);
  const isDanger = _pvIsInterestingRight(item) && !isDangerousExcludedPrincipal(item);
  const markDanger      = aclFilter !== 'extended-rights' && isDanger && isDirect;
  const markExtendedTop = aclFilter === 'extended-rights' && _pvExtendedRightTopTier(item);

  row.className      = 'acl-row' + (markDanger ? ' dangerous' : '') + (markExtendedTop ? ' extended-critical' : '');
  row.dataset.uniqueKey = _pvDangerousUniqueKey(item);
  row.onclick        = () => showACLDetail(item, row);

  const rightsLabel = _pvAclRightsLabel(item);
  row.innerHTML = `
    <div class="acl-cell acl-cell-target"
         title="${escapeHtml(item.target_dn || '')}"
    >${escapeHtml(item.target_name || '—')}</div>
    <div class="acl-cell acl-cell-principal"
         title="${escapeHtml(item.principal_sid || '')}"
    >${escapeHtml(item.principal || '—')}</div>
    <div class="acl-cell acl-cell-rights"
         title="${escapeHtml(rightsLabel || '')}"
    >${escapeHtml(rightsLabel || '—')}</div>
    <div class="acl-cell acl-cell-type">${escapeHtml(item.target_type || '—')}</div>
  `;
  return row;
}

function renderACLs() {
  const body = document.getElementById('acl-table-body');
  body.innerHTML = '';

  let list;
  if (_aclFullFetchActive) {
    list = _aclFullFetchData.filter(item => !isExcludedDefaultPrincipal(item));
  } else {
    list = aclData.filter(matchesACLFilter);
  }

  if (domainsListCache && aclDomainsSelected && aclDomainsSelected.size < domainsListCache.length) {
    const activeDomains = domainsListCache.filter(d => aclDomainsSelected.has(d.name.toLowerCase()));
    list = list.filter(i => activeDomains.some(d => aclItemBelongsToDomain(i, d)));
  }

  if (aclSearch) {
    const q = aclSearch;
    list = list.filter(i =>
      (i.target_name  || '').toLowerCase().includes(q) ||
      (i.target_dn    || '').toLowerCase().includes(q) ||
      (i.principal    || '').toLowerCase().includes(q) ||
      _pvAclRightsLabel(i).toLowerCase().includes(q)  ||
      (i.target_type  || '').toLowerCase().includes(q)
    );
  }
  if (aclObjectFilter !== 'all') {
    list = list.filter(i => String(i.target_type || '').toLowerCase() === aclObjectFilter);
  }
  if (aclRightsSort === 'critical-desc') {
    list = [...list].sort((a, b) => {
      if (aclFilter === 'dangerous') {
        const aE = _hasObjectAceType(a), bE = _hasObjectAceType(b);
        if (aE !== bE) return aE ? 1 : -1;
      }
      const d = aclUnifiedCriticalScore(b) - aclUnifiedCriticalScore(a);
      return d !== 0 ? d : String(a.target_name || '').localeCompare(String(b.target_name || ''));
    });
  }
  if (aclFilter === 'dangerous') {
    const seen = new Set();
    list = list.filter(i => {
      const k = _pvDangerousUniqueKey(i);
      if (seen.has(k)) return false;
      seen.add(k); return true;
    });
  }

  filteredACLs = list;

  if (!filteredACLs.length) {
    const sourceEmpty = _aclFullFetchActive ? _aclFullFetchData.length === 0 : aclData.length === 0;
    const emptyMsg = sourceEmpty
      ? (_aclFullFetchLoading ? 'Loading…' : 'No ACEs loaded from DB.')
      : aclFilter === 'dangerous'
        ? 'No ACE of interest found.'
        : 'No matching ACL entry.';
    body.innerHTML = `<div class="acl-empty"><p>${emptyMsg}</p></div>`;
    return;
  }

  const frag = document.createDocumentFragment();
  filteredACLs.forEach(item => frag.appendChild(_buildACLRow(item)));
  body.appendChild(frag);
}

function filterACLs() {
  const targetVal    = (document.getElementById('acl-target-search')?.value    || '').toLowerCase();
  const principalVal = (document.getElementById('acl-principal-search')?.value || '').toLowerCase();
  const targetChanged    = targetVal    !== aclTargetSearch;
  const principalChanged = principalVal !== aclPrincipalSearch;

  aclSearch          = (document.getElementById('acl-search')?.value || '').toLowerCase();
  aclTargetSearch    = targetVal;
  aclPrincipalSearch = principalVal;

  renderACLs();

  if (targetChanged || principalChanged) {
    _scheduleACLServerFilter();
  }
}

function _scheduleACLServerFilter() {
  if (_aclTargetDebounceTimer)    clearTimeout(_aclTargetDebounceTimer);
  if (_aclPrincipalDebounceTimer) clearTimeout(_aclPrincipalDebounceTimer);

  const fireToken = ++_aclFullFetchToken; 
  _aclTargetDebounceTimer = setTimeout(() => {
    _runACLServerSideFilter(fireToken);
  }, ACL_FILTER_DEBOUNCE_MS);
}

async function _runACLServerSideFilter(myToken) {
  const baseTable = ACL_FILTER_TABLE_MAP[aclFilter] || 'aces';

  try {
    const params = new URLSearchParams({ offset: '0' });

    if (ACL_FILTER_TABLE_MAP[aclFilter]) {
      params.set('limit', '500000');
    } else {
      params.set('limit', String(ACL_PAGE_SIZE));
    }
    if (aclTargetSearch)    params.set('target', aclTargetSearch);
    if (aclPrincipalSearch) params.set('principal', aclPrincipalSearch);

    const url  = `${DB_READER_BASE}/api/list/${baseTable}?${params.toString()}`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    if (myToken !== _aclFullFetchToken) return; 

    const rows = Array.isArray(data.rows) ? data.rows : [];

    if (ACL_FILTER_TABLE_MAP[aclFilter]) {
      _aclFullFetchActive = true;
      _aclFullFetchData   = rows;
      const visibleCount = rows.filter(item => !isExcludedDefaultPrincipal(item)).length;
      document.getElementById('acl-meta').textContent =
        `${visibleCount.toLocaleString()} / ${(data.total ?? rows.length).toLocaleString()} (filtered, default trustees removed, source: ${baseTable}) · domain_data.db`;
    } else {
      aclData       = rows;
      _aclOffset    = rows.length;
      _aclTotalInDB = typeof data.total === 'number' ? data.total : rows.length;
      document.getElementById('acl-meta').textContent =
        `${rows.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs (filtered) · source: domain_data.db`;
      _updateLoadMoreBtn();
      _updateACLDbStat();
    }

    renderACLObjectFilters();
    renderACLs();
    addLog(`ACL (${baseTable}): server-side filter — ${rows.length} sətir`, 'ok');
  } catch (err) {
    if (myToken !== _aclFullFetchToken) return;
    addLog(`ACL server-side filter: ${err.message}`, 'err');
  }
}

async function setACLFilter(filter, btn) {
  aclFilter = filter || 'all';
  document.querySelectorAll('#acl-filter-chips .chip').forEach(ch => ch.classList.remove('active'));
  if (btn) btn.classList.add('active');

  if (_aclTargetDebounceTimer)    clearTimeout(_aclTargetDebounceTimer);
  if (_aclPrincipalDebounceTimer) clearTimeout(_aclPrincipalDebounceTimer);
  _aclFullFetchToken++;

  if (aclFilter === 'force-change-password') {
    await ensureACLKnownPrincipalSIDs();
  }

  if (ACL_FILTER_TABLE_MAP[aclFilter]) {
    await ensureACLKnownPrincipalSIDs();
    await loadACLFullFilterTable(aclFilter);
    return; 
  }

  _aclFullFetchActive = false;
  _aclFullFetchData   = [];
  renderACLs();
  _updateLoadMoreBtn();
}

async function loadACLFullFilterTable(filterKey) {
  const table = ACL_FILTER_TABLE_MAP[filterKey];
  if (!table) return;

  const myToken = ++_aclFullFetchToken;
  _aclFullFetchLoading = true;
  _aclFullFetchActive  = true;

  const body = document.getElementById('acl-table-body');
  if (body) {
    body.innerHTML = '<div class="acl-empty"><p>Loading… (all matching ACEs are fetched from the database)</p></div>';
  }

  try {
    const h = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!h.ok) throw new Error('offline');
  } catch (_) {
    if (myToken === _aclFullFetchToken) {
      _aclFullFetchData = [];
      if (body) body.innerHTML = '<div class="acl-empty"><p>sqlite_reader.py (port 8800) əlçatan deyil.</p></div>';
      addLog('ACL: sqlite_reader.py (port 8800) is offline', 'warn');
    }
    _aclFullFetchLoading = false;
    return;
  }

  try {
    const params = new URLSearchParams({ offset: '0', limit: '500000' });
    if (aclTargetSearch)    params.set('target', aclTargetSearch);
    if (aclPrincipalSearch) params.set('principal', aclPrincipalSearch);

    const url  = `${DB_READER_BASE}/api/list/${table}?${params.toString()}`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);

    if (myToken !== _aclFullFetchToken) return;

    const rows = Array.isArray(data.rows) ? data.rows : [];
    _aclFullFetchData = rows;

    const visibleCount = rows.filter(item => !isExcludedDefaultPrincipal(item)).length;
    document.getElementById('acl-meta').textContent =
      `${visibleCount.toLocaleString()} / ${rows.length.toLocaleString()} ${filterKey === 'dangerous' ? 'Dangerous ACE' : 'Extended Right'} (default trustees removed, source: ${table}) · domain_data.db`;

    renderACLObjectFilters();
    renderACLs();
    _updateLoadMoreBtn();
    addLog(`ACL (${table}): ${rows.length} sətir DB-dən limitsiz yükləndi`, 'ok');
  } catch (err) {
    if (myToken !== _aclFullFetchToken) return;
    addLog(`ACL (${table}): ${err.message}`, 'err');
    _aclFullFetchData = [];
    if (body) body.innerHTML = `<div class="acl-empty"><p>${err.message}</p></div>`;
  } finally {
    if (myToken === _aclFullFetchToken) _aclFullFetchLoading = false;
  }
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
  if (sortBtn) {
    sortBtn.classList.toggle('active', aclRightsSort === 'critical-desc');
    sortBtn.textContent = aclRightsSort === 'critical-desc' ? '↓' : '↕';
  }
  renderACLs();
}

function renderACLObjectFilters() {
  const wrap = document.getElementById('acl-object-filter-scroll');
  if (!wrap) return;
  const sourceData = _aclFullFetchActive ? _aclFullFetchData : aclData;
  const types   = Array.from(new Set(sourceData.map(i => String(i?.target_type || '').trim()).filter(Boolean))).sort();
  const options = ['all', ...types];
  if (!options.some(opt => String(opt).toLowerCase() === aclObjectFilter)) aclObjectFilter = 'all';
  wrap.innerHTML = '';
  options.forEach(opt => {
    const key = opt.toLowerCase();
    const btn = document.createElement('button');
    btn.className         = `chip${key === aclObjectFilter ? ' active' : ''}`;
    btn.type              = 'button';
    btn.dataset.objFilter = key;
    btn.textContent       = opt === 'all' ? 'All' : opt;
    btn.onclick           = () => setACLObjectFilter(key, btn);
    wrap.appendChild(btn);
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
    ['ObjectDN', item.target_dn   || '—', 'accent'],
    ['Name',     item.target_name || '—', ''],
    ['Type',     item.target_type || '—', ''],
    ['Modified', fmtDate(item.modified), item.modified ? '' : 'dim'],
  ]);

  const aceFlags      = parseInt(item.ace_flags, 10) || 0;
  const aceQualifier  = _pvAceQualifier(item);
  const objectAceType = _pvObjectAceType(item);
  const aceType       = item.ace_type || 'AccessAllowed';
  const inheritFlags  = _pvInheritanceFlags(aceFlags);
  const howAssigned   = _pvHowAssigned(item);
  const howAssignedCls = _pvHowAssignedClass(item);
  const aceFlagsLabel  = _pvAceFlagsLabel(aceFlags);

  detailBody.innerHTML += detailSection('ACE Properties', [
    ['AceQualifier',     aceQualifier,                   aceQualifier === 'AccessAllowed' ? 'green' : 'red'],
    ['AceType',          aceType,                         ''],
    ['AceFlags',         aceFlagsLabel || 'None',         aceFlags ? '' : 'dim'],
    ['InheritanceFlags', inheritFlags,                    inheritFlags !== 'None' ? '' : 'dim'],
    ['ObjectAceType',    objectAceType,                   objectAceType !== 'None' ? 'amber' : 'dim'],
    ['Inherited',        howAssigned,                     howAssignedCls],
  ]);

  const iRefClass = _pvIdentityReferenceClass(item);
  detailBody.innerHTML += detailSection('IdentityReference (Principal)', [
    ['IdentityReferenceName',   item.principal        || '—', 'accent'],
    ['SecurityIdentifier',      item.principal_sid    || '—', item.principal_sid ? '' : 'dim'],
    ['IdentityReferenceDomain', item.principal_domain || (state.domain || '—'), ''],
    ['IdentityReferenceClass',  iRefClass,                    iRefClass !== '—' ? '' : 'dim'],
    ['Scope',                   item.principal_scope  || '—', ''],
  ]);

  const rights = Array.isArray(item.rights) ? item.rights : [];
  const _rightColor = (r) => {
    const k = canonicalRightName(r);
    if (['genericall','writedacl','writeowner','genericwrite',
         'dsreplicationgetchangesall','dsreplicationgetchangesinfilteredset',
         'forcechangepassword'].some(d => k.includes(canonicalRightName(d)))) return 'red';
    if (['addmember','writeproperty','selfmembership','dsreplicationgetchanges',
         'writemsdskeyCredentialLink','writemsdskeyCredential'].some(d =>
         k.includes(canonicalRightName(d)))) return 'amber';
    return '';
  };
  detailBody.innerHTML += `
    <div class="detail-section">
      <div class="detail-section-title">ActiveDirectoryRights</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">
        ${rights.length > 0
          ? rights.map(r => {
              const c = _rightColor(r);
              const style = c === 'red'
                ? 'background:rgba(255,80,80,.18);color:var(--red);border:1px solid var(--red);'
                : c === 'amber'
                  ? 'background:rgba(255,160,0,.15);color:var(--amber);border:1px solid var(--amber);'
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
  const rights = aclRightsSet(item);
  const target = item.target_type || '';
  const has    = (v) => hasAnyRight(rights, [v]);
  const notes  = [];
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