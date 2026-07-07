/* ═══════════════════════════════════════════════════
   10-objects-acl.js
   ACL tab: load, render, filter, detail panel.
   Depends on: 00-globals.js
   Data source: YALNIZ sqlite_reader.py (port 8800) — JSONL oxunmur.

   Yükləmə strategiyası (RAM partlaması qarşısı):
     loadACLs()     → offset=0,  limit=50000 (first batch)
     loadMoreACLs() → offset+=50000 each call (next batch)
   Hər iki funksiya HTML-dən birbaşa çağırıla bilər.
   ═══════════════════════════════════════════════════ */

/* ─── State ──────────────────────────────────────────────────────────────── */
let aclSearch          = '';
let aclTargetSearch    = '';
let aclPrincipalSearch = '';
let aclFilter          = 'all';
let aclObjectFilter    = 'all';
let aclRightsSort      = 'none';

/* Pagination state */
let _aclOffset        = 0;       // şimdiki yüklənmiş sətir sayı
const ACL_PAGE_SIZE   = 2000;
let _aclTotalInDB     = 0;       // DB-dəki ümumi ACE sayı (ilk sorğudan gəlir)
let _aclLoading       = false;   // paralel sorğuların qarşısını alır

/* ─── Dangerous ACEs / Extended Rights — limitsiz tam-cədvəl yüklənməsi ───
   Bu iki filter 'aces' cədvəlinin 2K-lik səhifəsi üzərində İŞLƏMİR —
   onların öz xüsusi SQLite cədvəlləri var (dangerous_ace, extended_rights),
   hər ikisi 2000 limitindən çox-çox kiçikdir, ona görə bir sorğuda tam çəkilir. */
const ACL_FILTER_TABLE_MAP = {
  'dangerous':        'dangerous_ace',
  'extended-rights':  'extended_rights',
};
let _aclFullFetchData      = [];    // aktiv full-fetch filterinin (limitsiz) sətirləri
let _aclFullFetchActive    = false; // hazırda 'dangerous' / 'extended-rights' rejimindəyik?
let _aclFullFetchLoading   = false;
let _aclFullFetchToken     = 0;     // köhnə cavabların gec gəlib data üzərinə yazmasının qarşısını alır

/* ─── Filter Target / Filter Principal — server-side debounce sorğusu ───
   İstifadəçi yazdıqca hər keystroke-da sorğu getmir; 3 saniyə fasilə
   (debounce) tələb olunur, sonra aktiv cədvələ uyğun server-side
   WHERE target_name/target_dn LIKE... və ya principal/principal_sid LIKE...
   sorğusu göndərilir. */
const ACL_FILTER_DEBOUNCE_MS = 3000;
let _aclTargetDebounceTimer    = null;
let _aclPrincipalDebounceTimer = null;

let aclKnownPrincipalSIDs       = new Set();
let aclKnownPrincipalSIDsLoaded = false;

/* ── Select Domains (ACEs tab) ──
   Users tabındakı paylaşılan domainsListCache/ensureDomainsListLoaded()
   (03-objects-users.js) istifadə olunur; ACEs tabına aid yalnız seçim
   state-i (aclDomainsSelected) və dropdown UI-si burada saxlanılır.
   Uyğunluq ACE-nin target obyektinin domenini müəyyən edir: əvvəlcə
   principal_sid domain SID prefiksinə görə (əgər hədəf sistemi principal
   kimi eyni domendədirsə), sonra isə target_dn son hissəsinə (dc=...)
   görə yoxlanılır. */
let aclDomainsSelected     = null;   // Set<string> (lowercased domain names) — null = hamısı seçili
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

/* ─── SID utility ────────────────────────────────────────────────────────── */
function _normSid(value) {
  return String(value || '').trim().toUpperCase();
}

async function ensureACLKnownPrincipalSIDs() {
  /* Əgər usersData/computersData/groupsData artıq yüklüdürsə, oradan al */
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

  /* Fallback: connection.py-dən SID kataloqu */
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

/* ─── ACE flag constants ─────────────────────────────────────────────────── */
const ACE_FLAG_INHERITED         = 0x10;
const ACE_FLAG_CONTAINER_INHERIT = 0x02;
const ACE_FLAG_OBJECT_INHERIT    = 0x01;
const ACE_FLAG_INHERIT_ONLY      = 0x08;
const ACE_FLAG_NO_PROPAGATE      = 0x04;

/* ─── Principal / rights helpers ─────────────────────────────────────────── */
const _PV_INTERESTING_SID_RE = /^S-1-5-.*-[1-9]\d{3,}$/;
function _pvSidIsInteresting(sid) { return _PV_INTERESTING_SID_RE.test(sid || ''); }

/* ═══════════════════════════════════════════════════════════════════════
   ACL_EXCLUDED_DEFAULT_PRINCIPALS — TƏK massiv (single source of truth).

   Dangerous ACEs və Extended Rights filterlərinin HƏR İKİSİ məhz bu
   massivi istifadə edir. Massivdəki hər giriş bir built-in/default AD
   trustee-ni təmsil edir və 3 açarla uyğunlaşdırılır (hamısı optional,
   ən azı biri doldurulur):
     sid  — tam SID uyğunluğu (well-known/BUILTIN SID-lər)
     rid  — SID sonluğu (domen fərqli olsa belə, unresolved SID-lərdə də tutur)
     name — principal adında substring axtarışı (case-insensitive)

   Bu obyektlərdən biri uyğun gələrsə, həmin ACE nə Dangerous ACEs, nə də
   Extended Rights nəticələrində Principal olaraq göstərilmir — çünki
   bunlar hər domendə default olaraq mövcud olan, gözlənilən ACE-lərdir
   (əsl privilege-escalation yolu deyil, "noise").

   Mənbə: constants.py (_DEFAULT_TRUSTEE_SIDS, _DEFAULT_TRUSTEE_RIDS,
   _PRIVILEGED_RIDS, _DANGEROUS_ACE_NOISY_*, _EXTENDED_RIGHTS_NOISY_*) və
   əvvəlki frontend-only istisnalar.
   ═══════════════════════════════════════════════════════════════════════ */
const ACL_EXCLUDED_DEFAULT_PRINCIPALS = [
  /* ── Well-known / BUILTIN SID-lər ── */
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

  /* ── Domain-relative well-known RID-lər ── */
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

  /* ── Yalnız ad-əsaslı (RID/SID sabit deyil və ya BUILTIN-də göstərilmir) ── */
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

/* Massivdən sürətli axtarış üçün 3 lookup dəsti qurulur (bir dəfə, modul
   yüklənəndə). Yeni bir default trustee əlavə etmək üçün YALNIZ yuxarıdakı
   ACL_EXCLUDED_DEFAULT_PRINCIPALS massivinə sətir əlavə etmək kifayətdir —
   bu 3 dəst və aşağıdakı isExcludedDefaultPrincipal() avtomatik yenilənir. */
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

/* Bir ACE-nin principal-ının ACL_EXCLUDED_DEFAULT_PRINCIPALS massivində
   olub-olmadığını yoxlayır. Həm Dangerous ACEs, həm də Extended Rights
   filteri bu TƏK funksiyanı çağırır. */
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

/* Geriyə uyğunluq üçün nazik wrapper-lər — matchesACLFilter() və digər
   render funksiyaları bu adları çağırır, hər ikisi eyni tək mənbəyə
   (isExcludedDefaultPrincipal) yönləndirilir. */
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

/* ─── Extended-right priority ────────────────────────────────────────────── */
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

/* ─── Right classification ───────────────────────────────────────────────── */
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

/* ─── Unique key helpers ─────────────────────────────────────────────────── */
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

/* ─── Severity scoring ───────────────────────────────────────────────────── */
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

/* ─── Label helpers ──────────────────────────────────────────────────────── */
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

/* ─── Filter predicate ───────────────────────────────────────────────────── */
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

/* ─── "Load More" düyməsini yenilə ──────────────────────────────────────── */
function _updateLoadMoreBtn() {
  const btn  = document.getElementById('acl-load-more-btn');
  const wrap = document.getElementById('acl-load-more-wrap');

  /* Dangerous ACEs / Extended Rights rejimində bütün sətirlər artıq
     limitsiz çəkilib — "Load More" mənasızdır, gizlət. */
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

/* ─── DB stat panelini yenilə ─────────────────────────────────────────── */
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

/* ─── ACE ümumi sayını əvvəlcədən göstər (yüngül sorğu) ─────────────────────── */
async function prefetchACECount() {
  /* Tab açılmadan da nav badge-ini doldurur — yalnız 1 sətir çəkir, yüksüz. */
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
  } catch (_) { /* sessizce yox ol */ }
}

/* ═══════════════════════════════════════════════════════════════════════════
   loadACLs()
   ─────────────────────────────────────────────────────────────────────────
   Loads first batch from DB, writes to aclData, renders.
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadACLs() {
  if (_aclLoading) return;
  _aclLoading = true;

  document.getElementById('acl-loading').style.display = 'flex';
  document.getElementById('acl-table-body').innerHTML = '';
  closeACLDetail();

  /* Sıfırla */
  aclData    = [];
  _aclOffset = 0;
  _aclTotalInDB = 0;
  aclDomainsSelected = null;
  _updateLoadMoreBtn();

  /* sqlite_reader sağlamlıq yoxlaması */
  try {
    const h = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!h.ok) throw new Error('offline');
  } catch (_) {
    document.getElementById('acl-table-body').innerHTML =
      '<div class="acl-empty"><p>sqlite_reader.py (port 8800) əlçatan deyil.</p></div>';
    document.getElementById('acl-loading').style.display = 'none';
    addLog('ACL: sqlite_reader.py (8800) əlçatan deyil', 'warn');
    _aclLoading = false;
    return;
  }

  await ensureACLKnownPrincipalSIDs();

  try {
    /* /api/list/aces?offset=0&limit=50000 */
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
      `${rows.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs yükləndi · source: domain_data.db`;

    renderACLObjectFilters();
    renderACLs();
    addLog(`ACL DB-dən yükləndi: ${rows.length} ACE (cəmi DB-də: ${_aclTotalInDB})`, 'ok');
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

/* ═══════════════════════════════════════════════════════════════════════════
   loadMoreACLs()
   ─────────────────────────────────────────────────────────────────────────
   Fetches next batch from DB, appends to aclData.
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadMoreACLs() {
  if (_aclLoading) return;
  if (_aclOffset >= _aclTotalInDB) {
    addLog('ACL: bütün ACE-lər artıq yüklənib', 'info');
    _updateLoadMoreBtn();
    return;
  }

  _aclLoading = true;
  _updateLoadMoreBtn();

  /* Yüklənir göstərgəsi — mövcud cədvəlin altında */
  const loadingIndicator = document.createElement('div');
  loadingIndicator.id        = 'acl-loadmore-indicator';
  loadingIndicator.className = 'acl-empty';
  loadingIndicator.style.padding = '12px';
  loadingIndicator.textContent   = `Yüklənir… (${_aclOffset + 1}–${Math.min(_aclOffset + ACL_PAGE_SIZE, _aclTotalInDB)})`;
  document.getElementById('acl-table-body').appendChild(loadingIndicator);

  try {
    const url  = `${DB_READER_BASE}/api/list/aces?offset=${_aclOffset}&limit=${ACL_PAGE_SIZE}`;
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();

    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);

    const rows = Array.isArray(data.rows) ? data.rows : [];

    /* aclData-ya əlavə et (mövcud filter/render üzərindən işləyəcək) */
    aclData   = aclData.concat(rows);
    _aclOffset += rows.length;

    /* Total-i yenilə (serverdən gələn dəyərə etibar et) */
    if (typeof data.total === 'number') _aclTotalInDB = data.total;

    document.getElementById('nav-acl-count').textContent = _aclTotalInDB;
    document.getElementById('acl-meta').textContent =
      `${aclData.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs yükləndi · source: domain_data.db`;

    /* Yalnız yeni əlavə olunan sətirləri render et (mövcudları toxunmadan qal) */
    _appendACLRows(rows);
    renderACLObjectFilters();

    addLog(`ACL: daha ${rows.length} ACE əlavə edildi (cəmi: ${aclData.length} / ${_aclTotalInDB})`, 'ok');
  } catch (err) {
    addLog(`ACL loadMore: ${err.message}`, 'err');
  } finally {
    /* Yüklənir göstəriciyi sil */
    const ind = document.getElementById('acl-loadmore-indicator');
    if (ind) ind.remove();

    _aclLoading = false;
    _updateLoadMoreBtn();
    _updateACLDbStat();
  }
}

/* ─── Yalnız yeni gələn sətirləri DOM-a əlavə et ────────────────────────── */
function _appendACLRows(newRows) {
  const body = document.getElementById('acl-table-body');

  /* Əgər cədvəl "boş" mesajı göstərirsə, sıfırla */
  const emptyEl = body.querySelector('.acl-empty');
  if (emptyEl) emptyEl.remove();

  /* Mövcud filterləri tətbiq et, yalnız uyğun sətirləri əlavə et */
  const seen = new Set();
  if (aclFilter === 'dangerous') {
    document.querySelectorAll('.acl-row').forEach(r => {
      seen.add(r.dataset.uniqueKey || '');
    });
  }

  const frag = document.createDocumentFragment();
  newRows.forEach(item => {
    if (!matchesACLFilter(item)) return;

    /* Dangerous filter-də duplicate-lər */
    if (aclFilter === 'dangerous') {
      const k = _pvDangerousUniqueKey(item);
      if (seen.has(k)) return;
      seen.add(k);
    }

    /* Mövcud axtarış filterlərini yoxla */
    if (aclSearch && ![
      (item.target_name || ''), (item.target_dn || ''),
      (item.principal   || ''), _pvAclRightsLabel(item), (item.target_type || ''),
    ].some(s => s.toLowerCase().includes(aclSearch))) return;

    if (aclTargetSearch && ![
      (item.target_name || ''), (item.target_dn || ''),
    ].some(s => s.toLowerCase().includes(aclTargetSearch))) return;

    if (aclPrincipalSearch && ![
      (item.principal || ''), (item.principal_sid || ''),
    ].some(s => s.toLowerCase().includes(aclPrincipalSearch))) return;

    if (aclObjectFilter !== 'all' &&
        String(item.target_type || '').toLowerCase() !== aclObjectFilter) return;

    frag.appendChild(_buildACLRow(item));
  });

  body.appendChild(frag);
}

/* ─── Tək ACL sırasını DOM elementinə çevir ─────────────────────────────── */
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

/* ─── Full render (filter/sort dəyişdikdə) ──────────────────────────────── */
function renderACLs() {
  const body = document.getElementById('acl-table-body');
  body.innerHTML = '';

  /* Dangerous ACEs / Extended Rights aktivdirsə, mənbə aclData yox,
     limitsiz çəkilmiş _aclFullFetchData-dır. Bu sətirlər artıq uyğun
     SQLite cədvəlindən (dangerous_ace / extended_rights) gəlir, lakin
     həmin cədvəllər RAW ACL nəticələridir — default/built-in trustee
     istisnası (ACL_EXCLUDED_DEFAULT_PRINCIPALS) server tərəfində
     TƏTBİQ OLUNMUR (bax api.py: dangerous_ace() funksiyası mövcuddur,
     amma heç bir yerdən çağırılmır — collector.py bunu wire etməyib).
     Ona görə matchesACLFilter() burda ÇAĞIRILMASA da (o, 'aces' bazasına
     aid digər şərtləri ehtiva edir və full-fetch üçün uyğun deyil),
     isExcludedDefaultPrincipal() mütləq tətbiq olunmalıdır — əks halda
     Dangerous ACEs / Extended Rights nəticələrində SYSTEM, Domain Admins,
     DnsAdmins və digər default trustee-lər görünməyə davam edər. */
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
  /* Filter Target / Filter Principal: full-fetch rejimində bu süzgəc artıq
     server-side (debounce sorğusu ilə) tətbiq olunub gəlib — burda təkrar
     client-side filterləmə yalnız debounce gözlədiyi 3 saniyəlik aralıqda
     köhnə nəticənin üstündə əlavə dəqiqləşdirmə kimi işləyir, ziyansızdır. */
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
      ? (_aclFullFetchLoading ? 'Yüklənir…' : 'DB-dən heç bir ACE yüklənməyib.')
      : aclFilter === 'dangerous'
        ? 'Maraqlı ACE tapılmadı.'
        : 'Uyğun ACL girişi yoxdur.';
    body.innerHTML = `<div class="acl-empty"><p>${emptyMsg}</p></div>`;
    return;
  }

  /* DocumentFragment — toplu DOM əlavəsi, hər sətirdə reflow yoxdur */
  const frag = document.createDocumentFragment();
  filteredACLs.forEach(item => frag.appendChild(_buildACLRow(item)));
  body.appendChild(frag);
}

/* ─── Filter / Search ────────────────────────────────────────────────────── */
function filterACLs() {
  const targetVal    = (document.getElementById('acl-target-search')?.value    || '').toLowerCase();
  const principalVal = (document.getElementById('acl-principal-search')?.value || '').toLowerCase();
  const targetChanged    = targetVal    !== aclTargetSearch;
  const principalChanged = principalVal !== aclPrincipalSearch;

  aclSearch          = (document.getElementById('acl-search')?.value || '').toLowerCase();
  aclTargetSearch    = targetVal;
  aclPrincipalSearch = principalVal;

  /* Dərhal mövcud (artıq yüklənmiş) data üzərində client-side render —
     istifadəçi yazarkən boş ekran görməsin. */
  renderACLs();

  /* Target / Principal dəyişdikdə isə 3 saniyəlik debounce ilə aktiv
     cədvələ server-side sorğu göndər (yazı dayanandan 3 san sonra). */
  if (targetChanged || principalChanged) {
    _scheduleACLServerFilter();
  }
}

/* ─── Filter Target / Filter Principal — 3 saniyəlik debounce server sorğusu ───
   Hər keystroke timer-i sıfırlayır; yazı 3 saniyə dayananda DB-yə
   server-side WHERE target_name/target_dn LIKE... və/və ya
   principal/principal_sid LIKE... sorğusu göndərilir, nəticə aktiv
   filterin mənbəyinə (aclData və ya _aclFullFetchData) yazılıb render olunur. */
function _scheduleACLServerFilter() {
  if (_aclTargetDebounceTimer)    clearTimeout(_aclTargetDebounceTimer);
  if (_aclPrincipalDebounceTimer) clearTimeout(_aclPrincipalDebounceTimer);

  const fireToken = ++_aclFullFetchToken; // eyni token sistemi — gecikmiş cavabları ləğv edir
  _aclTargetDebounceTimer = setTimeout(() => {
    _runACLServerSideFilter(fireToken);
  }, ACL_FILTER_DEBOUNCE_MS);
}

async function _runACLServerSideFilter(myToken) {
  const baseTable = ACL_FILTER_TABLE_MAP[aclFilter] || 'aces';

  try {
    const params = new URLSearchParams({ offset: '0' });
    /* Dangerous/Extended Rights cədvəlləri kiçikdir → limitsiz çək.
       'aces' üçünsə hələ də ACL_PAGE_SIZE tətbiq olunur (2K limiti qalır,
       çünki bu sorğu yalnız Target/Principal axtarışını server-də işlədir,
       əsas 'aces' tabının pagination siyasətini dəyişmir). */
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
    if (myToken !== _aclFullFetchToken) return; // başqa sorğu/filter dəyişimi bunu artıq köhnəltdi

    const rows = Array.isArray(data.rows) ? data.rows : [];

    if (ACL_FILTER_TABLE_MAP[aclFilter]) {
      _aclFullFetchActive = true;
      _aclFullFetchData   = rows;
      const visibleCount = rows.filter(item => !isExcludedDefaultPrincipal(item)).length;
      document.getElementById('acl-meta').textContent =
        `${visibleCount.toLocaleString()} / ${(data.total ?? rows.length).toLocaleString()} (filtrlənmiş, default trustee-lər çıxarılıb, source: ${baseTable}) · domain_data.db`;
    } else {
      aclData       = rows;
      _aclOffset    = rows.length;
      _aclTotalInDB = typeof data.total === 'number' ? data.total : rows.length;
      document.getElementById('acl-meta').textContent =
        `${rows.length.toLocaleString()} / ${_aclTotalInDB.toLocaleString()} ACEs (filtrlənmiş) · source: domain_data.db`;
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

  /* Filter düyməsi dəyişdikdə, gözləyən debounce sorğusu varsa ləğv et —
     köhnə filterə aid gecikmiş nəticə yeni rejimə qarışmasın. */
  if (_aclTargetDebounceTimer)    clearTimeout(_aclTargetDebounceTimer);
  if (_aclPrincipalDebounceTimer) clearTimeout(_aclPrincipalDebounceTimer);
  _aclFullFetchToken++;

  if (aclFilter === 'force-change-password') {
    await ensureACLKnownPrincipalSIDs();
  }

  /* ── Dangerous ACEs / Extended Rights: 2K limitini keçərək DB-dəki bütün
     uyğun sətirləri xüsusi cədvəldən (dangerous_ace / extended_rights) çək. ── */
  if (ACL_FILTER_TABLE_MAP[aclFilter]) {
    await ensureACLKnownPrincipalSIDs();
    await loadACLFullFilterTable(aclFilter);
    return; // loadACLFullFilterTable artıq renderACLs()-i çağırır
  }

  /* 'all' və ya digər yüngül filterlərə qayıdış — normal paginated aclData-ya keç */
  _aclFullFetchActive = false;
  _aclFullFetchData   = [];
  renderACLs();
  _updateLoadMoreBtn();
}

/* ═══════════════════════════════════════════════════════════════════════════
   loadACLFullFilterTable(filterKey)
   ─────────────────────────────────────────────────────────────────────────
   'Dangerous ACEs' və ya 'Extended Rights' düyməsi basıldıqda çağırılır.
   ACL_PAGE_SIZE (2000) limitini bypass edib, həmin filterin öz xüsusi
   SQLite cədvəlindən (dangerous_ace / extended_rights) BÜTÜN sətirləri
   bir dəfəyə çəkir — bu cədvəllər artıq kiçikdir (yüzlərlə sətir),
   ona görə limitsiz tək sorğu təhlükəsizdir.
   Aktiv Filter Target / Filter Principal dəyərləri varsa, onlar da
   server-side ötürülür ki, nəticə əvvəlcədən süzülmüş gəlsin.
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadACLFullFilterTable(filterKey) {
  const table = ACL_FILTER_TABLE_MAP[filterKey];
  if (!table) return;

  const myToken = ++_aclFullFetchToken;
  _aclFullFetchLoading = true;
  _aclFullFetchActive  = true;

  const body = document.getElementById('acl-table-body');
  if (body) {
    body.innerHTML = '<div class="acl-empty"><p>Yüklənir… (DB-dən bütün uyğun ACE-lər çəkilir)</p></div>';
  }

  try {
    const h = await fetch(`${DB_READER_BASE}/api/health`, { method: 'GET' });
    if (!h.ok) throw new Error('offline');
  } catch (_) {
    if (myToken === _aclFullFetchToken) {
      _aclFullFetchData = [];
      if (body) body.innerHTML = '<div class="acl-empty"><p>sqlite_reader.py (port 8800) əlçatan deyil.</p></div>';
      addLog('ACL: sqlite_reader.py (8800) əlçatan deyil', 'warn');
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

    /* Köhnə / artıq keçərliliyini itirmiş cavabı buraxma (sürətli filter dəyişimi zamanı) */
    if (myToken !== _aclFullFetchToken) return;

    const rows = Array.isArray(data.rows) ? data.rows : [];
    _aclFullFetchData = rows;

    /* Meta yazısı raw (DB-dəki) say deyil, default trustee-lər çıxarıldıqdan
       sonra faktiki görünəcək say ilə göstərilsin — əks halda "459 / 459"
       yazıb cədvəldə 62 sətir göstərmək çaşdırıcı olardı. */
    const visibleCount = rows.filter(item => !isExcludedDefaultPrincipal(item)).length;
    document.getElementById('acl-meta').textContent =
      `${visibleCount.toLocaleString()} / ${rows.length.toLocaleString()} ${filterKey === 'dangerous' ? 'Dangerous ACE' : 'Extended Right'} (default trustee-lər çıxarılıb, source: ${table}) · domain_data.db`;

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

/* ─── Detail Panel ───────────────────────────────────────────────────────── */
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