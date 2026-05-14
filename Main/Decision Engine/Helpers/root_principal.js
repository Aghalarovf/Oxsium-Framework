(function () {
    'use strict';

    /* ── DOM refs ─────────────────────────────────────────── */
    const btn        = document.getElementById('root-principal-trigger');
    const dropdown   = document.getElementById('root-principal-dropdown');
    const searchInput = document.getElementById('rp-search-input');
    const scrollArea = document.getElementById('rp-scroll-area');
    const statusDot = document.querySelector('.status-dot');
    const statusLabel = document.querySelector('.status-label');

    /* ── Runtime state ────────────────────────────────────── */
    let rpUsers     = [];   // [{ username, sid, target_attributes }]
    let rpComputers = [];   // [{ computer_name, sid, target_attributes }]
    let allItems    = [];   // merged flat list for filtering
    let loaded      = false;

    // ─── Current selected principal (exposed globally for engine) ───
    window.SELECTED_PRINCIPAL = null;
    window.SELECTED_ROOT_PRINCIPAL_SID = '';

    const domainObjectBaseUrl = new URL('../../Domain%20Object/', window.location.href);
    const defaultIconHref = new URL('../../assets/Icons/root_principal.png', window.location.href).href;
    const fallbackHref = new URL('../../assets/favicon.png', window.location.href).href;

    // Engine API port control (default 5100). Click the status label to change.
    window.ENGINE_API_HOST = window.ENGINE_API_HOST || '127.0.0.1';
    window.ENGINE_API_PORT = window.ENGINE_API_PORT || '5100';

    function setEngineStatus(isActive) {
        if (statusLabel) {
            statusLabel.textContent = isActive ? 'Engine Active' : 'Engine Deactive';
            statusLabel.classList.toggle('is-active', !!isActive);
            statusLabel.classList.toggle('is-deactive', !isActive);
        }
        if (statusDot) {
            statusDot.classList.toggle('is-active', !!isActive);
            statusDot.classList.toggle('is-deactive', !isActive);
        }
    }

    async function checkEngineHealth() {
        try {
            const url = `http://${window.ENGINE_API_HOST}:${window.ENGINE_API_PORT}/health`;
            const response = await fetch(url, { cache: 'no-store' });
            setEngineStatus(response.ok);
            return response.ok;
        } catch (err) {
            setEngineStatus(false);
            return false;
        }
    }

    // Attach a click handler to the topbar status label so user can set the engine port.
    try {
        if (statusLabel) {
            statusLabel.style.cursor = 'pointer';
            statusLabel.title = 'Click to set Engine API host:port';
            statusLabel.addEventListener('click', () => {
                const current = `${window.ENGINE_API_HOST}:${window.ENGINE_API_PORT}`;
                const input = prompt('Enter Engine API host:port', current);
                if (!input) return;
                const parts = input.split(':').map(s => s.trim());
                if (parts.length === 1) {
                    window.ENGINE_API_HOST = '127.0.0.1';
                    window.ENGINE_API_PORT = parts[0];
                } else {
                    window.ENGINE_API_HOST = parts[0] || '127.0.0.1';
                    window.ENGINE_API_PORT = parts[1] || window.ENGINE_API_PORT;
                }
                alert('Engine API set to ' + window.ENGINE_API_HOST + ':' + window.ENGINE_API_PORT);
            });
        }
    } catch (err) {
        console.warn('[RootPrincipal] status label attach failed:', err && err.message);
    }

    setEngineStatus(false);
    checkEngineHealth();

    /* ══════════════════════════════════════════════════════════
       1. DATA LOADING
    ══════════════════════════════════════════════════════════ */

    /**
     * Fetch a JSON file and return parsed data.
     * Resolves to null on failure so the other file can still load.
     */
    async function fetchJSON(path) {
        try {
            const res = await fetch(path);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return await res.json();
        } catch (err) {
            console.warn(`[RootPrincipal] Could not load ${path}:`, err.message);
            return null;
        }
    }

    /** Load both JSON files and extract relevant fields. */
    async function loadPrincipals() {
        scrollArea.innerHTML = '<div class="rp-loading">Loading principals…</div>';

        const [usersData, computersData] = await Promise.all([
            fetchJSON(new URL('domain_users.json', domainObjectBaseUrl).href),
            fetchJSON(new URL('domain_computers.json', domainObjectBaseUrl).href)
        ]);

        /* ── Users ──────────────────────────────────────────── */
        if (usersData && Array.isArray(usersData.users)) {
            rpUsers = usersData.users.map(u => ({
                username: u.username || '(unnamed)',
                sid:      u.sid      || '',
                target_attributes: u
            }));
        } else {
            rpUsers = [];
            console.warn('[RootPrincipal] domain_users.json: missing or invalid users array');
        }

        /* ── Computers ──────────────────────────────────────── */
        if (computersData && Array.isArray(computersData.computers)) {
            rpComputers = computersData.computers.map(c => ({
                computer_name: (c.computer_name || '(unnamed)').replace(/\$$/, ''), // strip trailing $
                sid:           c.sid || '',
                target_attributes: c
            }));
        } else {
            rpComputers = [];
            console.warn('[RootPrincipal] domain_computers.json: missing or invalid computers array');
        }

        /* ── Build flat allItems list (for search) ──────────── */
        allItems = [
            ...rpUsers.map(u => ({
                label:  u.username,
                sid:    u.sid,
                kind:   'user',
                target_attributes: u.target_attributes
            })),
            ...rpComputers.map(c => ({
                label:  c.computer_name,
                sid:    c.sid,
                kind:   'computer',
                target_attributes: c.target_attributes
            }))
        ];

        /* SID reference store — available globally for future engine use */
        window.RP_SID_MAP = Object.fromEntries(
            allItems.map(item => [item.label.toUpperCase(), item.sid])
        );

        loaded = true;
        renderDropdown('');
    }

    /* ══════════════════════════════════════════════════════════
       2. RENDERING
    ══════════════════════════════════════════════════════════ */

    /** Render source-info mini-cards at the top of the scroll area. */
    function buildSourcePanel() {
        return `
        <div class="rp-source-panel">
            <div class="rp-source-card">
                <div class="rp-source-top">
                    <span class="rp-source-label">Users</span>
                    <span class="rp-source-count">${rpUsers.length}</span>
                </div>
                <div class="rp-source-file">domain_users.json</div>
            </div>
            <div class="rp-source-card">
                <div class="rp-source-top">
                    <span class="rp-source-label">Computers</span>
                    <span class="rp-source-count">${rpComputers.length}</span>
                </div>
                <div class="rp-source-file">domain_computers.json</div>
            </div>
        </div>`;
    }

    /**
     * Build a single <div class="rp-item"> element.
     * @param {string} label  - display name
     * @param {string} sid    - stored in data-sid for future use
     * @param {string} kind   - 'user' | 'computer'
     */
    function buildItem(item) {
        const label = item.kind === 'computer' ? item.computer_name : item.username;
        const sid = item.sid;
        const kind = item.kind;
        const iconFile = kind === 'user' ? 'user.png' : 'computer.png';
        const iconHref = new URL(`../../assets/Icons/${iconFile}`, window.location.href).href;
        const icon = `<img class="rp-item-icon-img" src="${iconHref}" alt="${kind}" onerror="this.onerror=null;this.src='${fallbackHref}'" />`;
        const isSelected = window.SELECTED_PRINCIPAL
            && window.SELECTED_PRINCIPAL.label === label
            && window.SELECTED_PRINCIPAL.kind  === kind;

        const el = document.createElement('div');
        el.className  = 'rp-item' + (isSelected ? ' selected' : '');
        el.dataset.sid  = sid;   // SID reference — do not remove
        el.dataset.kind = kind;
        el.dataset.label = label;
        el.innerHTML = `
            <span class="rp-item-icon">${icon}</span>
            <span class="rp-item-text" title="${escHtml(label)}">${escHtml(label)}</span>`;
        el.addEventListener('click', () => onItemSelect(item));
        return el;
    }

    /**
     * Render/re-render the full scroll area contents.
     * @param {string} query - current search string
     */
    function renderDropdown(query) {
        scrollArea.innerHTML = '';

        const q = query.trim().toLowerCase();

        /* Filter each group */
        const filteredUsers = rpUsers.filter(u =>
            u.username.toLowerCase().includes(q)
        );
        const filteredComps = rpComputers.filter(c =>
            c.computer_name.toLowerCase().includes(q)
        );

        const totalVisible = filteredUsers.length + filteredComps.length;

        /* Source panel (only when no query active) */
        if (!q) {
            scrollArea.insertAdjacentHTML('beforeend', buildSourcePanel());
        }

        /* Summary header */
        const summaryEl = document.createElement('div');
        summaryEl.className = 'rp-section-header';
        summaryEl.innerHTML = q
            ? `Results for "<strong>${escHtml(query)}</strong>" <strong>${totalVisible}</strong>`
            : `All principals &nbsp;<strong>${allItems.length}</strong>`;
        scrollArea.appendChild(summaryEl);

        if (totalVisible === 0) {
            const empty = document.createElement('div');
            empty.className = 'rp-loading rp-error';
            empty.textContent = 'No match found';
            scrollArea.appendChild(empty);
            return;
        }

        /* ── Users group ────────────────────────────────────── */
        if (filteredUsers.length > 0) {
            const hdr = document.createElement('div');
            hdr.className = 'rp-group-label';
            hdr.innerHTML = `Users <span class="rp-group-count">${filteredUsers.length}</span>`;
            scrollArea.appendChild(hdr);

            filteredUsers.forEach(u =>
                scrollArea.appendChild(buildItem({
                    username: u.username,
                    sid: u.sid,
                    kind: 'user',
                    target_attributes: u.target_attributes
                }))
            );
        }

        /* ── Computers group ────────────────────────────────── */
        if (filteredComps.length > 0) {
            const hdr = document.createElement('div');
            hdr.className = 'rp-group-label';
            hdr.innerHTML = `Computers <span class="rp-group-count">${filteredComps.length}</span>`;
            scrollArea.appendChild(hdr);

            filteredComps.forEach(c =>
                scrollArea.appendChild(buildItem({
                    computer_name: c.computer_name,
                    sid: c.sid,
                    kind: 'computer',
                    target_attributes: c.target_attributes
                }))
            );
        }

        // After rendering, ensure we update sticky group visibility according to scroll
        // (hides the group label that would otherwise appear pinned at the bottom when scrolling)
        requestAnimationFrame(() => updateGroupLabelVisibility());
    }

    /** Hide any group-label that is touching the bottom edge of the scroll area while scrolling */
    function updateGroupLabelVisibility() {
        if (!scrollArea) return;
        const areaRect = scrollArea.getBoundingClientRect();
        const labels = scrollArea.querySelectorAll('.rp-group-label');
        labels.forEach(lbl => {
            const lblRect = lbl.getBoundingClientRect();
            // If the label's bottom is within 6px of the scroll area's bottom, consider it 'touching'
            if (lblRect.bottom > areaRect.bottom - 6) {
                lbl.classList.add('hidden-on-scroll');
            } else {
                lbl.classList.remove('hidden-on-scroll');
            }
        });
    }

    // Attach scroll handler to update visibility while user scrolls
    if (scrollArea) {
        scrollArea.addEventListener('scroll', () => {
            updateGroupLabelVisibility();
        }, { passive: true });
    }

    /* ══════════════════════════════════════════════════════════
       3. INTERACTION
    ══════════════════════════════════════════════════════════ */

    /** Called when a principal item is clicked. */
    function isTruthyAttrValue(v) {
        if (v === true) return true;
        if (typeof v === 'string') return v.toLowerCase() === 'true';
        if (typeof v === 'number') return Number(v) === 1;
        return false;
    }

    function hasTruthyAttr(attrs, key) {
        if (!attrs || typeof attrs !== 'object') return false;
        return isTruthyAttrValue(attrs[key]);
    }

    function onItemSelect(item) {
        const label = item.kind === 'computer' ? item.computer_name : item.username;
        const sid = item.sid;
        const kind = item.kind;
        const targetAttributes = item.target_attributes || null;
        /* Persist globally — SID kept for future engine use */
        window.SELECTED_PRINCIPAL = { label, sid, kind, target_attributes: targetAttributes };
        window.SELECTED_ROOT_PRINCIPAL_SID = sid || '';

        /* Update button label */
        const iconFile = kind === 'computer' ? 'computer.png' : 'user.png';
        const iconHref = new URL(`../../assets/Icons/${iconFile}`, window.location.href).href;
        btn.innerHTML = `<img class="rp-icon-img" src="${iconHref}" alt="${kind}" onerror="this.onerror=null;this.src='${fallbackHref}'" /><span class="topbar-btn-label rp-selected-text" title="${escHtml(label)}">${escHtml(label)}</span>`;
        btn.classList.add('active');

        /* Visually mark selected item */
        scrollArea.querySelectorAll('.rp-item').forEach(el => {
            el.classList.toggle('selected',
                el.dataset.label === label && el.dataset.kind === kind);
        });

        /* Close dropdown */
        closeDropdown();

        sessionStorage.setItem('selectedRootPrincipal', label);
        sessionStorage.setItem('selectedRootPrincipalType', kind);
        sessionStorage.setItem('selectedRootPrincipalSID', sid || '');
        sessionStorage.setItem('selectedRootPrincipalAttrs', JSON.stringify(targetAttributes || {}));

        /* Notify Decision Engine if callback is present */
        if (typeof window.onRootPrincipalSelected === 'function') {
            window.onRootPrincipalSelected({ label, sid, kind, target_attributes: targetAttributes });
        }

        console.info(
            `[RootPrincipal] attrs → is_admin=${hasTruthyAttr(targetAttributes, 'is_admin')} | potential_admin=${hasTruthyAttr(targetAttributes, 'potential_admin')}`
        );
        console.info(`[RootPrincipal] Selected → ${kind.toUpperCase()} | ${label} | SID: ${sid || '(none)'}`);
    }

    /** Open/close toggle */
    function toggleDropdown() {
        const isOpen = dropdown.classList.contains('open');
        isOpen ? closeDropdown() : openDropdown();
    }

    function openDropdown() {
        dropdown.classList.add('open');
        btn.classList.add('open');
        btn.classList.remove('is-default');
        if (!loaded) {
            loadPrincipals();
        } else {
            renderDropdown(searchInput.value);
        }
        // Focus search box after transition
        setTimeout(() => searchInput.focus(), 60);
    }

    function closeDropdown() {
        dropdown.classList.remove('open');
        btn.classList.remove('open');
    }

    function resetSelection() {
        window.SELECTED_PRINCIPAL = null;
        window.SELECTED_ROOT_PRINCIPAL_SID = '';
        sessionStorage.removeItem('selectedRootPrincipalAttrs');
        btn.classList.remove('active');
        btn.classList.remove('open');
        setDefaultButtonState();
        closeDropdown();

        if (loaded) {
            renderDropdown('');
        }
    }

    /* ── Button click ───────────────────────────────────────── */
    btn.addEventListener('click', e => {
        e.stopPropagation();
        toggleDropdown();
    });

    /* ── Search / filter ────────────────────────────────────── */
    searchInput.addEventListener('input', () => {
        if (loaded) renderDropdown(searchInput.value);
    });

    searchInput.addEventListener('keydown', e => {
        if (e.key === 'Escape') closeDropdown();
    });

    /* ── Close on outside click ─────────────────────────────── */
    document.addEventListener('click', e => {
        if (!dropdown.contains(e.target) && e.target !== btn) {
            closeDropdown();
        }
    });

    /* ── Stop click inside dropdown from bubbling to document ─ */
    dropdown.addEventListener('click', e => e.stopPropagation());

    /* ══════════════════════════════════════════════════════════
       4. UTILITIES
    ══════════════════════════════════════════════════════════ */

    function escHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function setDefaultButtonState() {
        btn.classList.add('is-default');
        btn.innerHTML = `<img class="rp-icon-img" src="${defaultIconHref}" alt="Root Principal" onerror="this.onerror=null;this.src='${fallbackHref}'" /><span class="topbar-btn-label rp-selected-text">Root Principal</span>`;
    }

    if (!window.SELECTED_PRINCIPAL) {
        setDefaultButtonState();
    }

    /* ── Expose public API ───────────────────────────────────── */
    window.RootPrincipal = {
        /** Reload data from JSON files (call after file update) */
        reload: () => { loaded = false; loadPrincipals(); },
        /** Reset selected principal and restore default button state */
        reset: resetSelection,
        /** Get current selection */
        getSelected: () => window.SELECTED_PRINCIPAL,
        /** Get selected SID directly */
        getSelectedSID: () => window.SELECTED_ROOT_PRINCIPAL_SID || window.SELECTED_PRINCIPAL?.sid || sessionStorage.getItem('selectedRootPrincipalSID') || '',
        /** Get SID for a given label (future engine use) */
        getSID: (label) => window.RP_SID_MAP?.[label?.toUpperCase()] || null
    };

})();