(function () {
    'use strict';

    function initReset() {
        const btn = document.getElementById('reset-btn');
        const notificationsBtn = document.getElementById('notifications-btn');
        const settingsBtn = document.getElementById('settings-btn');
        const notificationsPopover = document.getElementById('notifications-popover');
        const settingsPanel = document.getElementById('settings-panel');
        const settingsBackdrop = document.getElementById('settings-backdrop');
        const filtersDropdown = document.getElementById('filters-dropdown');
        const filtersTrigger = document.getElementById('filters-trigger');

        if (!btn) return;

        function closeAuxPanels() {
            notificationsPopover?.classList.remove('open');
            notificationsBtn?.classList.remove('active');
            settingsPanel?.classList.remove('open');
            settingsBackdrop?.classList.remove('open');
            settingsBtn?.classList.remove('active');
            filtersDropdown?.classList.remove('open');
            filtersTrigger?.classList.remove('open');
            const exportPanel = document.getElementById('export-panel');
            const exportBackdrop = document.getElementById('export-backdrop');
            const exportBtn = document.getElementById('export-btn');
            exportPanel?.classList.remove('open');
            exportBackdrop?.classList.remove('open');
            exportBtn?.classList.remove('open');
        }

        btn.addEventListener('click', e => {
            e.stopPropagation();

            if (window.RootPrincipal && typeof window.RootPrincipal.reset === 'function') {
                window.RootPrincipal.reset();
            }

            closeAuxPanels();
            btn.classList.add('active');

            setTimeout(() => btn.classList.remove('active'), 160);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initReset);
    } else {
        initReset();
    }
})();