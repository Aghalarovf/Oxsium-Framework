(function () {
    'use strict';

    function initExport() {
        const trigger = document.getElementById('export-btn');
        const panel = document.getElementById('export-panel');
        const backdrop = document.getElementById('export-backdrop');
        const closeBtn = document.getElementById('export-close');

        if (!trigger || !panel || !backdrop || !closeBtn) return;

        function openPanel() {
            panel.classList.add('open');
            backdrop.classList.add('open');
            trigger.classList.add('open');
            panel.setAttribute('aria-hidden', 'false');
            backdrop.setAttribute('aria-hidden', 'false');
        }

        function closePanel() {
            panel.classList.remove('open');
            backdrop.classList.remove('open');
            trigger.classList.remove('open');
            panel.setAttribute('aria-hidden', 'true');
            backdrop.setAttribute('aria-hidden', 'true');
        }

        trigger.addEventListener('click', e => {
            e.stopPropagation();
            if (panel.classList.contains('open')) {
                closePanel();
            } else {
                openPanel();
            }
        });

        closeBtn.addEventListener('click', closePanel);
        backdrop.addEventListener('click', closePanel);

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                closePanel();
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initExport);
    } else {
        initExport();
    }
})();