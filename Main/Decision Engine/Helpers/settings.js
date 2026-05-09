(function () {
    'use strict';

    function initSettings() {
        const trigger = document.getElementById('settings-btn');
        const panel = document.getElementById('settings-panel');
        const backdrop = document.getElementById('settings-backdrop');
        const closeBtn = document.getElementById('settings-close');

        if (!trigger || !panel || !backdrop || !closeBtn) return;

        function openPanel() {
            panel.classList.add('open');
            backdrop.classList.add('open');
            trigger.classList.add('active');
            panel.setAttribute('aria-hidden', 'false');
            backdrop.setAttribute('aria-hidden', 'false');
        }

        function closePanel() {
            panel.classList.remove('open');
            backdrop.classList.remove('open');
            trigger.classList.remove('active');
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
        document.addEventListener('DOMContentLoaded', initSettings);
    } else {
        initSettings();
    }
})();