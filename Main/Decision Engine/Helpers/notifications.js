(function () {
    'use strict';

    function initNotifications() {
        const trigger = document.getElementById('notifications-btn');
        const popover = document.getElementById('notifications-popover');
        const closeBtn = document.getElementById('notifications-close');
        const body = document.getElementById('notifications-popover-body');

        if (!trigger || !popover || !closeBtn || !body) return;

        body.innerHTML = '';

        function openPopover() {
            popover.classList.add('open');
            trigger.classList.add('active');
            popover.setAttribute('aria-hidden', 'false');
        }

        function closePopover() {
            popover.classList.remove('open');
            trigger.classList.remove('active');
            popover.setAttribute('aria-hidden', 'true');
        }

        trigger.addEventListener('click', e => {
            e.stopPropagation();
            if (popover.classList.contains('open')) {
                closePopover();
            } else {
                openPopover();
            }
        });

        closeBtn.addEventListener('click', closePopover);

        document.addEventListener('click', e => {
            if (!e.target.closest('#notifications-popover') && !e.target.closest('#notifications-btn')) {
                closePopover();
            }
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closePopover();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNotifications);
    } else {
        initNotifications();
    }
})();