(function () {
    'use strict';

    function initFilters() {
        const btn = document.getElementById('filters-trigger');
        const dropdown = document.getElementById('filters-dropdown');
        const scrollArea = document.getElementById('filters-scroll-area');

        if (!btn || !dropdown || !scrollArea) return;

        function closeDropdown() {
            dropdown.classList.remove('open');
            btn.classList.remove('open');
        }

        function openDropdown() {
            dropdown.classList.add('open');
            btn.classList.add('open');
            scrollArea.innerHTML = '';
        }

        btn.addEventListener('click', e => {
            e.stopPropagation();

            const isOpen = dropdown.classList.contains('open');
            if (isOpen) {
                closeDropdown();
            } else {
                openDropdown();
            }
        });

        dropdown.addEventListener('click', e => e.stopPropagation());

        document.addEventListener('click', e => {
            if (!e.target.closest('.filters-section')) {
                closeDropdown();
            }
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                closeDropdown();
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFilters);
    } else {
        initFilters();
    }
})();