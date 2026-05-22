if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js');
}

document.addEventListener('DOMContentLoaded', function() {
    // Linkify URLs + YouTube embeds
    document.querySelectorAll('.linkify, .note-content, .daily-text, .description').forEach(function(el) {
        if (el.dataset.linked) return;
        el.dataset.linked = '1';
        el.innerHTML = el.innerHTML.replace(
            /(https?:\/\/[^\s<]+)/g,
            function(url) {
                var m = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([\w\-]+)/);
                if (m) {
                    return '<div style="position:relative;padding-bottom:56.25%;height:0;margin:8px 0;"><iframe src="https://www.youtube.com/embed/' + m[1] + '" style="position:absolute;top:0;left:0;width:100%;height:100%;border:0;" allowfullscreen></iframe></div>';
                }
                return '<a href="' + url + '" target="_blank" rel="noopener">' + url + '</a>';
            }
        );
    });

    // Relative time
    document.querySelectorAll('[data-time]').forEach(function(el) {
        var seconds = Math.floor((Date.now() / 1000) - parseInt(el.dataset.time));
        if (seconds < 60) el.textContent = 'just now';
        else if (seconds < 3600) el.textContent = Math.floor(seconds / 60) + 'm ago';
        else if (seconds < 86400) el.textContent = Math.floor(seconds / 3600) + 'h ago';
        else if (seconds < 604800) el.textContent = Math.floor(seconds / 86400) + 'd ago';
        else el.textContent = Math.floor(seconds / 604800) + 'w ago';
    });

    // Mobile nav toggle
    var toggle = document.querySelector('.nav-toggle');
    var menu = document.querySelector('.nav-mobile');
    if (toggle && menu) {
        toggle.addEventListener('click', function() {
            menu.classList.toggle('open');
        });
        document.addEventListener('click', function(e) {
            if (!toggle.contains(e.target) && !menu.contains(e.target)) {
                menu.classList.remove('open');
            }
        });
    }

    // Save buttons — intercept /notes/add forms, use fetch, show toast
    document.querySelectorAll('form[action="/notes/add"]').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            var btn = form.querySelector('button[type="submit"]');
            if (btn) btn.disabled = true;
            fetch('/notes/add', {
                method: 'POST',
                body: new URLSearchParams(new FormData(form))
            }).then(function() {
                showToast('Saved to notes');
            }).catch(function() {
                showToast('Failed to save');
            }).finally(function() {
                if (btn) btn.disabled = false;
            });
        });
    });
});

function showToast(msg) {
    var el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        el.className = 'toast';
        document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(function() { el.classList.remove('show'); }, 2000);
}
