if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js');
}

document.addEventListener('DOMContentLoaded', function() {
    // Only transform text nodes: never rebuild HTML from source text or attributes.
    document.querySelectorAll('.linkify, .note-content, .daily-text, .description').forEach(function(el) {
        if (el.dataset.linked) return;
        el.dataset.linked = '1';
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        const nodes = [];
        while (walker.nextNode()) {
            if (!walker.currentNode.parentElement.closest('a,script,style')) nodes.push(walker.currentNode);
        }
        nodes.forEach(function(node) {
            const text = node.textContent;
            const pattern = /https?:\/\/[^\s<>"']+/g;
            const fragment = document.createDocumentFragment();
            let end = 0;
            for (const match of text.matchAll(pattern)) {
                fragment.append(document.createTextNode(text.slice(end, match.index)));
                const a = document.createElement('a');
                a.href = match[0]; a.textContent = match[0]; a.target = '_blank'; a.rel = 'noopener noreferrer';
                fragment.append(a); end = match.index + match[0].length;
            }
            if (end) { fragment.append(document.createTextNode(text.slice(end))); node.replaceWith(fragment); }
        });
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

    // Source quick-saves stay in place; the note editor submits normally.
    document.querySelectorAll('form[action="/notes/add"]:not([data-note-editor])').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            var btn = form.querySelector('button[type="submit"]');
            if (btn) btn.disabled = true;
            fetch('/notes/add', {
                method: 'POST',
                headers: {'Accept': 'application/json'},
                body: new URLSearchParams(new FormData(form))
            }).then(function(response) {
                if (!response.ok || response.redirected) throw new Error('Save failed');
                return response.json();
            }).then(function(result) {
                if (result.saved !== true) throw new Error('Save failed');
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
