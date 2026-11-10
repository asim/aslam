const CACHE_NAME = 'aslam-public-v2';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Never store authenticated HTML, account responses or API keys on disk.
  // Reader offline data is managed separately; this cache holds static assets only.
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (!/^\/(app\.(js|css)|marked\.js|purify\.min\.js|favicon\.ico|manifest\.json|icons\/[^/]+|fonts\/[^/]+)$/.test(url.pathname)) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (!response.ok || response.redirected || /no-store|private/i.test(response.headers.get("Cache-Control") || "")) return response;
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
