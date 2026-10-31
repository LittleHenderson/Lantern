// Lantern service worker: keeps the app shell and recently opened reports available offline.
// API calls always go to the network; reports fall back to the last copy when the server is off.
const CACHE = 'lantern-v2';
self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/icon.svg', '/manifest.webmanifest']))); });
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/') || u.search.includes('token=')) return;
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request).then(r => r || new Response('Lantern is offline. Start it with `lantern serve`.', {status: 503, headers: {'Content-Type': 'text/plain'}}))));
});
