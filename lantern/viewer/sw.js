// Lantern service worker: makes the app installable and keeps its icon at hand.
// It keeps no page, no report and no answer of the app: those hold a project's source and findings, and what a
// browser stores for an address on this computer can be read by whatever program serves a page there later.
// Everything an earlier version put aside is deleted when this one takes over.
const CACHE = 'lantern-static-v3';
const FIXED = ['/icon.svg', '/manifest.webmanifest'];
const OFFLINE = 'Lantern is offline. Start it with `lantern serve`.';
self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then(c => c.addAll(FIXED))); });
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  if (FIXED.includes(u.pathname) && !u.search) { e.respondWith(fetch(e.request).catch(() => caches.match(u.pathname).then(r => r || new Response(OFFLINE, {status: 503, headers: {'Content-Type': 'text/plain'}})))); return; }
  // a page: from the app or not at all (nothing is put aside, so nothing can come back from a store)
  if (e.request.mode === 'navigate') e.respondWith(fetch(e.request).catch(() => new Response(OFFLINE, {status: 503, headers: {'Content-Type': 'text/plain'}})));
});
