// Lantern cloud service worker: makes the website installable like the app and keeps its icon at hand.
// It never stores pages, results or answers from /v1/ or /r/: those are private to the person signed in.
const CACHE = 'lantern-cloud-v1';
const SHELL = ['/icon.svg', '/manifest.webmanifest'];
self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))); });
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  if (SHELL.includes(u.pathname)) { e.respondWith(caches.match(e.request).then(r => r || fetch(e.request))); return; }
  if (e.request.mode === 'navigate' && u.pathname === '/') {
    e.respondWith(fetch(e.request).catch(() => new Response(
      '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lantern</title>' +
      '<body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#0E0E10;color:#BEBEC3;font:15px/1.5 -apple-system,Segoe UI,sans-serif;text-align:center;padding:24px">' +
      '<div><div style="font:600 20px -apple-system,Segoe UI,sans-serif;color:#F3F3F1;margin-bottom:6px">You are offline</div>Lantern needs the internet to check an app from its link. Your runs are safe; open Lantern again when you are back online.</div>',
      {status: 503, headers: {'Content-Type': 'text/html; charset=utf-8'}})));
  }
});
