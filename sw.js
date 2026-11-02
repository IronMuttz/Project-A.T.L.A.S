// A.T.L.A.S offline support for the installed PC app.
// Network first, so a new version is picked up on the next start; the last copy is kept for playing offline.
const CACHE = 'atlas-v1';
const SHELL = ['./', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(self.clients.claim()); });
// The page is served cross-origin isolated (Chrome/Edge), which lets the HD voice pack use several CPU cores.
// 'credentialless' keeps fonts, images and other sites loading exactly as before.
const isolate = res => {
  if (!res || !res.ok || res.type === 'opaque') return res;
  const h = new Headers(res.headers);
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Cross-Origin-Embedder-Policy', 'credentialless');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
};
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;                         // fonts and other sites: straight to the network
  const page = req.mode === 'navigate' || /\/(index\.html)?$/.test(url.pathname);
  if (!page && !/\.(webmanifest|png)$/.test(url.pathname)) return;   // version.json, the Android APK etc. are never cached
  const key = page ? new URL('./', location.href).href : url.origin + url.pathname;
  e.respondWith((async () => {
    try {
      const res = await fetch(page ? url.href : req, { cache: 'no-store', credentials: 'same-origin' });
      if (res.ok) { const c = await caches.open(CACHE); c.put(key, res.clone()); }
      return page ? isolate(res) : res;
    } catch (err) {
      const hit = await caches.match(key);
      if (hit) return page ? isolate(hit) : hit;
      throw err;
    }
  })());
});
