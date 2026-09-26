/* ═══════════════════════════════════════════════════════════════════
   THE SERVICE WORKER — so the page loads with no signal
                                          Portfolio · Rotterdam, v1.8

   IT LIVES IN `public/` AND THAT IS NOT A DETAIL. Vite copies public/
   to the output untouched, so this arrives as a real file beside
   index.html. Anywhere inside `src/` it would be inlined into the
   single-file bundle by vite-plugin-singlefile and there would be no
   worker to register. It is also a SECOND DEPLOYED FILE for this tool —
   the first one ever — which is why `portfolio-sw` had to be added to
   deploy.js's TARGETS and to NOT_A_TOOL in tests/check_tool_urls.js.

   THIS IS THE PART THAT MAKES OFFLINE POSSIBLE AT ALL. The talk tracks
   themselves are cached by data.js, but a cached talk is no use if the
   page will not open: GitHub Pages is a network fetch, and a phone in a
   basement gets a dinosaur.

   WHAT IT CANNOT REACH, and this cost a rewrite to notice: a worker
   only sees fetches inside its own scope, and its scope is the folder
   it is served from. `cc-suite.css` is one level up and the icon font
   is on another origin, so neither passes through here. The app keeps
   its own copy of those — see talk/offline-assets.js.

   ⚠ IT COLLIDES WITH THE STALE-TAB RULE, AND THE COLLISION IS HANDLED.
   A three-day-old tab destroyed data on 10 August and v57.4 made an
   out-of-date page refuse to write. A service worker serves stale files
   ON PURPOSE, which is the same hazard pointed the other way. The two
   are reconciled by two decisions, and neither is optional:

     1  NETWORK FIRST for the app itself. Online, the newest build wins
        every time and the cache is never consulted. The cache exists
        for the case where there is no network at all — which is not a
        stale page, it is the only page.
     2  OFFLINE IS READ ONLY. data.js refuses every write when
        navigator.onLine is false. The stale-tab rule exists because an
        old page WROTE; a page that cannot write cannot commit that sin.

   WHAT IS DELIBERATELY NOT CACHED: anything from Supabase. The talk
   tracks are cached in localStorage by data.js, where the app can see
   them, reason about them and say how old they are. A silent HTTP cache
   in front of a database is how a screen and a database start
   disagreeing with nobody able to tell.
   ═══════════════════════════════════════════════════════════════════ */

/* Bump this with the tool's version. A new name is what evicts the old
   cache — there is no other eviction, on purpose: guessing at expiry
   is how a phone ends up holding half of one build and half of another. */
const CACHE = 'cc-portfolio-v1.8-rotterdam';

/* Only the shell. The index and the bundle are enough to open the
   screen; everything else the app needs offline it already holds. */
const SHELL = ['./', './index.html'];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    /* addAll fails the whole install if ONE file 404s, and a failed
       install leaves no worker at all — which is worse than a shell
       with a gap. Each file is added on its own and allowed to fail. */
    await Promise.all(SHELL.map(u => c.add(u).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter(n => n !== CACHE && n.startsWith('cc-portfolio-'))
                           .map(n => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  /* NOT OURS: Supabase, the icon CDN, anything cross-origin. Let the
     network handle it and fail honestly if it cannot. */
  if (url.origin !== self.location.origin) return;

  /* NOT OURS EITHER: anything outside this tool's own folder. The
     worker is registered with a scope, but a scope is a promise about
     what it MAY control, not a statement of what it should. */
  if (!url.pathname.startsWith(new URL('./', self.location.href).pathname)) return;

  e.respondWith((async () => {
    try {
      /* NETWORK FIRST — see the note at the top. `cache: 'no-store'`
         so the browser's own HTTP cache cannot hand back a stale build
         while claiming the network answered. */
      const fresh = await fetch(req, { cache: 'no-store' });
      if (fresh && fresh.ok) {
        const c = await caches.open(CACHE);
        c.put(req, fresh.clone()).catch(() => {});
      }
      return fresh;
    } catch (err) {
      const hit = await caches.match(req);
      if (hit) return hit;
      /* A navigation with nothing cached is the one case worth a real
         answer rather than a browser error page. */
      if (req.mode === 'navigate') {
        const shell = await caches.match('./index.html');
        if (shell) return shell;
      }
      throw err;
    }
  })());
});
