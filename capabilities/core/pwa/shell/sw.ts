/// <reference lib="webworker" />
// The service worker. It keeps the shell (HTML, JS, CSS, icons) so the app
// opens instantly and offline, and shows notifications. It never touches
// /api/: nothing a person can see once signed in is ever stored on the device,
// so a lost phone holds the shell and nothing else.

const sw = self as unknown as ServiceWorkerGlobalScope
// Filled in by build.mjs: a hash of the shell, and the files in it.
declare const __VERSION__: string
declare const __SHELL__: string[]
declare const __APP_NAME__: string

// The notification's picture is the app's icon (the same one as the favicon), and
// the badge is the white tick Android puts in the status bar. A client with a logo
// replaces icon-192.png and every notification shows it.
const ICON = '/icon-192.png'
const BADGE = '/badge-96.png'

const CACHE = `shell-${__VERSION__}`

sw.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(__SHELL__)).then(() => sw.skipWaiting()))
})

sw.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key)
    await sw.clients.claim()
  })())
})

sw.addEventListener('fetch', event => {
  const req = event.request
  const url = new URL(req.url)
  // The API is network only: no cache, no fallback.
  if (req.method !== 'GET' || url.origin !== sw.location.origin || url.pathname.startsWith('/api/')) return
  if (req.mode === 'navigate') {
    // Fresh when online, so a new version shows up; the cached shell when not.
    event.respondWith(fetch(req).catch(async () => (await caches.match('/')) ?? Response.error()))
    return
  }
  event.respondWith(caches.match(req).then(hit => hit ?? fetch(req)))
})

interface PushNotice { title?: string; body?: string; url?: string; tag?: string }

sw.addEventListener('push', event => {
  let n: PushNotice = {}
  try { n = event.data?.json() ?? {} } catch { n = { body: event.data?.text() } }
  event.waitUntil(sw.registration.showNotification(n.title || __APP_NAME__, {
    body: n.body, tag: n.tag, icon: ICON, badge: BADGE, data: { url: n.url },
  }))
})

sw.addEventListener('notificationclick', event => {
  event.notification.close()
  // Only ever opens a page of this app, whatever the notice says.
  let target = new URL('/', sw.location.origin)
  try {
    const u = new URL((event.notification.data as PushNotice | undefined)?.url ?? '/', sw.location.origin)
    if (u.origin === sw.location.origin) target = u
  } catch { /* keep the home page */ }
  event.waitUntil((async () => {
    const open = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const win = open.find(c => new URL(c.url).origin === sw.location.origin)
    if (win) { await win.focus(); await win.navigate(target.href).catch(() => {}) }
    else await sw.clients.openWindow(target.href)
  })())
})
