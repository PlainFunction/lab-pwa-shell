// The test runner needs a Worker entry. Nothing is served from it.
export default {
  async fetch() { return new Response('pwa-shell test worker', { status: 404 }) },
}
