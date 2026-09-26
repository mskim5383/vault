// Serves decrypted files from Cache Storage (written by loader.js); everything else goes to the network.
const CACHE = "vault";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || new URL(request.url).origin !== location.origin) {
    return;
  }
  event.respondWith(
    caches
      .open(CACHE)
      .then((cache) => cache.match(request.url, { ignoreSearch: true }))
      .then((hit) => hit || fetch(request)),
  );
});
