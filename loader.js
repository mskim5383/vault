// Unlocks the encrypted bundle (vault.json → bundle) with a password, writes its files into Cache Storage
// for sw.js to serve, and remembers the derived key (non-extractable CryptoKey in IndexedDB) so the password
// is asked once per device. Visiting "?lock" forgets everything.
(async () => {
  const BASE = new URL("./", location.href).pathname;
  const CACHE = "vault";
  const HOME = `${BASE}home/`;
  const form = document.getElementById("unlock");
  const input = document.getElementById("password");
  const status = document.getElementById("status");

  const idb = (mode, fn) =>
    new Promise((resolve, reject) => {
      const open = indexedDB.open("vault", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("kv");
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const tx = open.result.transaction("kv", mode);
        const req = fn(tx.objectStore("kv"));
        tx.oncomplete = () => resolve(req && req.result);
        tx.onerror = () => reject(tx.error);
      };
    });
  const get = (key) => idb("readonly", (store) => store.get(key));
  const set = (key, value) => idb("readwrite", (store) => store.put(value, key));
  const b64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

  const deriveKey = async (password, meta) => {
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: b64(meta.salt), iterations: meta.iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  };

  // Throws when the key is wrong (AES-GCM authentication fails).
  const install = async (key, meta) => {
    status.textContent = "Loading...";
    const sealed = await (await fetch(BASE + meta.bundle)).arrayBuffer();
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(meta.iv) }, key, sealed));
    const manifestLength = new DataView(plain.buffer).getUint32(0);
    const manifest = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + manifestLength)));
    const body = 4 + manifestLength;

    await caches.delete(CACHE);
    const cache = await caches.open(CACHE);
    for (const file of manifest) {
      const bytes = plain.slice(body + file.offset, body + file.offset + file.length);
      const response = () => new Response(bytes, { headers: { "Content-Type": file.type } });
      await cache.put(BASE + file.path, response());
      if (file.path.endsWith("/index.html")) {
        await cache.put(BASE + file.path.slice(0, -"index.html".length), response());
      }
    }
    await set("version", meta.bundle);
  };

  const go = () => location.replace(HOME);

  if (location.search.includes("lock")) {
    await caches.delete(CACHE);
    await set("key", undefined);
    await set("version", undefined);
    history.replaceState(null, "", BASE);
  }

  await navigator.serviceWorker.register(BASE + "sw.js", { scope: BASE });
  await navigator.serviceWorker.ready;

  let meta = null;
  try {
    meta = await (await fetch(BASE + "vault.json", { cache: "no-store" })).json();
  } catch {
    // Offline: whatever was unlocked before still works.
  }
  const key = await get("key");
  const version = await get("version");
  if (key && version && (!meta || version === meta.bundle)) {
    return go();
  }
  if (key && meta) {
    try {
      await install(key, meta);
      return go();
    } catch {
      // Password changed on the server side: ask again.
    }
  }

  form.hidden = false;
  input.focus();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!meta) {
      status.textContent = "Offline.";
      return;
    }
    status.textContent = "Checking...";
    try {
      const derived = await deriveKey(input.value, meta);
      await install(derived, meta);
      await set("key", derived);
      go();
    } catch {
      status.textContent = "Wrong password.";
    }
  });
})();
