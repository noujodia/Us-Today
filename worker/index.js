// Us, Today notification sender (Cloudflare Worker).
// Receives {sub, title, body, url} from the app and delivers an encrypted Web Push.
// The VAPID private key is stored as the secret VAPID_D in Cloudflare, never in this file.
const VAPID_PUBLIC = "BH9swIrCDeQtLef9p5w_PeBjFBodHEF5AWX2j4aktaTlHWYquTK9HCNx_VIgClhmmK4F1sC0Jn6UmK_AgKvm8jU";
const VAPID_X = "f2zAisIN5C0t5_2nnD894GMUGh0cQXkBZfaPhqS1pOU";
const VAPID_Y = "HWYquTK9HCNx_VIgClhmmK4F1sC0Jn6UmK_AgKvm8jU";
const SUBJECT = "https://noujodia.github.io/Us-Today/";
const ALLOWED_ORIGINS = ["https://noujodia.github.io"];
const PUSH_HOSTS = [/\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /\.notify\.windows\.com$/];

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const concat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

async function vapidAuth(endpoint, d) {
  const aud = new URL(endpoint).origin;
  const header = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: VAPID_X, y: VAPID_Y, d, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(header + "." + claims));
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${VAPID_PUBLIC}`;
}

async function encrypt(sub, payload) {
  const uaPublic = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(enc.encode(payload), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ct);
}

function cors(origin) {
  return { "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0], "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" };
}
const reply = (obj, status, origin) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors(origin) } });

// Song search for the app. Apple's catalog first; Deezer as a backup. Results come back in Apple's field names.
async function searchSongs(term) {
  const t = term.trim().slice(0, 80);
  if (t.length < 2) return [];
  try {
    const r = await fetch("https://itunes.apple.com/search?media=music&entity=song&limit=8&country=US&term=" + encodeURIComponent(t), { headers: { "User-Agent": "UsToday/1.0", Accept: "application/json" }, cf: { cacheTtl: 86400, cacheEverything: true } });
    if (r.ok) {
      const d = await r.json();
      const out = (d.results || []).filter((x) => x.trackName).map((x) => ({ trackId: x.trackId, trackName: x.trackName, artistName: x.artistName, collectionName: x.collectionName, artworkUrl100: x.artworkUrl100, previewUrl: x.previewUrl, trackViewUrl: x.trackViewUrl }));
      if (out.length) return out;
    }
  } catch (_) {}
  try {
    const r = await fetch("https://api.deezer.com/search?limit=8&q=" + encodeURIComponent(t));
    if (r.ok) {
      const d = await r.json();
      return (d.data || []).map((x) => ({ trackId: "dz" + x.id, trackName: x.title, artistName: x.artist && x.artist.name, collectionName: x.album && x.album.title, artworkUrl100: x.album && (x.album.cover_medium || x.album.cover), previewUrl: x.preview, trackViewUrl: "" }));
    }
  } catch (_) {}
  return [];
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
    const path = new URL(req.url).pathname;
    if (req.method === "GET" && path === "/search") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      const results = await searchSongs(new URL(req.url).searchParams.get("term") || "");
      return new Response(JSON.stringify({ results }), { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=3600", ...cors(origin) } });
    }
    if (req.method === "GET") return reply({ ok: true, service: "us-today-push", ready: !!env.VAPID_D }, 200, origin);
    if (req.method !== "POST") return reply({ error: "method" }, 405, origin);
    if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
    if (!env.VAPID_D) return reply({ error: "missing VAPID_D secret" }, 500, origin);
    let data; try { data = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
    const sub = data && data.sub;
    if (!sub || typeof sub.endpoint !== "string" || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return reply({ error: "bad subscription" }, 400, origin);
    let host; try { host = new URL(sub.endpoint).hostname; } catch { return reply({ error: "bad endpoint" }, 400, origin); }
    if (!PUSH_HOSTS.some((r) => r.test(host))) return reply({ error: "endpoint not allowed" }, 400, origin);
    const payload = JSON.stringify({ title: String(data.title || "Us, Today").slice(0, 80), body: String(data.body || "").slice(0, 240), url: String(data.url || "").slice(0, 400), tag: String(data.tag || "").slice(0, 40) });
    const body = await encrypt(sub, payload);
    const res = await fetch(sub.endpoint, { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal", Authorization: await vapidAuth(sub.endpoint, env.VAPID_D) }, body });
    return reply({ ok: res.ok, status: res.status, gone: res.status === 404 || res.status === 410 }, 200, origin);
  },
};
