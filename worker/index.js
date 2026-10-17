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

// AI ideas. The app sends a plain-text summary of check-ins and About me answers; the prompts live here.
const AI_MODEL = "claude-sonnet-5-5";
const AI_PROMPTS = {
  suggest: {
    max: 700,
    system: `You help one partner in a couple show up for the other today. You will get the partner's check-in for today, their recent days, their About me answers, and the user's own schedule.
Write warm, specific, practical ideas for today, grounded only in the details given. Use the partner's name. Plain everyday words. No therapy jargon, no diagnosing, no generic advice that would fit anyone.
Fit the ideas to the user's schedule and today's day of the week. If an idea uses a favorite (flowers, treat, food, place), name it.
If anything suggests danger, abuse or a crisis, make the first step gently encouraging reaching out to a trusted person or a professional.
Respond with JSON only, no other text:
{"headline": "one sentence, at most 22 words, on how they seem today and what would help most",
 "steps": [{"title": "imperative, under 10 words", "detail": "1 or 2 sentences: how, and why it fits them"}],
 "avoid": "one short sentence on what not to do today, or an empty string"}
Give exactly 3 steps.`,
  },
  summary: {
    max: 900,
    system: `Write a short weekly reflection for a couple from both partners' daily check-ins over the last 7 days, plus their About me answers and schedules.
Be warm, honest and specific: name who, which days, and what the check-ins showed. Notice links with schedules (work days, kid nights) when the data supports it. Do not diagnose, assign blame or invent details. If there are few check-ins, say so briefly and keep it short.
If anything suggests danger, abuse or a crisis, gently encourage reaching out to a trusted person or a professional.
Respond with JSON only, no other text:
{"title": "short title for the week, at most 8 words",
 "patterns": ["2 or 3 short observations, one or two sentences each"],
 "win": "one sentence on something that went well between them",
 "try": ["2 concrete ideas for the coming week that fit their schedules"]}`,
  },
};
async function runAi(env, mode, facts) {
  const p = AI_PROMPTS[mode];
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model: AI_MODEL, max_tokens: p.max, system: p.system, messages: [{ role: "user", content: String(facts).slice(0, 9000) }] }),
  });
  if (!r.ok) return { error: "ai " + r.status };
  const d = await r.json();
  const text = (d.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return { error: "no json" };
  try { return { result: JSON.parse(m[0]) }; } catch (_) { return { error: "bad json" }; }
}

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
    if (req.method === "GET" && path === "/preview") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      const id = (new URL(req.url).searchParams.get("id") || "").replace(/^dz/, "");
      if (!/^\d{1,15}$/.test(id)) return reply({ error: "bad id" }, 400, origin);
      let preview = "";
      try { const r = await fetch("https://api.deezer.com/track/" + id); if (r.ok) preview = (await r.json()).preview || ""; } catch (_) {}
      return reply({ preview }, 200, origin);
    }
    if (req.method === "GET" && path === "/search") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      const results = await searchSongs(new URL(req.url).searchParams.get("term") || "");
      return new Response(JSON.stringify({ results }), { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=3600", ...cors(origin) } });
    }
    if (req.method === "GET") return reply({ ok: true, service: "us-today-push", ready: !!env.VAPID_D, ai: !!env.ANTHROPIC_API_KEY }, 200, origin);
    if (req.method === "POST" && path === "/ai") {
      if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.ANTHROPIC_API_KEY) return reply({ error: "ai off" }, 503, origin);
      let d; try { d = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
      if (!d || !AI_PROMPTS[d.mode] || typeof d.facts !== "string" || d.facts.length < 20) return reply({ error: "bad request" }, 400, origin);
      try { const out = await runAi(env, d.mode, d.facts); return reply(out, out.error ? 502 : 200, origin); }
      catch (_) { return reply({ error: "ai failed" }, 502, origin); }
    }
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
