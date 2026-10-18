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

async function sendPush(env, sub, msg) {
  const payload = JSON.stringify({ title: String(msg.title || "Us, Today").slice(0, 80), body: String(msg.body || "").slice(0, 240), url: String(msg.url || "").slice(0, 400), tag: String(msg.tag || "").slice(0, 40) });
  const body = await encrypt(sub, payload);
  const res = await fetch(sub.endpoint, { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal", Authorization: await vapidAuth(sub.endpoint, env.VAPID_D) }, body });
  return { ok: res.ok, status: res.status, gone: res.status === 404 || res.status === 410 };
}
const validSub = (sub) => { if (!sub || typeof sub.endpoint !== "string" || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return false; try { return PUSH_HOSTS.some((r) => r.test(new URL(sub.endpoint).hostname)); } catch (_) { return false; } };

// Check-in reminders. Each person is one KV key: value holds the push subscription; metadata holds
// the small state the schedule needs (time zone, choices, today's check-in times, what was sent).
const REMIND_ID = /^[0-9a-f]{16}-[ab]$/;
function localParts(tz) {
  let f;
  try { f = new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23" }); }
  catch (_) { f = new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23" }); }
  const o = {}; for (const p of f.formatToParts(new Date())) o[p.type] = p.value;
  return { date: `${o.year}-${o.month}-${o.day}`, min: (+o.hour % 24) * 60 + +o.minute, weekday: o.weekday };
}
async function saveReminder(env, d) {
  if (!REMIND_ID.test(d.id || "")) return { error: "bad id" };
  const am = !!d.am, mid = !!d.mid;
  // Dated reminders (birthdays, anniversaries, date night). The app works out the send times.
  const now = Date.now();
  const ev = (Array.isArray(d.ev) ? d.ev : []).filter((e) => e && Number.isFinite(+e.at) && +e.at > now && +e.at < now + 50 * 86400000)
    .slice(0, 16).map((e) => ({ at: +e.at, t: String(e.t || "").slice(0, 80), b: String(e.b || "").slice(0, 140), g: String(e.g || "").slice(0, 40) }));
  if ((!am && !mid && !ev.length) || !validSub(d.sub)) { await env.REMIND.delete(d.id); return { ok: true, off: true }; }
  const old = (await env.REMIND.getWithMetadata(d.id)).metadata || {};
  const st = d.state || {};
  const meta = { tz: String(d.tz || "America/New_York").slice(0, 40), am, mid, d: String(st.date || old.d || "").slice(0, 10),
    f: Number.isFinite(+st.first) ? +st.first : (old.f ?? -1), l: Number.isFinite(+st.last) ? +st.last : (old.l ?? -1), s: st.same != null ? !!st.same : !!old.s,
    sa: old.sa || "", sm: old.sm || "", nx: ev.length ? Math.min(...ev.map((e) => e.at)) : 0 };
  if (st.date && st.date !== old.d && st.same == null) meta.s = false;
  await env.REMIND.put(d.id, JSON.stringify({ sub: d.sub, url: String(d.url || "").slice(0, 400), partner: String(d.partner || "").slice(0, 40), ev }), { metadata: meta });
  return { ok: true };
}
async function runReminders(env) {
  if (!env.REMIND || !env.VAPID_D) return;
  let cursor;
  do {
    const page = await env.REMIND.list({ cursor });
    for (const k of page.keys) {
      let m = k.metadata || {}; const t = localParts(m.tz);
      if (m.nx && Date.now() >= m.nx) {
        const rec = await env.REMIND.get(k.name, "json");
        if (rec && rec.sub) {
          const now = Date.now(), due = (rec.ev || []).filter((e) => e.at <= now), rest = (rec.ev || []).filter((e) => e.at > now);
          let gone = false;
          for (const e of due) {
            if (e.at < now - 6 * 3600000) continue; // too late to be useful
            const r = await sendPush(env, rec.sub, { title: e.t, body: e.b, tag: e.g || "occ", url: rec.url || "" }).catch(() => ({ ok: false }));
            if (r.gone) { gone = true; break; }
          }
          if (gone) { await env.REMIND.delete(k.name); continue; }
          rec.ev = rest; m = { ...m, nx: rest.length ? Math.min(...rest.map((e) => e.at)) : 0 };
          if (!m.am && !m.mid && !rest.length) { await env.REMIND.delete(k.name); continue; }
          await env.REMIND.put(k.name, JSON.stringify(rec), { metadata: m });
        }
      }
      if (["Sat", "Sun"].includes(t.weekday)) continue;
      let msg = null, mark = null;
      const checkedToday = m.d === t.date;
      if (m.am && t.min >= 540 && t.min < 570 && !checkedToday && m.sa !== t.date) {
        msg = { title: "Good morning ☀️", body: "How are you feeling today? Take 30 seconds to check in.", tag: "remind-am" }; mark = "sa";
      } else if (m.mid && t.min >= 750 && t.min < 780 && m.sm !== t.date) {
        if (checkedToday && m.f >= 0 && m.f < 660 && !(m.l >= 660) && !m.s) { msg = { title: "Midday check 🌤️", body: "Anything changed since this morning? Update your check-in or keep it the same.", tag: "remind-mid", hash: "#midday" }; }
        else if (!checkedToday) { msg = { title: "Still time to check in 💞", body: "Let your partner know how your day is going.", tag: "remind-mid" }; }
        mark = "sm";
      }
      if (!mark) continue;
      const rec = await env.REMIND.get(k.name, "json");
      if (!rec || !rec.sub) continue;
      if (msg) {
        const r = await sendPush(env, rec.sub, { ...msg, url: (rec.url || "") + (msg.hash || "") }).catch(() => ({ ok: false }));
        if (r.gone) { await env.REMIND.delete(k.name); continue; }
      }
      await env.REMIND.put(k.name, JSON.stringify(rec), { metadata: { ...m, [mark]: t.date } });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

// AI ideas. The app sends a plain-text summary of check-ins and About me answers; the prompts live here.
const AI_MODEL = "claude-sonnet-5-5";
const AI_PROMPTS = {
  suggest: {
    max: 1200,
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
    max: 1600,
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
// Pull the JSON object out of a reply, tolerating code fences or a sentence before/after it.
function parseAiJson(text) {
  const t = String(text || "").replace(/```(?:json)?/gi, "");
  const i = t.indexOf("{"), j = t.lastIndexOf("}");
  if (i < 0 || j <= i) return null;
  try { return JSON.parse(t.slice(i, j + 1)); } catch (_) {}
  try { return JSON.parse(t.slice(i, j + 1).replace(/,\s*([}\]])/g, "$1")); } catch (_) {}
  return null;
}
async function runAi(env, mode, facts) {
  const p = AI_PROMPTS[mode];
  let last = "no json";
  for (let attempt = 0; attempt < 2; attempt++) {
    const system = attempt ? p.system + "\nKeep it brief. Reply with the JSON object only, complete and valid." : p.system;
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: AI_MODEL, max_tokens: p.max, system, messages: [{ role: "user", content: String(facts).slice(0, 9000) }] }),
    });
    if (!r.ok) { last = "ai " + r.status; if (r.status === 429 || r.status >= 500) continue; return { error: last }; }
    const d = await r.json();
    const text = (d.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
    const out = parseAiJson(text);
    if (out) return { result: out };
    last = d.stop_reason === "max_tokens" ? "cut off" : "no json";
  }
  return { error: last };
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
    if (req.method === "GET") return reply({ ok: true, service: "us-today-push", ready: !!env.VAPID_D, ai: !!env.ANTHROPIC_API_KEY, reminders: !!env.REMIND }, 200, origin);
    if (req.method === "POST" && path === "/remind") {
      if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.REMIND) return reply({ error: "reminders off" }, 503, origin);
      let d; try { d = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
      try { const out = await saveReminder(env, d || {}); return reply(out, out.error ? 400 : 200, origin); } catch (_) { return reply({ error: "failed" }, 500, origin); }
    }
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
    return reply(await sendPush(env, sub, data), 200, origin);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runReminders(env));
  },
};
