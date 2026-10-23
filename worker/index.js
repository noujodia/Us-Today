// Noudé notification sender (Cloudflare Worker).
// Receives {sub, title, body, url} from the app and delivers an encrypted Web Push.
// The VAPID private key is stored as the secret VAPID_D in Cloudflare, never in this file.
const VAPID_PUBLIC = "BH9swIrCDeQtLef9p5w_PeBjFBodHEF5AWX2j4aktaTlHWYquTK9HCNx_VIgClhmmK4F1sC0Jn6UmK_AgKvm8jU";
const VAPID_X = "f2zAisIN5C0t5_2nnD894GMUGh0cQXkBZfaPhqS1pOU";
const VAPID_Y = "HWYquTK9HCNx_VIgClhmmK4F1sC0Jn6UmK_AgKvm8jU";
const SUBJECT = "https://noujodia.github.io/Us-Today/";
const ALLOWED_ORIGINS = ["https://noujodia.github.io", "https://noudeapp.com", "https://www.noudeapp.com"];
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
  const payload = JSON.stringify({ title: String(msg.title || "Noudé").slice(0, 80), body: String(msg.body || "").slice(0, 240), url: String(msg.url || "").slice(0, 400), tag: String(msg.tag || "").slice(0, 40) });
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
  if (!validSub(d.sub)) { await env.REMIND.delete(d.id); return { ok: true, off: true }; }
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
      if (!REMIND_ID.test(k.name)) continue; // owner alerts and other keys live here too
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
Be warm, honest and specific: name who, which days, and what the check-ins showed. Notice links with schedules (work days, kid nights) when the data supports it. Some feelings come with a reason (work, personal, or just in general, sometimes in their own words); use it. Celebrate logged wins by name and count. Do not diagnose, assign blame or invent details. If there are few check-ins, say so briefly and keep it short.
If anything suggests danger, abuse or a crisis, gently encourage reaching out to a trusted person or a professional.
Respond with JSON only, no other text:
{"title": "short title for the week, at most 8 words",
 "patterns": ["2 or 3 short observations, one or two sentences each"],
 "win": "one sentence on something that went well between them",
 "wins": ["1 or 2 short celebrations of the wins they logged, with counts, like 'Maya worked out 3 times this week'. Empty list if no wins were logged"],
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

// Owner alerts: the owner's phones register here (guarded by the owner key's hash, trust on first use),
// and any app can report that a beta invite code was used. Each code alerts once.
const OWNER_REC = "owner:subs";
const CODE_RE = /^US-[A-Z0-9]{6}$/;
async function ownerRegister(env, d) {
  if (!/^[0-9a-f]{64}$/.test(d.k || "") || !validSub(d.sub)) return { error: "bad request" };
  const rec = (await env.REMIND.get(OWNER_REC, "json")) || { k: "", subs: [] };
  if (rec.k && rec.k !== d.k) return { error: "key" };
  rec.k = d.k;
  rec.subs = [{ sub: d.sub, url: String(d.url || "").slice(0, 400) }, ...(rec.subs || []).filter((x) => x.sub && x.sub.endpoint !== d.sub.endpoint)].slice(0, 6);
  await env.REMIND.put(OWNER_REC, JSON.stringify(rec));
  return { ok: true, phones: rec.subs.length };
}
// Owner spotlight push: owner key required, at most once every 2 days, only to the chosen anonymous couples.
async function ownerBroadcast(env, d) {
  const rec = await env.REMIND.get(OWNER_REC, "json");
  if (!rec || !rec.k || !/^[0-9a-f]{64}$/.test(d.k || "") || rec.k !== d.k) return { error: "key" };
  const last = +(await env.REMIND.get("bc:last")) || 0, now = Date.now();
  if (now - last < 2 * 86400000 && !d.dry) return { error: "too soon", next: last + 2 * 86400000 };
  const title = String(d.title || "Noudé").slice(0, 60), body = String(d.body || "").slice(0, 200), hash = /^#[\w=-]{1,40}$/.test(d.hash || "") ? d.hash : "";
  if (!body) return { error: "empty" };
  const targets = Array.isArray(d.targets) ? new Set(d.targets.filter((t) => /^[0-9a-f]{16}$/.test(t))) : null;
  let cursor, sent = 0, reach = 0;
  do {
    const page = await env.REMIND.list({ cursor });
    for (const k of page.keys) {
      if (!REMIND_ID.test(k.name)) continue;
      if (targets && !targets.has(k.name.slice(0, 16))) continue;
      reach++; if (d.dry) continue;
      const r0 = await env.REMIND.get(k.name, "json");
      if (!r0 || !r0.sub) continue;
      const r = await sendPush(env, r0.sub, { title, body, tag: "spot", url: (r0.url || "") + hash }).catch(() => ({ ok: false }));
      if (r.ok) sent++;
      if (r.gone) await env.REMIND.delete(k.name);
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  if (!d.dry) await env.REMIND.put("bc:last", String(now));
  return { ok: true, sent, reach };
}
async function ownerCodeUsed(env, d) {
  const code = String(d.code || "").toUpperCase();
  if (!CODE_RE.test(code)) return { error: "bad code" };
  const seen = "used:" + code;
  if (await env.REMIND.get(seen)) return { ok: true, dup: true };
  await env.REMIND.put(seen, "1", { expirationTtl: 60 * 60 * 24 * 60 });
  const rec = await env.REMIND.get(OWNER_REC, "json");
  if (!rec || !rec.subs || !rec.subs.length) return { ok: true, sent: 0 };
  const note = String(d.note || "").replace(/[\u0000-\u001f]/g, "").slice(0, 40);
  const msg = { title: "🎉 A beta invite was used", body: note ? `${note}'s code (${code}) just started a new space.` : `Code ${code} just started a new space.`, tag: "owner-code" };
  let sent = 0; const keep = [];
  for (const x of rec.subs) {
    const r = await sendPush(env, x.sub, { ...msg, url: x.url || "" }).catch(() => ({ ok: false }));
    if (r.ok) sent++;
    if (!r.gone) keep.push(x);
  }
  if (keep.length !== rec.subs.length) { rec.subs = keep; await env.REMIND.put(OWNER_REC, JSON.stringify(rec)); }
  return { ok: true, sent };
}

// GIF search through GIPHY. Needs a GIPHY_KEY secret in Cloudflare (Settings → Variables and secrets).
// Date ideas near you: Ticketmaster Discovery events within a radius of a ZIP code, for the next 3 weeks.
// Only the ZIP and the chosen interests are sent; results are cached for 6 hours.
const EVENT_CATS = { music: "Music", comedy: "Comedy", theater: "Theatre", sports: "Sports", family: "Family", film: "Film", arts: "Fine Art" };
async function nearbyEvents(env, sp) {
  const zip = (sp.get("zip") || "").trim();
  if (!/^\d{5}$/.test(zip)) return { error: "zip" };
  const radius = Math.min(50, Math.max(1, parseInt(sp.get("r") || "15", 10) || 15));
  const cats = (sp.get("cats") || "").split(",").map((s) => s.trim()).filter((c) => EVENT_CATS[c]).slice(0, 7);
  const kws = (sp.get("kw") || "").split("|").map((s) => s.trim().replace(/[^\p{L}\p{N} &'-]/gu, "").slice(0, 40)).filter(Boolean).slice(0, 3);
  const start = new Date(), end = new Date(Date.now() + 21 * 864e5);
  const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
  const base = `https://app.ticketmaster.com/discovery/v2/events.json?apikey=${encodeURIComponent(env.TM_KEY)}&postalCode=${zip}&radius=${radius}&unit=miles&countryCode=US&startDateTime=${iso(start)}&endDateTime=${iso(end)}&sort=date,asc&size=40`;
  const urls = [];
  if (cats.length) urls.push(base + "&classificationName=" + encodeURIComponent(cats.map((c) => EVENT_CATS[c]).join(",")));
  else if (!kws.length) urls.push(base);
  kws.forEach((k) => urls.push(base + "&keyword=" + encodeURIComponent(k)));
  const cache = caches.default, seen = new Set(), events = [];
  for (const u of urls) {
    let data = null;
    try {
      const key = new Request(u.replace(/apikey=[^&]+/, "apikey=x"));
      let r = await cache.match(key);
      if (!r) { const live = await fetch(u); if (!live.ok) continue; r = new Response(await live.text(), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=21600" } }); await cache.put(key, r.clone()); }
      data = await r.json();
    } catch (_) { continue; }
    for (const e of (data && data._embedded && data._embedded.events) || []) {
      const v = (e._embedded && e._embedded.venues && e._embedded.venues[0]) || {};
      const k = (e.name || "") + "|" + (e.dates && e.dates.start && e.dates.start.localDate) + "|" + (v.name || "");
      if (!e.id || seen.has(k)) continue; seen.add(k);
      const c = (e.classifications && e.classifications[0]) || {};
      const img = (e.images || []).filter((i) => i.url && /^https:\/\//.test(i.url) && i.width >= 300 && i.width <= 1100).sort((a, b) => a.width - b.width)[0];
      const url = typeof e.url === "string" && /^https:\/\/([a-z0-9-]+\.)*(ticketmaster|livenation|universe|frontgatetickets)\.com\//i.test(e.url) ? e.url : "";
      events.push({ id: String(e.id).slice(0, 40), name: String(e.name || "").slice(0, 120), url, date: (e.dates && e.dates.start && e.dates.start.localDate) || "", time: (e.dates && e.dates.start && e.dates.start.localTime) || "",
        venue: String(v.name || "").slice(0, 80), city: String((v.city && v.city.name) || "").slice(0, 40), dist: typeof e.distance === "number" ? Math.round(e.distance * 10) / 10 : null,
        cat: String((c.genre && c.genre.name !== "Undefined" && c.genre.name) || (c.segment && c.segment.name) || "").slice(0, 30), seg: String((c.segment && c.segment.name) || "").slice(0, 30), img: img ? img.url : "" });
    }
  }
  events.sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time));
  return { events: events.slice(0, 24) };
}
// Follow a TikTok share link to the full video address (up to 3 hops).
async function resolveTikTok(u) {
  let cur = u;
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(cur, { method: "GET", redirect: "manual", headers: { "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1" } });
      const loc = r.headers.get("Location");
      if (!loc) return cur;
      const next = new URL(loc, cur);
      if (!/(^|\.)tiktok\.com$/.test(next.hostname)) return cur;
      cur = next.href;
      if (/\/video\/\d+/.test(next.pathname)) return cur;
    } catch (_) { return cur; }
  }
  return cur;
}
// Title and thumbnail for a YouTube or TikTok link, from their free public oEmbed endpoints (no key).
async function oembed(u) {
  let x; try { x = new URL(String(u).slice(0, 500)); } catch (_) { return { error: "bad url" }; }
  if (x.protocol !== "https:" && x.protocol !== "http:") return { error: "bad url" };
  const h = x.hostname.replace(/^(www\.|m\.)/, "");
  let api = "", provider = "";
  if (/^(youtube\.com|youtu\.be|music\.youtube\.com)$/.test(h)) { api = "https://www.youtube.com/oembed?format=json&url=" + encodeURIComponent(x.href); provider = "youtube"; }
  else if (/^(tiktok\.com|vm\.tiktok\.com|vt\.tiktok\.com)$/.test(h)) {
    // Share links (tiktok.com/t/…, vm.tiktok.com/…) are redirects; TikTok's oEmbed only knows the full /@user/video/… address.
    let full = x.href;
    if (h !== "tiktok.com" || /^\/t\//.test(x.pathname)) full = await resolveTikTok(x.href);
    try { const f = new URL(full); full = f.origin + f.pathname; } catch (_) {}
    api = "https://www.tiktok.com/oembed?url=" + encodeURIComponent(full); provider = "tiktok";
  }
  else return { error: "unsupported" };
  try {
    const r = await fetch(api, { headers: { "User-Agent": "Noude/1.0 (+https://noudeapp.com)" } });
    if (!r.ok) return { error: "not found" };
    const d = await r.json();
    const thumb = typeof d.thumbnail_url === "string" && /^https:\/\//.test(d.thumbnail_url) ? d.thumbnail_url.slice(0, 600) : "";
    return { provider, title: String(d.title || "").slice(0, 150), author: String(d.author_name || "").slice(0, 80), thumb };
  } catch (_) { return { error: "failed" }; }
}
async function searchGifs(env, q, offset) {
  const params = new URLSearchParams({ api_key: env.GIPHY_KEY, limit: "24", offset: String(Math.max(0, Math.min(+offset || 0, 200))), rating: "pg-13", bundle: "messaging_non_clips" });
  const url = q ? "https://api.giphy.com/v1/gifs/search?" + params + "&q=" + encodeURIComponent(q.slice(0, 50)) : "https://api.giphy.com/v1/gifs/trending?" + params;
  const r = await fetch(url);
  if (!r.ok) return { error: "giphy " + r.status };
  const d = await r.json();
  const ok = (u) => typeof u === "string" && /^https:\/\/media\d*\.giphy\.com\//.test(u);
  return { results: (d.data || []).map((g) => {
    const im = g.images || {}, sm = im.fixed_width || {}, md = im.downsized_medium || im.downsized || im.original || {};
    return { id: String(g.id || "").slice(0, 40), title: String(g.title || "").slice(0, 80), thumb: ok(sm.url) ? sm.url : "", url: ok(md.url) ? md.url : (ok(sm.url) ? sm.url : ""), w: +md.width || +sm.width || 0, h: +md.height || +sm.height || 0 };
  }).filter((g) => g.id && g.url && g.thumb) };
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
    if (req.method === "GET" && path === "/events") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.TM_KEY) return reply({ events: [], off: true }, 200, origin);
      const out = await nearbyEvents(env, new URL(req.url).searchParams);
      return new Response(JSON.stringify(out), { status: out.error ? 400 : 200, headers: { "Content-Type": "application/json", "Cache-Control": out.error ? "no-store" : "public, max-age=21600", ...cors(origin) } });
    }
    if (req.method === "GET" && path === "/oembed") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      const out = await oembed(new URL(req.url).searchParams.get("url") || "");
      return new Response(JSON.stringify(out), { status: out.error ? 400 : 200, headers: { "Content-Type": "application/json", "Cache-Control": out.error ? "no-store" : "public, max-age=86400", ...cors(origin) } });
    }
    if (req.method === "GET" && path === "/gif") {
      if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.GIPHY_KEY) return reply({ error: "gif off" }, 503, origin);
      const sp = new URL(req.url).searchParams;
      try { const out = await searchGifs(env, (sp.get("q") || "").trim(), sp.get("offset")); return new Response(JSON.stringify(out), { status: out.error ? 502 : 200, headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=600", ...cors(origin) } }); }
      catch (_) { return reply({ error: "gif failed" }, 502, origin); }
    }
    if (req.method === "GET") return reply({ ok: true, gif: !!env.GIPHY_KEY, service: "us-today-push", ready: !!env.VAPID_D, ai: !!env.ANTHROPIC_API_KEY, reminders: !!env.REMIND }, 200, origin);
    if (req.method === "POST" && path === "/remind") {
      if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.REMIND) return reply({ error: "reminders off" }, 503, origin);
      let d; try { d = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
      try { const out = await saveReminder(env, d || {}); return reply(out, out.error ? 400 : 200, origin); } catch (_) { return reply({ error: "failed" }, 500, origin); }
    }
    if (req.method === "POST" && path === "/broadcast") {
      if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.REMIND || !env.VAPID_D) return reply({ error: "off" }, 503, origin);
      let d; try { d = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
      try { const out = await ownerBroadcast(env, d || {}); return reply(out, out.error ? 400 : 200, origin); } catch (_) { return reply({ error: "failed" }, 500, origin); }
    }
    if (req.method === "POST" && (path === "/owner" || path === "/code-used")) {
      if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "origin" }, 403, origin);
      if (!env.REMIND || !env.VAPID_D) return reply({ error: "off" }, 503, origin);
      let d; try { d = await req.json(); } catch { return reply({ error: "bad json" }, 400, origin); }
      try { const out = path === "/owner" ? await ownerRegister(env, d || {}) : await ownerCodeUsed(env, d || {}); return reply(out, out.error ? 400 : 200, origin); }
      catch (_) { return reply({ error: "failed" }, 500, origin); }
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
