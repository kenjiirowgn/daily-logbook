// Dailio sync API — Cloudflare Worker + D1.
// Static files are served from the assets binding; only /api/* runs here.

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS recs (username TEXT NOT NULL, k TEXT NOT NULL, v TEXT, t INTEGER NOT NULL, del INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL, PRIMARY KEY (username, k));
CREATE INDEX IF NOT EXISTS recs_seq ON recs (username, seq);
CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, n INTEGER NOT NULL, since INTEGER NOT NULL);
`;
let schemaReady = false;
const PBKDF2_ITERATIONS = 20000;
const USERNAME_RE = /^[a-z0-9_.]{3,20}$/;
const MAX_FAILED_LOGINS = 10; // per username per 15 minutes

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const randomHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITERATIONS }, key, 256);
  return hex(bits);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function ensureSchema(db) {
  if (schemaReady) return;
  // D1 exec runs one statement per line
  await db.exec(SCHEMA.trim());
  schemaReady = true;
}

async function readCreds(request) {
  let body;
  try { body = await request.json(); } catch { return { error: "Bad request" }; }
  const username = String(body?.username || "").trim().toLowerCase();
  const password = String(body?.password || "");
  if (!USERNAME_RE.test(username)) return { error: "Username 3-20 karakter, hanya huruf, angka, titik, atau underscore." };
  if (password.length < 6 || password.length > 200) return { error: "Password minimal 6 karakter." };
  return { username, password };
}

async function newSession(db, username) {
  const token = randomHex(32);
  await db.prepare("INSERT INTO sessions (token_hash, username, created) VALUES (?1, ?2, ?3)").bind(await sha256(token), username, Date.now()).run();
  return token;
}

async function authUser(db, request) {
  const m = (request.headers.get("authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) return null;
  const row = await db.prepare("SELECT username FROM sessions WHERE token_hash = ?1").bind(await sha256(m[1])).first();
  return row ? row.username : null;
}

async function signup(db, request) {
  const c = await readCreds(request);
  if (c.error) return json({ error: c.error }, 400);
  const exists = await db.prepare("SELECT 1 FROM users WHERE username = ?1").bind(c.username).first();
  if (exists) return json({ error: "Username sudah dipakai. Coba username lain atau Login." }, 409);
  const salt = randomHex(16);
  await db.prepare("INSERT INTO users (username, salt, hash, seq, created) VALUES (?1, ?2, ?3, 0, ?4)")
    .bind(c.username, salt, await hashPassword(c.password, salt), Date.now()).run();
  return json({ token: await newSession(db, c.username), username: c.username });
}

async function login(db, request) {
  const c = await readCreds(request);
  if (c.error) return json({ error: "Username atau password salah." }, 401);
  const now = Date.now(), window = 15 * 60 * 1000, akey = "login:" + c.username;
  const att = await db.prepare("SELECT n, since FROM attempts WHERE key = ?1").bind(akey).first();
  if (att && now - att.since < window && att.n >= MAX_FAILED_LOGINS)
    return json({ error: "Terlalu banyak percobaan. Coba lagi dalam 15 menit." }, 429);
  const user = await db.prepare("SELECT salt, hash FROM users WHERE username = ?1").bind(c.username).first();
  const ok = user && timingSafeEqual(await hashPassword(c.password, user.salt), user.hash);
  if (!ok) {
    if (!att || now - att.since >= window) await db.prepare("INSERT OR REPLACE INTO attempts (key, n, since) VALUES (?1, 1, ?2)").bind(akey, now).run();
    else await db.prepare("UPDATE attempts SET n = n + 1 WHERE key = ?1").bind(akey).run();
    return json({ error: "Username atau password salah." }, 401);
  }
  if (att) await db.prepare("DELETE FROM attempts WHERE key = ?1").bind(akey).run();
  return json({ token: await newSession(db, c.username), username: c.username });
}

async function logout(db, request) {
  const m = (request.headers.get("authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  if (m) await db.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(await sha256(m[1])).run();
  return json({ ok: true });
}

// Body: { since, changes: [{k, v (JSON text or null), t (ms), del (0|1)}] }
// Last-write-wins per record key. Returns every record whose seq > since.
async function sync(db, request) {
  const username = await authUser(db, request);
  if (!username) return json({ error: "Sesi habis. Silakan login lagi." }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Bad request" }, 400); }
  const since = Math.max(0, Number(body?.since) || 0);
  const changes = (Array.isArray(body?.changes) ? body.changes : [])
    .filter(c => c && typeof c.k === "string" && c.k.length <= 200 && Number.isFinite(+c.t))
    .map(c => ({ k: c.k, v: c.del ? null : (typeof c.v === "string" ? c.v : null), t: Math.floor(+c.t), del: c.del ? 1 : 0 }))
    .filter(c => c.del || c.v !== null);
  if (changes.length > 5000) return json({ error: "Too many changes in one request" }, 413);

  let seq;
  if (changes.length) {
    const bumped = await db.prepare("UPDATE users SET seq = seq + 1 WHERE username = ?1 RETURNING seq").bind(username).first();
    seq = bumped.seq;
    await db.prepare(
      `INSERT INTO recs (username, k, v, t, del, seq)
       SELECT ?1, json_extract(value, '$.k'), json_extract(value, '$.v'), json_extract(value, '$.t'), json_extract(value, '$.del'), ?2
       FROM json_each(?3) WHERE true
       ON CONFLICT (username, k) DO UPDATE SET v = excluded.v, t = excluded.t, del = excluded.del, seq = excluded.seq
       WHERE excluded.t > recs.t`
    ).bind(username, seq, JSON.stringify(changes)).run();
  } else {
    seq = (await db.prepare("SELECT seq FROM users WHERE username = ?1").bind(username).first()).seq;
  }
  const { results } = await db.prepare("SELECT k, v, t, del FROM recs WHERE username = ?1 AND seq > ?2").bind(username, since).all();
  return json({ seq, rows: results, username });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
    try {
      await ensureSchema(env.DB);
      switch (url.pathname) {
        case "/api/signup": return await signup(env.DB, request);
        case "/api/login": return await login(env.DB, request);
        case "/api/logout": return await logout(env.DB, request);
        case "/api/sync": return await sync(env.DB, request);
        default: return json({ error: "Not found" }, 404);
      }
    } catch (err) {
      console.error(err);
      return json({ error: "Server error" }, 500);
    }
  },
};
