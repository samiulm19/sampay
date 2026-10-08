'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const REDIS_URL = () => process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || process.env.REDIS_REST_URL;
const REDIS_TOKEN = () => process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || process.env.REDIS_REST_TOKEN;
const COOKIE = 'tt_session';
const SESSION_DAYS = 30;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/* ---------- Redis over REST (Upstash / Vercel KV) ---------- */
async function redis(commands, pipeline) {
  const url = REDIS_URL(), token = REDIS_TOKEN();
  if (!url || !token) throw new HttpError(500, 'Database is not connected. Add an Upstash Redis store to this Vercel project.');
  const r = await fetch(pipeline ? url.replace(/\/$/, '') + '/pipeline' : url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(commands)
  });
  let j;
  try { j = await r.json(); } catch (e) { throw new HttpError(502, 'Database returned an invalid response.'); }
  if (!pipeline) { if (j.error) throw new HttpError(502, 'Database error: ' + j.error); return j.result; }
  return j.map(x => { if (x.error) throw new HttpError(502, 'Database error: ' + x.error); return x.result; });
}
const cmd = (...args) => redis(args, false);
const pipe = list => redis(list, true);

/* ---------- http helpers ---------- */
function send(res, status, body, headers) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (headers) Object.keys(headers).forEach(k => res.setHeader(k, headers[k]));
  res.end(JSON.stringify(body));
}
async function readBody(req) {
  if (req.body !== undefined && req.body !== null && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { throw new HttpError(400, 'Invalid JSON.'); } }
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > 1.5e6) throw new HttpError(413, 'Request too large.'); chunks.push(c); }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { throw new HttpError(400, 'Invalid JSON.'); }
}
function guardWrite(req) {
  const ct = String(req.headers['content-type'] || '');
  if (req.method !== 'GET' && req.method !== 'DELETE' && ct.indexOf('application/json') < 0) throw new HttpError(415, 'Use application/json.');
  const origin = req.headers.origin;
  if (origin && req.method !== 'GET') {
    let host; try { host = new URL(origin).host; } catch (e) { throw new HttpError(403, 'Bad origin.'); }
    const mine = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
    if (host !== mine) throw new HttpError(403, 'Cross-site request blocked.');
  }
}
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
function cookieHeader(req, value, maxAge) {
  const secure = String(req.headers['x-forwarded-proto'] || '').indexOf('https') >= 0 || !!process.env.VERCEL;
  return COOKIE + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (secure ? '; Secure' : '');
}

/* ---------- sessions (HMAC signed cookie) ---------- */
function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) throw new HttpError(500, 'AUTH_SECRET is missing. Add a random string of 32+ characters in Vercel Environment Variables.');
  return s;
}
const b64u = b => Buffer.from(b).toString('base64url');
function makeToken(user, created) {
  const payload = b64u(JSON.stringify({ u: user, c: created, exp: Date.now() + SESSION_DAYS * 864e5 }));
  const sig = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function readToken(token) {
  if (!token || token.indexOf('.') < 0) return null;
  const [payload, sig] = token.split('.');
  const good = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}
async function getSession(req) {
  const p = readToken(parseCookies(req)[COOKIE]);
  if (!p) return null;
  const raw = await cmd('GET', 'user:' + p.u);
  if (!raw) return null;
  let rec; try { rec = JSON.parse(raw); } catch (e) { return null; }
  if (rec.created !== p.c) return null;
  return { user: p.u, rec };
}
async function requireSession(req) {
  const s = await getSession(req);
  if (!s) throw new HttpError(401, 'Please log in.');
  return s;
}

/* ---------- passwords ---------- */
async function hashPassword(pw, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64);
  return { salt: salt.toString('hex'), hash: key.toString('hex') };
}
async function checkPassword(pw, rec) {
  const { hash } = await hashPassword(pw, rec.salt);
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
function cleanUsername(u) { return String(u || '').trim().toLowerCase(); }

function wrap(fn) {
  return async (req, res) => {
    try { await fn(req, res); }
    catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.message });
      console.error(e);
      send(res, 500, { error: 'Something went wrong on the server.' });
    }
  };
}

module.exports = { HttpError, cmd, pipe, send, readBody, guardWrite, clientIp, cookieHeader, makeToken, getSession, requireSession, hashPassword, checkPassword, USERNAME_RE, cleanUsername, wrap, COOKIE };
