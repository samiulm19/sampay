'use strict';
const u = require('../lib/util');

const MAX_FAILS = 10, WINDOW_S = 900;

async function limited(key) {
  const [n] = await u.pipe([['INCR', key], ['EXPIRE', key, WINDOW_S, 'NX']]);
  return n > MAX_FAILS;
}

module.exports = u.wrap(async (req, res) => {
  if (req.method === 'GET') {
    const s = await u.getSession(req);
    if (!s) return u.send(res, 401, { error: 'Not logged in.' });
    return u.send(res, 200, { user: s.user });
  }
  if (req.method !== 'POST') return u.send(res, 405, { error: 'Method not allowed.' });
  u.guardWrite(req);
  const body = await u.readBody(req);
  const action = body.action;

  if (action === 'signup') {
    const name = u.cleanUsername(body.username), pw = String(body.password || '');
    if (!u.USERNAME_RE.test(name)) return u.send(res, 400, { error: 'Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore.' });
    if (pw.length < 6 || pw.length > 200) return u.send(res, 400, { error: 'Password must be at least 6 characters.' });
    const ip = u.clientIp(req);
    if (await limited('rl:signup:' + ip)) return u.send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const { salt, hash } = await u.hashPassword(pw);
    const created = Date.now();
    const ok = await u.cmd('SET', 'user:' + name, JSON.stringify({ salt, hash, created }), 'NX');
    if (!ok) return u.send(res, 409, { error: 'That username is taken. Try another one.' });
    return u.send(res, 200, { user: name }, { 'Set-Cookie': u.cookieHeader(req, u.makeToken(name, created), 30 * 86400) });
  }

  if (action === 'login') {
    const name = u.cleanUsername(body.username), pw = String(body.password || '');
    const rlKey = 'rl:login:' + u.clientIp(req) + ':' + name;
    if (!u.USERNAME_RE.test(name) || !pw) return u.send(res, 401, { error: 'Wrong username or password.' });
    const cur = Number(await u.cmd('GET', rlKey)) || 0;
    if (cur >= MAX_FAILS) return u.send(res, 429, { error: 'Too many attempts. Try again in 15 minutes.' });
    const raw = await u.cmd('GET', 'user:' + name);
    let rec = null; try { rec = raw && JSON.parse(raw); } catch (e) {}
    const good = rec ? await u.checkPassword(pw, rec) : (await u.hashPassword(pw), false);
    if (!good) { await limited(rlKey); return u.send(res, 401, { error: 'Wrong username or password.' }); }
    await u.cmd('DEL', rlKey);
    return u.send(res, 200, { user: name }, { 'Set-Cookie': u.cookieHeader(req, u.makeToken(name, rec.created), 30 * 86400) });
  }

  if (action === 'logout') {
    return u.send(res, 200, { ok: true }, { 'Set-Cookie': u.cookieHeader(req, '', 0) });
  }

  if (action === 'delete') {
    const s = await u.requireSession(req);
    if (!(await u.checkPassword(String(body.password || ''), s.rec))) return u.send(res, 401, { error: 'Wrong password.' });
    await u.pipe([['DEL', 'user:' + s.user], ['DEL', 'd:' + s.user]]);
    return u.send(res, 200, { ok: true }, { 'Set-Cookie': u.cookieHeader(req, '', 0) });
  }

  return u.send(res, 400, { error: 'Unknown action.' });
});
