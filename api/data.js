'use strict';
const u = require('../lib/util');

const KEY_RE = /^(core|tx-\d{4}-(0[1-9]|1[0-2]))$/;
const MAX_DOC_BYTES = 400 * 1024, MAX_DOCS_PER_REQUEST = 120;

module.exports = u.wrap(async (req, res) => {
  const s = await u.requireSession(req);
  const hkey = 'd:' + s.user;

  if (req.method === 'GET') {
    const flat = await u.cmd('HGETALL', hkey);
    const docs = {};
    if (Array.isArray(flat)) { for (let i = 0; i < flat.length; i += 2) { try { docs[flat[i]] = JSON.parse(flat[i + 1]); } catch (e) {} } }
    else if (flat && typeof flat === 'object') { Object.keys(flat).forEach(k => { try { docs[k] = JSON.parse(flat[k]); } catch (e) {} }); }
    return u.send(res, 200, { docs });
  }

  if (req.method === 'PUT') {
    u.guardWrite(req);
    const body = await u.readBody(req);
    const docs = body && body.docs;
    if (!docs || typeof docs !== 'object' || Array.isArray(docs)) return u.send(res, 400, { error: 'Missing docs.' });
    const keys = Object.keys(docs);
    if (!keys.length) return u.send(res, 200, { saved: 0 });
    if (keys.length > MAX_DOCS_PER_REQUEST) return u.send(res, 413, { error: 'Too many documents in one request.' });
    const args = ['HSET', hkey];
    for (const k of keys) {
      if (!KEY_RE.test(k)) return u.send(res, 400, { error: 'Invalid document key: ' + k });
      const v = docs[k];
      if (!v || typeof v !== 'object' || Array.isArray(v)) return u.send(res, 400, { error: 'Document must be an object.' });
      const json = JSON.stringify(v);
      if (Buffer.byteLength(json) > MAX_DOC_BYTES) return u.send(res, 413, { error: 'Document ' + k + ' is too large.' });
      args.push(k, json);
    }
    await u.cmd(...args);
    return u.send(res, 200, { saved: keys.length });
  }

  if (req.method === 'DELETE') {
    u.guardWrite(req);
    await u.cmd('DEL', hkey);
    return u.send(res, 200, { ok: true });
  }

  return u.send(res, 405, { error: 'Method not allowed.' });
});
