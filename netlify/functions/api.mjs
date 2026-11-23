// emilylam.hk backend: links, documents, Log posts with photos, status,
// document unlock (email code + password), requests and the admin dashboard.
// Runs as one Netlify Function at /api/*.
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

export const config = { path: '/api/*' };

const env = (k, d = '') => {
  try { const v = globalThis.Netlify?.env?.get?.(k); if (v) return v; } catch (e) {}
  return process.env[k] || d;
};
const db = () => globalThis.__TEST_STORE__ || getStore({ name: 'emilylam', consistency: 'strong' });

const SECTIONS = ['main', 'portfolio', 'certs', 'books', 'projects'];
const DEFAULT_DOCS = [
  { id: 'cv', name: 'CV', section: 'main' },
  { id: 'resume', name: 'Résumé', section: 'main' },
  { id: 'portfolio-personal', name: 'Personal', section: 'portfolio' },
  { id: 'portfolio-occupational', name: 'Occupational', section: 'portfolio' },
  { id: 'portfolio-ap2d', name: 'AP 2D Art & Design', extra: '5/5', section: 'portfolio' },
  { id: 'portfolio-apdrawing', name: 'AP Drawing', extra: '5/5', section: 'portfolio' },
  { id: 'cert-soty', name: 'Student of the Year — Scientist & Mathematician', section: 'certs' },
  { id: 'cert-speech', name: 'Champion, Hong Kong Schools Speech Festival', section: 'certs' },
  { id: 'cert-mediation', name: 'Champion, Peer Mediation Competition', section: 'certs' },
  { id: 'cert-biology', name: 'Gold Award, Biology Challenge', section: 'certs' },
  { id: 'cert-stem', name: 'Finalist, STEM Challenge', section: 'certs' },
  { id: 'cert-hkfyg', name: 'Finalist, HKFYG English Public Speaking Contest', section: 'certs' },
  { id: 'book-dnawayhome', name: 'DNA Way Home', section: 'books' },
  { id: 'book-dnaindigestion', name: 'DNA in Digestion', section: 'books' },
  { id: 'project-alginate', name: 'Alginate', section: 'projects' },
  { id: 'project-drdd', name: 'Date Rape Drug Detector', section: 'projects' },
  { id: 'project-medaitor', name: 'MedAitor', section: 'projects' },
];
const DEFAULT_LINKS = [
  { id: 'linkedin', label: 'LinkedIn', url: 'https://www.linkedin.com/in/emilylam-hk', note: '', color: '#0A66C2', icon: 'briefcase' },
  { id: 'instagram', label: 'Instagram', url: 'https://www.instagram.com/emilylam.hk', note: '', color: '#C13584', icon: 'camera' },
  { id: 'bufferbox', label: 'bufferbox.ing', url: 'https://bufferbox.ing', note: 'my current project', color: '#1F5F8B', icon: 'box' },
  { id: 'i2ol', label: 'i2ol.org', url: 'https://i2ol.org', note: 'the NGO I’m working at', color: '#6B3FA0', icon: 'globe' },
];
const ICONS = ['briefcase', 'camera', 'box', 'globe', 'link', 'flask', 'book', 'star', 'play', 'mail', 'notebook'];
const STATUSES = ['free', 'busy', 'travel', 'heads'];
const MAX_FILE = 4 * 1024 * 1024;
const MAX_PHOTO = 3 * 1024 * 1024;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ID_RE = /^[a-z0-9-]{1,60}$/;

/* ---------- helpers ---------- */
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
const fail = (error, status = 400) => json({ error }, status);
class SetupError extends Error {}
const secret = () => { const s = env('SESSION_SECRET'); if (!s || s.length < 16) throw new SetupError('SESSION_SECRET'); return s; };
const hmac = (data) => crypto.createHmac('sha256', secret()).update(data).digest('base64url');
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
export function sign(payload, ttlSec) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec })).toString('base64url');
  return body + '.' + hmac(body);
}
export function verify(token, roles) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!safeEqual(sig, hmac(body))) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch (e) { return null; }
  if (!p.exp || p.exp < Date.now() / 1000) return null;
  if (roles && !roles.includes(p.role)) return null;
  return p;
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw) { const salt = crypto.randomBytes(16).toString('hex'); return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex'); }
function checkPw(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, h] = stored.split(':');
  return safeEqual(crypto.scryptSync(pw, salt, 32).toString('hex'), h);
}
async function body(req) {
  const text = await req.text();
  if (text.length > 6 * 1024 * 1024) throw Object.assign(new Error('too_big'), { status: 413 });
  try { return text ? JSON.parse(text) : {}; } catch (e) { return {}; }
}
const getJSON = async (k, d) => (await db().get(k, { type: 'json' })) ?? d;
const setJSON = (k, v) => db().setJSON(k, v);
async function limited(key, max, windowSec) {
  const now = Date.now(); const k = 'rl/' + sha(key);
  const r = await getJSON(k, null);
  const next = !r || now - r.start > windowSec * 1000 ? { start: now, count: 1 } : { start: r.start, count: r.count + 1 };
  await setJSON(k, next);
  return next.count > max;
}
async function sendMail(to, subject, text) {
  const key = env('RESEND_API_KEY'); const from = env('MAIL_FROM');
  if (!key || !from) throw new SetupError('RESEND_API_KEY / MAIL_FROM');
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [to], subject, text }),
  });
  if (!r.ok) throw new Error('send_failed ' + r.status + ' ' + (await r.text()).slice(0, 200));
}
const site = () => env('SITE_URL', 'https://emilylam.hk').replace(/\/$/, '');
const bearer = (req, url) => (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('t') || '';
const clean = (s, n) => String(s ?? '').trim().slice(0, n);
const allowed = (p, doc) => p.all === true || (p.docs || []).includes(doc.id) || (p.sections || []).includes(doc.section);
const getDocs = () => getJSON('docs', DEFAULT_DOCS);
const getLinks = () => getJSON('links', DEFAULT_LINKS);
const newId = () => crypto.randomBytes(9).toString('base64url');
const toAB = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

/* Remove metadata from images: JPEG APPn (EXIF, XMP, IPTC) and COM segments; PNG text/EXIF/time chunks. */
export function stripImage(buf) {
  if (buf[0] === 0xFF && buf[1] === 0xD8) {
    const out = [buf.subarray(0, 2)]; let i = 2;
    while (i + 4 <= buf.length) {
      if (buf[i] !== 0xFF) return null;
      const marker = buf[i + 1];
      if (marker === 0xDA) { out.push(buf.subarray(i)); break; }           // start of scan: rest is image data
      const len = buf.readUInt16BE(i + 2);
      const keep = !((marker >= 0xE1 && marker <= 0xEF) || marker === 0xFE); // drop APP1–APP15 and comments
      if (keep) out.push(buf.subarray(i, i + 2 + len));
      i += 2 + len;
    }
    return { data: Buffer.concat(out), type: 'image/jpeg' };
  }
  const sig = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (buf.subarray(0, 8).equals(sig)) {
    const out = [sig]; let i = 8;
    const drop = new Set(['tEXt', 'iTXt', 'zTXt', 'eXIf', 'tIME']);
    while (i + 12 <= buf.length) {
      const len = buf.readUInt32BE(i); const type = buf.toString('ascii', i + 4, i + 8);
      const end = i + 12 + len;
      if (!drop.has(type)) out.push(buf.subarray(i, end));
      i = end; if (type === 'IEND') break;
    }
    return { data: Buffer.concat(out), type: 'image/png' };
  }
  return null;
}
async function deletePhotos(ids) { for (const id of ids || []) if (ID_RE.test(String(id).toLowerCase()) || /^[A-Za-z0-9_-]{6,40}$/.test(id)) await db().delete('photo/' + id); }

/* ---------- handler ---------- */
export default async (req, context) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const m = req.method;
  const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'unknown';
  try {
    /* ----- public ----- */
    if (route === 'public' && m === 'GET') {
      const [st, posts, links, docs] = await Promise.all([getJSON('status', { status: 'free' }), getJSON('posts', []), getLinks(), getDocs()]);
      return json({ status: st.status, posts, links, docs: docs.map(({ id, name, section, extra }) => ({ id, name, section, extra })) });
    }

    if (route === 'photo' && m === 'GET') {
      const id = url.searchParams.get('id') || '';
      if (!/^[A-Za-z0-9_-]{6,40}$/.test(id)) return new Response('Not found', { status: 404 });
      const r = await db().getWithMetadata('photo/' + id, { type: 'arrayBuffer' });
      if (!r || !r.data) return new Response('Not found', { status: 404 });
      return new Response(r.data, { headers: { 'content-type': r.metadata?.type || 'image/jpeg', 'cache-control': 'public, max-age=31536000, immutable' } });
    }

    if (route === 'code' && m === 'POST') {
      const { email } = await body(req);
      const e = clean(email, 200).toLowerCase();
      if (!EMAIL_RE.test(e)) return fail('bad_email');
      if (await limited('code-ip:' + ip, 10, 3600)) return fail('too_many', 429);
      const k = 'code/' + sha(e);
      const prev = await getJSON(k, null);
      if (prev && Date.now() - prev.sentAt < 45 * 1000) return fail('too_many', 429);
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      await setJSON(k, { hash: sha(code + secret()), exp: Date.now() + 10 * 60 * 1000, attempts: 0, sentAt: Date.now() });
      try {
        await sendMail(e, 'Your code for emilylam.hk: ' + code,
          `Your code is ${code}\n\nEnter it on emilylam.hk to keep going. It expires in 10 minutes.\n\nIf you didn't ask for this, you can ignore this email.`);
      } catch (err) { if (err instanceof SetupError) throw err; console.error(err); return fail('send_failed', 502); }
      return json({ ok: true });
    }

    if (route === 'verify' && m === 'POST') {
      const { email, code } = await body(req);
      const e = clean(email, 200).toLowerCase(); const c = clean(code, 6);
      const k = 'code/' + sha(e);
      const rec = await getJSON(k, null);
      if (!rec) return fail('expired');
      if (rec.exp < Date.now()) { await db().delete(k); return fail('expired'); }
      if (rec.attempts >= 5) return fail('too_many', 429);
      if (!safeEqual(sha(c + secret()), rec.hash)) { await setJSON(k, { ...rec, attempts: rec.attempts + 1 }); return fail('bad_code'); }
      await db().delete(k);
      return json({ vtoken: sign({ role: 'verified', email: e }, 15 * 60) });
    }

    if (route === 'unlock' && m === 'POST') {
      const { vtoken, password } = await body(req);
      const p = verify(vtoken, ['verified']);
      if (!p) return fail('expired');
      if (await limited('pw:' + p.email, 6, 900)) return fail('too_many', 429);
      const stored = (await getJSON('docs-password', {})).hash;
      if (!stored) return fail('no_password');
      if (!checkPw(clean(password, 200), stored)) return fail('bad_password');
      return json({ token: sign({ role: 'viewer', email: p.email, all: true }, 24 * 3600) });
    }

    if (route === 'docs' && m === 'GET') {
      const p = verify(bearer(req, url), ['viewer']);
      if (!p) return fail('expired', 401);
      const [docs, meta] = await Promise.all([getDocs(), getJSON('docs-meta', {})]);
      return json({ docs: docs.filter((d) => meta[d.id] && allowed(p, d)).map((d) => ({ id: d.id, name: d.name, section: d.section, extra: d.extra, type: meta[d.id].type })) });
    }

    if (route === 'file' && m === 'GET') {
      const p = verify(bearer(req, url), ['viewer']);
      if (!p) return new Response('This link has expired. Go back to emilylam.hk and unlock again.', { status: 401 });
      const doc = (await getDocs()).find((d) => d.id === url.searchParams.get('id'));
      if (!doc || !allowed(p, doc)) return new Response('Not found', { status: 404 });
      const meta = (await getJSON('docs-meta', {}))[doc.id];
      if (!meta) return new Response('Not found', { status: 404 });
      if (meta.type === 'link') return Response.redirect(meta.link, 302);
      const data = await db().get('doc-file/' + doc.id, { type: 'arrayBuffer' });
      if (!data) return new Response('Not found', { status: 404 });
      return new Response(data, { headers: {
        'content-type': meta.contentType || 'application/octet-stream',
        'content-disposition': `inline; filename="${(meta.filename || doc.id).replace(/["\\\r\n]/g, '')}"`,
        'cache-control': 'private, no-store',
      } });
    }

    if (route === 'request' && m === 'POST') {
      const b = await body(req);
      if (b.bot) return json({ ok: true });
      const name = clean(b.name, 120), email = clean(b.email, 200).toLowerCase();
      const docs = await getDocs();
      const items = (Array.isArray(b.documents) ? b.documents : []).map(String).filter((k) =>
        (k.startsWith('doc:') && docs.some((d) => d.id === k.slice(4))) || (k.startsWith('sec:') && SECTIONS.includes(k.slice(4))));
      if (!name || !EMAIL_RE.test(email) || !items.length) return fail('bad_request');
      if (await limited('req-ip:' + ip, 6, 3600)) return fail('too_many', 429);
      const label = (k) => k.startsWith('doc:') ? (docs.find((d) => d.id === k.slice(4))?.name || k) : ({ portfolio: 'Portfolio', certs: 'Certificates & prizes', books: 'Books', projects: 'Science projects', main: 'Documents' })[k.slice(4)];
      const r = { id: newId(), name, email, organisation: clean(b.organisation, 160), items, documents: items.map(label),
        language: clean(b.language, 10), created: new Date().toISOString(), state: 'pending' };
      const reqs = await getJSON('requests', []); reqs.unshift(r); await setJSON('requests', reqs.slice(0, 500));
      const owner = env('OWNER_EMAIL');
      if (owner) {
        try { await sendMail(owner, `Document request from ${name}`, `${name}${r.organisation ? ' (' + r.organisation + ')' : ''} <${email}> would like:\n- ${r.documents.join('\n- ')}\n\nApprove or decline: ${site()}/admin.html`); }
        catch (err) { console.error(err); }
      }
      return json({ ok: true });
    }

    /* ----- admin ----- */
    if (route === 'admin/login' && m === 'POST') {
      const pw = env('ADMIN_PASSWORD');
      if (!pw) throw new SetupError('ADMIN_PASSWORD');
      if (await limited('admin-ip:' + ip, 8, 900)) return fail('too_many', 429);
      const { password } = await body(req);
      if (!safeEqual(sha(String(password || '')), sha(pw))) return fail('bad_password', 401);
      return json({ token: sign({ role: 'admin' }, 7 * 24 * 3600) });
    }

    if (route.startsWith('admin/')) {
      if (!verify(bearer(req, url), ['admin'])) return fail('signed_out', 401);

      if (route === 'admin/state' && m === 'GET') {
        const [st, posts, requests, links, docs, meta, pw] = await Promise.all([getJSON('status', { status: 'free' }), getJSON('posts', []),
          getJSON('requests', []), getLinks(), getDocs(), getJSON('docs-meta', {}), getJSON('docs-password', {})]);
        return json({ status: st.status, posts, requests, links, docs, meta, hasPassword: !!pw.hash,
          mailReady: !!(env('RESEND_API_KEY') && env('MAIL_FROM')), icons: ICONS, sections: SECTIONS });
      }
      if (route === 'admin/status' && m === 'POST') {
        const { status } = await body(req);
        if (!STATUSES.includes(status)) return fail('bad_request');
        await setJSON('status', { status }); return json({ ok: true });
      }

      /* photos (Log posts and link logos) */
      if (route === 'admin/photo' && m === 'POST') {
        const { data } = await body(req);
        const raw = Buffer.from(String(data || ''), 'base64');
        if (!raw.length) return fail('bad_request');
        if (raw.length > MAX_PHOTO) return fail('too_big', 413);
        const img = stripImage(raw);
        if (!img) return fail('bad_image');
        const id = newId();
        await db().set('photo/' + id, toAB(img.data), { metadata: { type: img.type } });
        return json({ id });
      }

      /* posts */
      if (route === 'admin/post' && m === 'POST') {
        const b = await body(req);
        const title = clean(b.title, 160), text = clean(b.text, 8000);
        const date = /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : new Date().toISOString().slice(0, 10);
        const photos = (Array.isArray(b.photos) ? b.photos : []).filter((x) => /^[A-Za-z0-9_-]{6,40}$/.test(x)).slice(0, 8);
        if (!title && !text && !photos.length) return fail('bad_request');
        const posts = await getJSON('posts', []);
        if (b.id) {
          const p = posts.find((x) => x.id === b.id); if (!p) return fail('bad_request');
          await deletePhotos((p.photos || []).filter((x) => !photos.includes(x)));
          Object.assign(p, { title, text, date, photos, edited: new Date().toISOString() });
        } else posts.unshift({ id: newId(), date, title, text, photos });
        posts.sort((a, z) => (a.date < z.date ? 1 : a.date > z.date ? -1 : 0));
        await setJSON('posts', posts); return json({ ok: true });
      }
      if (route === 'admin/post' && m === 'DELETE') {
        const id = url.searchParams.get('id'); const posts = await getJSON('posts', []);
        const p = posts.find((x) => x.id === id); if (p) await deletePhotos(p.photos);
        await setJSON('posts', posts.filter((x) => x.id !== id)); return json({ ok: true });
      }

      /* links */
      if (route === 'admin/links' && m === 'POST') {
        const { links } = await body(req);
        if (!Array.isArray(links) || links.length > 20) return fail('bad_request');
        const old = await getLinks();
        const out = [];
        for (const l of links) {
          const u = clean(l.url, 500);
          if (!/^(https:\/\/|mailto:)\S+$/.test(u) || !clean(l.label, 60)) return fail('bad_link');
          out.push({ id: /^[A-Za-z0-9_-]{1,40}$/.test(l.id || '') ? l.id : newId(), label: clean(l.label, 60), url: u, note: clean(l.note, 80),
            color: /^#[0-9a-fA-F]{6}$/.test(l.color || '') ? l.color : '#3B6D11', icon: ICONS.includes(l.icon) ? l.icon : 'link',
            logo: /^[A-Za-z0-9_-]{6,40}$/.test(l.logo || '') ? l.logo : undefined });
        }
        const keep = new Set(out.map((l) => l.logo).filter(Boolean));
        await deletePhotos(old.map((l) => l.logo).filter((x) => x && !keep.has(x)));
        await setJSON('links', out); return json({ ok: true, links: out });
      }

      /* documents */
      if (route === 'admin/docs' && m === 'POST') {
        const { docs } = await body(req);
        if (!Array.isArray(docs) || docs.length > 120) return fail('bad_request');
        const out = []; const seen = new Set();
        for (const d of docs) {
          const id = ID_RE.test(d.id || '') ? d.id : 'doc-' + crypto.randomBytes(5).toString('hex');
          if (seen.has(id) || !clean(d.name, 160) || !SECTIONS.includes(d.section)) return fail('bad_request');
          seen.add(id); out.push({ id, name: clean(d.name, 160), section: d.section, ...(clean(d.extra, 20) ? { extra: clean(d.extra, 20) } : {}) });
        }
        const old = await getDocs(); const meta = await getJSON('docs-meta', {});
        for (const d of old) if (!seen.has(d.id)) { delete meta[d.id]; await db().delete('doc-file/' + d.id); }
        await setJSON('docs-meta', meta); await setJSON('docs', out); return json({ ok: true, docs: out });
      }
      if (route === 'admin/password' && m === 'POST') {
        const { password } = await body(req);
        const pw = String(password || '');
        if (pw.length < 6) return fail('too_short');
        await setJSON('docs-password', { hash: hashPw(pw), updated: new Date().toISOString() }); return json({ ok: true });
      }
      if (route === 'admin/doc-link' && m === 'POST') {
        const { id, link } = await body(req);
        if (!(await getDocs()).some((d) => d.id === id) || !/^https:\/\/\S+$/.test(String(link || ''))) return fail('bad_request');
        const meta = await getJSON('docs-meta', {});
        meta[id] = { type: 'link', link: String(link), updated: new Date().toISOString() };
        await db().delete('doc-file/' + id); await setJSON('docs-meta', meta); return json({ ok: true });
      }
      if (route === 'admin/doc-file' && m === 'POST') {
        const { id, filename, contentType, data } = await body(req);
        if (!(await getDocs()).some((d) => d.id === id) || !data) return fail('bad_request');
        let buf = Buffer.from(String(data), 'base64');
        if (buf.length > MAX_FILE) return fail('too_big', 413);
        const img = /^image\/(jpeg|png)$/.test(contentType || '') ? stripImage(buf) : null;
        if (img) buf = img.data;
        await db().set('doc-file/' + id, toAB(buf));
        const meta = await getJSON('docs-meta', {});
        meta[id] = { type: 'file', filename: clean(filename, 160) || id, contentType: clean(contentType, 100) || 'application/octet-stream', size: buf.length, updated: new Date().toISOString() };
        await setJSON('docs-meta', meta); return json({ ok: true });
      }
      if (route === 'admin/doc' && m === 'DELETE') {
        const id = url.searchParams.get('id');
        const meta = await getJSON('docs-meta', {}); delete meta[id];
        await db().delete('doc-file/' + id); await setJSON('docs-meta', meta); return json({ ok: true });
      }

      /* requests */
      if (route === 'admin/request' && m === 'POST') {
        const { id, action } = await body(req);
        const reqs = await getJSON('requests', []);
        const r = reqs.find((x) => x.id === id);
        if (!r || !['approve', 'decline'].includes(action)) return fail('bad_request');
        if (action === 'approve') {
          const items = r.items || [];
          const grant = { role: 'viewer', email: r.email,
            docs: items.filter((k) => k.startsWith('doc:')).map((k) => k.slice(4)),
            sections: items.filter((k) => k.startsWith('sec:')).map((k) => k.slice(4)) };
          const link = `${site()}/#unlock?grant=${sign(grant, 14 * 24 * 3600)}`;
          try {
            await sendMail(r.email, 'Emily shared her documents with you',
              `Hi ${r.name},\n\nEmily approved your request for: ${r.documents.join(', ')}.\n\nOpen them here (the link works for 14 days):\n${link}\n\nEmily Lam\nemilylam.hk`);
          } catch (err) { if (err instanceof SetupError) throw err; console.error(err); return fail('send_failed', 502); }
          r.state = 'approved';
        } else r.state = 'declined';
        r.decided = new Date().toISOString();
        await setJSON('requests', reqs); return json({ ok: true });
      }
    }
    return fail('not_found', 404);
  } catch (err) {
    if (err instanceof SetupError) { console.error('Missing setting:', err.message); return json({ error: 'setup', missing: err.message }, 500); }
    if (err && err.status === 413) return fail('too_big', 413);
    console.error(err); return fail('server', 500);
  }
};
