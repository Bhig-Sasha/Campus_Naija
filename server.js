const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

/* ============================================================
 * ONE-TIME MIGRATION (run these SQL statements once after deploy)
 * ------------------------------------------------------------
 * All existing rep content that was stuck in 'draft' or 'pending'
 * needs to be flipped to 'published' because the review queue is
 * gone. This is safe to run repeatedly — it only touches rows that
 * are still in the old states.
 *
 *   update public.courses            set status='published', updated_at=now() where status in ('draft','pending');
 *   update public.fee_records        set status='published', updated_at=now() where status in ('draft','pending');
 *   update public.admission_notices  set status='published', updated_at=now() where status in ('draft','pending');
 *   update public.academic_events    set status='published', updated_at=now() where status in ('draft','pending');
 *
 * The review_comments table is retained — it now holds the admin's
 * "sent back" notes for the rep to read.
 * ============================================================ */

/* ============================================================
 * CONFIG
 * ============================================================ */
const PORT = Number(process.env.PORT) || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const OWNER_EMAIL = process.env.OWNER_EMAIL || 'owner@campusnaija.ng';
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '';
const FORCE_PASSWORD_CHANGE = process.env.FORCE_PASSWORD_CHANGE === '1';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MEDIA_BUCKET = 'media';

if (!DATABASE_URL) { console.error('[env] DATABASE_URL is required'); process.exit(1); }
if (!JWT_SECRET)   { console.error('[env] JWT_SECRET is required');   process.exit(1); }
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('[env] SUPABASE_URL and SUPABASE_SERVICE_KEY are required for media uploads');
  process.exit(1);
}

/* ============================================================
 * PLACEMENT REGISTRY
 * ============================================================ */
const PLACEMENT_PAGES = ['home', 'schools', 'admissions', 'exams', 'scholarships', 'trending'];

const PLACEMENT_SLOTS = {
  home:         ['hero', 'featured_school', 'featured_story'],
  schools:      ['school_cover', 'school_logo'],
  admissions:   ['featured_banner'],
  exams:        ['featured_banner'],
  scholarships: ['featured_banner'],
  trending:     ['article_cover'],
};

const PLACEMENTS_REQUIRING_REF = new Set([
  'schools:school_cover',
  'schools:school_logo',
  'trending:article_cover',
  'home:featured_school',
  'home:featured_story',
]);

function isValidPlacement(page, slot) {
  return PLACEMENT_PAGES.includes(page)
    && Array.isArray(PLACEMENT_SLOTS[page])
    && PLACEMENT_SLOTS[page].includes(slot);
}

function placementNeedsRef(page, slot) {
  return PLACEMENTS_REQUIRING_REF.has(`${page}:${slot}`);
}

/* ============================================================
 * SUPABASE CLIENT
 * ============================================================ */
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

/* ============================================================
 * DATABASE
 * ============================================================ */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});
pool.on('error', (err) => console.error('[pg]', err.message));

async function q(text, params) { return pool.query(text, params || []); }
async function one(text, params) { const r = await q(text, params); return r.rows[0] || null; }
async function many(text, params) { const r = await q(text, params); return r.rows; }
async function run(text, params) { const r = await q(text, params); return r.rowCount; }

function idsEqual(a, b) {
  if (a == null || b == null) return false;
  return String(a) === String(b);
}

/* ============================================================
 * SEED
 * ============================================================ */
async function seed() {
  try {
    const settingsCount = (await one('select count(*)::int as c from public.settings')).c;
    if (settingsCount === 0) {
      const defaults = {
        site_name: 'CampusNaija',
        site_tagline: 'Your education. Your next move.',
        admin_email: OWNER_EMAIL,
        site_description: "Nigeria's education discovery platform.",
        require_review: '1',
        require_verification_for_fees: '1',
        auto_archive_expired: '1',
        single_session: '1',
        lockout_attempts: '5',
        session_timeout: '30',
      };
      for (const [k, v] of Object.entries(defaults)) {
        await run('insert into public.settings (key, value) values ($1,$2) on conflict (key) do nothing', [k, v]);
      }
    }

    const usersCount = (await one('select count(*)::int as c from public.users')).c;
    if (usersCount === 0 && OWNER_PASSWORD) {
      const hash = bcrypt.hashSync(OWNER_PASSWORD, 10);
      await run(
        `insert into public.users (name, email, password_hash, role, status, must_change_password)
         values ($1,$2,$3,'owner','active',$4)`,
        ['Platform Owner', OWNER_EMAIL, hash, FORCE_PASSWORD_CHANGE]
      );
      console.log(`[seed] Created owner account: ${OWNER_EMAIL}`);
    }
  } catch (e) {
    console.error('[seed]', e.message);
  }
}

/* ============================================================
 * APP
 * ============================================================ */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false,
}));
app.use(cors({
  origin: ALLOWED_ORIGINS.includes('*') ? true : ALLOWED_ORIGINS,
  credentials: true,
}));
app.use(express.json({ limit: '2mb' }));
app.use(morgan('tiny'));

/* ============================================================
 * HELPERS
 * ============================================================ */
const now = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const slugify = (t) => String(t).toLowerCase().trim()
  .replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-');

function httpError(status, message, code) {
  const err = new Error(message); err.status = status; err.code = code; return err;
}
function asyncH(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

async function audit(req, action, targetType, targetId, targetLabel, details) {
  try {
    const u = req.user;
    await run(
      `insert into public.audit_logs
        (actor_id, actor_name, actor_role, action, target_type, target_id, target_label, details, ip)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        u ? u.id : null, u ? u.name : 'Unknown', u ? u.role : 'security',
        action, targetType,
        targetId != null ? String(targetId) : null,
        targetLabel || null,
        details ? JSON.stringify(details) : null,
        (req.ip || '').toString(),
      ]
    );
  } catch (e) { console.error('[audit]', e.message); }
}

async function readSettings() {
  const rows = await many('select key, value from public.settings');
  const out = {}; for (const r of rows) out[r.key] = r.value; return out;
}

async function notify(userId, schoolId, title, body, link) {
  try {
    await run(
      `insert into public.notifications (user_id, school_id, title, body, link)
       values ($1,$2,$3,$4,$5)`,
      [userId || null, schoolId || null, title, body || null, link || null]
    );
  } catch (e) { console.error('[notify]', e.message); }
}

/**
 * notifySchoolManagers
 * --------------------
 * Sends an in-app notification to every school_manager for a school.
 * Used by the admin "send-back" flow.
 */
async function notifySchoolManagers(schoolId, title, body, link) {
  try {
    const managers = await many(
      `select id from public.users where role='school_manager' and school_id=$1`,
      [schoolId]
    );
    for (const m of managers) {
      await notify(m.id, schoolId, title, body, link);
    }
  } catch (e) { console.error('[notifySchoolManagers]', e.message); }
}

/* ============================================================
 * AUTH
 * ============================================================ */
const loginAttempts = new Map();
function rateLimit(key, max, windowMs) {
  const t = Date.now();
  const rec = loginAttempts.get(key) || { count: 0, reset: t + windowMs };
  if (t > rec.reset) { rec.count = 0; rec.reset = t + windowMs; }
  rec.count += 1; loginAttempts.set(key, rec);
  return rec.count <= max;
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, school_id: user.school_id || null },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, name: u.name, email: u.email, role: u.role,
    school_id: u.school_id ?? null,
    school_name: u.school_name ?? null,
    school_slug: u.school_slug ?? null,
    status: u.status,
    must_change_password: !!u.must_change_password,
    notes: u.notes, created_at: u.created_at, updated_at: u.updated_at,
  };
}

async function fetchUserWithSchool(userId) {
  return one(
    `select u.*, s.name as school_name, s.slug as school_slug
       from public.users u
       left join public.schools s on s.id = u.school_id
      where u.id = $1`,
    [userId]
  );
}

async function authenticate(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) throw httpError(401, 'Authentication required.', 'no_token');
    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); }
    catch { throw httpError(401, 'Session expired or invalid token.', 'bad_token'); }
    const user = await fetchUserWithSchool(payload.sub);
    if (!user) throw httpError(401, 'Account no longer exists.', 'no_user');
    if (user.status === 'suspended') throw httpError(403, 'This account is suspended.', 'suspended');
    if (user.status === 'pending') throw httpError(403, 'This account is pending approval.', 'pending_approval');
    req.user = user;
    next();
  } catch (e) { next(e); }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return next(httpError(401, 'Authentication required.'));
    if (!roles.includes(req.user.role)) return next(httpError(403, 'Forbidden.', 'forbidden'));
    next();
  };
}

function assertSchoolScope(user, schoolId) {
  if (!user) throw httpError(401, 'Authentication required.');
  if (user.role === 'school_manager') {
    if (!user.school_id || !idsEqual(user.school_id, schoolId)) {
      throw httpError(403, 'You can only manage your assigned institution.', 'school_scope');
    }
  }
}

function scopedSchoolFilter(user, requested) {
  if (user.role === 'school_manager') return { school_id: user.school_id, forced: true };
  return { school_id: requested || null, forced: false };
}

/* ============================================================
 * ROUTES
 * ============================================================ */
const router = express.Router();
app.use('/api', router);

/* ---------- AUTH ---------- */
router.get('/auth/config', asyncH(async (req, res) => {
  const s = await readSettings();
  res.json({
    site_name: s.site_name,
    site_tagline: s.site_tagline,
    require_review: s.require_review === '1',
    require_verification_for_fees: s.require_verification_for_fees === '1',
    allowed_roles: ['owner','admin','editor','reviewer','school_manager'],
  });
}));

router.post('/auth/login', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit(`login:${ip}`, 8, 15 * 60 * 1000))
    throw httpError(429, 'Too many sign-in attempts. Try again later.', 'rate_limited');

  const { identifier, password } = req.body || {};
  if (!identifier || !password) throw httpError(400, 'Email/username and password are required.');

  const user = await one('select * from public.users where lower(email) = lower($1)', [identifier]);
  const invalid = httpError(401, 'Invalid credentials, or this account is not approved for sign-in.');
  if (!user) throw invalid;
  if (!bcrypt.compareSync(password, user.password_hash)) throw invalid;
  if (user.status === 'suspended') throw httpError(403, 'This account is suspended. Contact the platform owner.');
  if (user.status === 'pending') throw httpError(403, 'This account is awaiting approval. Contact the platform owner.');

  const fullUser = await fetchUserWithSchool(user.id);

  if (fullUser.role === 'school_manager' && !fullUser.school_id) {
    console.warn(`[auth] school_manager ${fullUser.email} (id=${fullUser.id}) has NO school_id assigned — dashboard will show "Unassigned".`);
  }
  if (fullUser.role === 'school_manager' && fullUser.school_id && !fullUser.school_name) {
    console.warn(`[auth] school_manager ${fullUser.email} (id=${fullUser.id}) has school_id=${fullUser.school_id} but no matching school row — orphaned reference.`);
  }

  const token = signToken(fullUser);
  await audit({ user: fullUser, ip }, 'login', 'auth', fullUser.id, fullUser.email);
  res.json({ token, user: publicUser(fullUser) });
}));

router.post('/auth/refresh', authenticate, asyncH(async (req, res) => {
  res.json({ token: signToken(req.user), user: publicUser(req.user) });
}));

router.get('/auth/me', authenticate, asyncH(async (req, res) => {
  res.json({ user: publicUser(req.user) });
}));

router.post('/auth/logout', authenticate, asyncH(async (req, res) => {
  await audit(req, 'logout', 'auth', req.user.id, req.user.email);
  res.json({ ok: true });
}));

router.post('/auth/change-password', authenticate, asyncH(async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password)
    throw httpError(400, 'current_password and new_password are required.');
  if (String(new_password).length < 8)
    throw httpError(400, 'New password must be at least 8 characters.');
  const user = await one('select * from public.users where id = $1', [req.user.id]);
  if (!bcrypt.compareSync(current_password, user.password_hash))
    throw httpError(400, 'Current password is incorrect.');
  const hash = bcrypt.hashSync(new_password, 10);
  await run(
    `update public.users set password_hash=$1, must_change_password=false, updated_at=now() where id=$2`,
    [hash, user.id]
  );
  await audit(req, 'change_password', 'user', user.id, user.email);
  res.json({ ok: true });
}));

router.post('/auth/forgot-password', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit(`forgot:${ip}`, 4, 15 * 60 * 1000))
    throw httpError(429, 'Too many reset requests. Try again later.', 'rate_limited');
  const { email } = req.body || {};
  if (!email) throw httpError(400, 'email is required.');
  await audit({ user: null, ip }, 'forgot_password', 'auth', null, email);
  res.json({ ok: true, message: 'If an approved account exists for that email, a reset link will be sent.' });
}));

/* ---------- PUBLIC (no auth) ---------- */
router.get('/public/schools', asyncH(async (req, res) => {
  const { q: query, state, type } = req.query;
  const clauses = ["publication = 'published'"]; const params = [];
  if (query) { params.push(`%${query}%`, `%${query}%`); clauses.push(`(name ilike $${params.length-1} or city ilike $${params.length})`); }
  if (state) { params.push(state); clauses.push(`state = $${params.length}`); }
  if (type) { params.push(type); clauses.push(`type = $${params.length}`); }
  const rows = await many(`select * from public.schools where ${clauses.join(' and ')} order by name`, params);
  res.json({ schools: rows });
}));

router.get('/public/schools/:slug', asyncH(async (req, res) => {
  const school = await one(`select * from public.schools where slug=$1 and publication='published'`, [req.params.slug]);
  if (!school) throw httpError(404, 'School not found.');
  const [courses, fees, admissions, calendar] = await Promise.all([
    many(`select * from public.courses where school_id=$1 and status='published'`, [school.id]),
    many(`select * from public.fee_records where school_id=$1 and status='published'`, [school.id]),
    many(`select * from public.admission_notices where school_id=$1 and status='published'`, [school.id]),
    many(`select * from public.academic_events where school_id=$1 and status='published'`, [school.id]),
  ]);
  res.json({ school, courses, fees, admissions, calendar });
}));

router.get('/public/admissions', asyncH(async (req, res) => {
  const rows = await many(`
    select a.*, s.name as school_name, s.slug as school_slug
    from public.admission_notices a join public.schools s on s.id = a.school_id
    where a.status = 'published' order by a.created_at desc`);
  res.json({ admissions: rows });
}));

router.get('/public/exams', asyncH(async (req, res) => {
  res.json({ exams: await many(`select * from public.exams where status='published' order by created_at desc`) });
}));
router.get('/public/exams/:id', asyncH(async (req, res) => {
  const row = await one(`select * from public.exams where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  res.json({ exam: row });
}));

router.get('/public/scholarships', asyncH(async (req, res) => {
  res.json({ scholarships: await many(`select * from public.scholarships where status='published' order by created_at desc`) });
}));
router.get('/public/scholarships/:id', asyncH(async (req, res) => {
  const row = await one(`select * from public.scholarships where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  res.json({ scholarship: row });
}));

router.get('/public/trending', asyncH(async (req, res) => {
  res.json({ stories: await many(`select * from public.trending where status='published' order by featured desc, created_at desc`) });
}));
router.get('/public/trending/:id', asyncH(async (req, res) => {
  const row = await one(`select * from public.trending where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  res.json({ story: row });
}));

router.get('/public/settings', asyncH(async (req, res) => {
  const s = await readSettings();
  res.json({ site_name: s.site_name, site_tagline: s.site_tagline, site_description: s.site_description });
}));

router.get('/public/placements', asyncH(async (req, res) => {
  const { page, slot, content_ref } = req.query;
  const clauses = ['p.is_active = true'];
  const params = [];

  if (page) { params.push(page); clauses.push(`p.page = $${params.length}`); }
  if (slot) { params.push(slot); clauses.push(`p.slot = $${params.length}`); }

  if (content_ref !== undefined) {
    if (content_ref === '' || content_ref === 'null') {
      clauses.push('p.content_ref IS NULL');
    } else {
      params.push(String(content_ref));
      clauses.push(`p.content_ref = $${params.length}`);
    }
  }

  const rows = await many(
    `select p.id, p.page, p.slot, p.content_ref, p.media_id, p.is_active,
            p.created_at, p.updated_at,
            m.public_url, m.alt_text, m.caption, m.display_name
       from public.media_placements p
       left join public.media_assets m on m.id = p.media_id
      where ${clauses.join(' and ')}
      order by p.updated_at desc`,
    params
  );

  res.json({ placements: rows });
}));

/* ---------- SCHOOLS ---------- */
router.get('/schools', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const { q: query, type, state, publication } = req.query;
  const clauses = []; const params = [];
  if (query) { params.push(`%${query}%`, `%${query}%`); clauses.push(`(name ilike $${params.length-1} or city ilike $${params.length})`); }
  if (type) { params.push(type); clauses.push(`type = $${params.length}`); }
  if (state) { params.push(state); clauses.push(`state = $${params.length}`); }
  if (publication) { params.push(publication); clauses.push(`publication = $${params.length}`); }
  const rows = await many(`select * from public.schools ${clauses.length ? 'where ' + clauses.join(' and ') : ''} order by name`, params);
  res.json({ schools: rows });
}));

router.get('/schools/:id', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  const school = await one('select * from public.schools where id=$1', [req.params.id]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  res.json({ school });
}));

router.get('/schools/:id/summary', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  const id = req.params.id;
  const school = await one('select * from public.schools where id=$1', [id]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, id);
  const num = async (sql) => Number((await one(sql, [id])).c);
  const counts = {
    courses: await num('select count(*)::int as c from public.courses where school_id=$1'),
    courses_sent_back: await num(`select count(*)::int as c from public.courses c where c.school_id=$1 and c.status='draft' and exists (select 1 from public.review_comments r where r.submission_type='course' and r.submission_target_id=c.id)`),
    fees: await num('select count(*)::int as c from public.fee_records where school_id=$1'),
    fees_sent_back: await num(`select count(*)::int as c from public.fee_records f where f.school_id=$1 and f.status='draft' and exists (select 1 from public.review_comments r where r.submission_type='fee' and r.submission_target_id=f.id)`),
    admissions: await num('select count(*)::int as c from public.admission_notices where school_id=$1'),
    admissions_sent_back: await num(`select count(*)::int as c from public.admission_notices a where a.school_id=$1 and a.status='draft' and exists (select 1 from public.review_comments r where r.submission_type='admission' and r.submission_target_id=a.id)`),
    calendar: await num('select count(*)::int as c from public.academic_events where school_id=$1'),
    calendar_sent_back: await num(`select count(*)::int as c from public.academic_events e where e.school_id=$1 and e.status='draft' and exists (select 1 from public.review_comments r where r.submission_type='calendar' and r.submission_target_id=e.id)`),
    media: await num('select count(*)::int as c from public.media_assets where school_id=$1'),
  };
  res.json({ school, counts });
}));

router.post('/schools', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.type || !b.ownership) throw httpError(400, 'name, type and ownership are required.');
  let slug = slugify(b.name);
  if (await one('select 1 from public.schools where slug=$1', [slug]))
    slug += '-' + Date.now().toString(36);
  const school = await one(
    `insert into public.schools
       (name, slug, type, ownership, state, city, address, website, email, description, established,
        verification, publication)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'verified','published') returning *`,
    [b.name, slug, b.type, b.ownership, b.state||null, b.city||null, b.address||null,
     b.website||null, b.email||null, b.description||null, b.established||null]
  );
  await audit(req, 'create', 'school', school.id, school.name);
  res.status(201).json({ school });
}));

router.patch('/schools/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const school = await one('select * from public.schools where id=$1', [req.params.id]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  const allowed = ['name','type','ownership','state','city','address','website','email','description','established','logo_media_id','cover_media_id'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if (!Object.keys(updates).length) throw httpError(400, 'No editable fields provided.');
  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(school.id);
  const updated = await one(
    `update public.schools set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'school', updated.id, updated.name, { fields: keys });
  res.json({ school: updated });
}));

router.post('/schools/:id/publish', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const school = await one('select * from public.schools where id=$1', [req.params.id]);
  if (!school) throw httpError(404, 'School not found.');
  await run(`update public.schools set publication='published', updated_at=now() where id=$1`, [school.id]);
  await audit(req, 'publish_school', 'school', school.id, school.name);
  res.json({ ok: true });
}));

router.post('/schools/:id/archive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const school = await one('select * from public.schools where id=$1', [req.params.id]);
  if (!school) throw httpError(404, 'School not found.');
  await run(`update public.schools set publication='archived', updated_at=now() where id=$1`, [school.id]);
  await audit(req, 'archive_school', 'school', school.id, school.name);
  res.json({ ok: true });
}));

/* ============================================================
 * CONTENT HELPERS
 * ============================================================ */
const CONTENT_TYPES = {
  course:    { table: 'courses',            labelCol: 'name',                                             schoolIdCol: 'school_id', routeBase: 'courses',    friendly: 'course' },
  fee:       { table: 'fee_records',        labelCol: "('Fee ' || session || ' ' || category)",           schoolIdCol: 'school_id', routeBase: 'fees',       friendly: 'fee record' },
  admission: { table: 'admission_notices',  labelCol: 'title',                                            schoolIdCol: 'school_id', routeBase: 'admissions', friendly: 'admission notice' },
  calendar:  { table: 'academic_events',    labelCol: 'title',                                            schoolIdCol: 'school_id', routeBase: 'calendar',   friendly: 'calendar event' },
};

/**
 * sendBackContent
 * ---------------
 * Admin-only "send back to school" action. Flips status to 'draft',
 * records an audit row and a review_comments entry with the admin's
 * note, and notifies every school_manager for that school.
 * Option A: the record leaves the public site immediately (because
 * the public read endpoints filter status='published').
 */
async function sendBackContent(req, res, type, id) {
  const meta = CONTENT_TYPES[type];
  if (!meta) throw httpError(400, 'Unsupported content type.');

  const row = await one(`select * from public.${meta.table} where id=$1`, [id]);
  if (!row) throw httpError(404, `The ${meta.friendly} was not found.`);
  if (row.status === 'archived')
    throw httpError(400, `This ${meta.friendly} is archived and cannot be sent back.`);
  if (row.status === 'draft')
    throw httpError(400, `This ${meta.friendly} is already in draft.`);

  const comment = (req.body && req.body.comment) ? String(req.body.comment).trim() : '';
  if (!comment) throw httpError(400, 'A note for the school is required when sending back.');

  await run(
    `update public.${meta.table} set status='draft', updated_at=now() where id=$1`,
    [id]
  );

  await run(
    `insert into public.review_comments
       (submission_type, submission_target_id, school_id, reviewer_id, reviewer_name, decision, comment)
     values ($1,$2,$3,$4,$5,'changes_requested',$6)`,
    [type, id, row.school_id, req.user.id, req.user.name, comment]
  );

  const label = await one(`select ${meta.labelCol} as label from public.${meta.table} where id=$1`, [id]);

  await audit(req, 'send_back', type, id, (label && label.label) || `#${id}`, { comment });
  await notifySchoolManagers(
    row.school_id,
    `Your ${meta.friendly} was sent back for changes`,
    comment,
    '/SchoolAd/submissions.html'
  );

  res.json({ ok: true });
}

/**
 * archiveContent
 * --------------
 * Admin-only archive. Terminal for the rep (they can't republish).
 */
async function archiveContent(req, res, type, id) {
  const meta = CONTENT_TYPES[type];
  if (!meta) throw httpError(400, 'Unsupported content type.');
  const row = await one(`select * from public.${meta.table} where id=$1`, [id]);
  if (!row) throw httpError(404, `The ${meta.friendly} was not found.`);
  if (row.status === 'archived') { res.json({ ok: true }); return; }

  await run(
    `update public.${meta.table} set status='archived', updated_at=now() where id=$1`,
    [id]
  );
  const label = await one(`select ${meta.labelCol} as label from public.${meta.table} where id=$1`, [id]);
  await audit(req, 'archive', type, id, (label && label.label) || `#${id}`);
  res.json({ ok: true });
}

/**
 * unarchiveContent
 * ----------------
 * Admin-only un-archive. Restores the record to 'published'.
 */
async function unarchiveContent(req, res, type, id) {
  const meta = CONTENT_TYPES[type];
  if (!meta) throw httpError(400, 'Unsupported content type.');
  const row = await one(`select * from public.${meta.table} where id=$1`, [id]);
  if (!row) throw httpError(404, `The ${meta.friendly} was not found.`);
  if (row.status !== 'archived') throw httpError(400, `This ${meta.friendly} is not archived.`);
  await run(
    `update public.${meta.table} set status='published', updated_at=now() where id=$1`,
    [id]
  );
  const label = await one(`select ${meta.labelCol} as label from public.${meta.table} where id=$1`, [id]);
  await audit(req, 'unarchive', type, id, (label && label.label) || `#${id}`);
  res.json({ ok: true });
}

function assertRepCanEdit(row, friendly) {
  if (row.status === 'archived') {
    throw httpError(403, `This ${friendly} has been archived by the platform administrator and cannot be edited.`);
  }
}

/**
 * getLatestReviewComments
 * -----------------------
 * Fetches the most recent review_comment per record for a set of IDs,
 * keyed by record ID. Used by the four content GET endpoints so each
 * row carries its `review_comment` field for the frontend to render
 * the "Needs fix" tab and inline admin note.
 */
async function getLatestReviewComments(type, ids) {
  if (!Array.isArray(ids) || ids.length === 0) return {};
  const rows = await many(
    `select distinct on (submission_target_id)
            submission_target_id, comment, decision, created_at
       from public.review_comments
      where submission_type = $1
        and submission_target_id = ANY($2::uuid[])
      order by submission_target_id, created_at desc`,
    [type, ids]
  );
  const out = {};
  for (const r of rows) out[r.submission_target_id] = r.comment;
  return out;
}

/* ---------- COURSES ---------- */
router.get('/schools/:schoolId/courses', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  // ── CHANGED ── join latest review comment so the frontend can classify
  // sent_back vs draft.
  const rows = await many(
    `select c.*, rc.comment as review_comment
       from public.courses c
       left join lateral (
         select comment
           from public.review_comments
          where submission_type = 'course'
            and submission_target_id = c.id
          order by created_at desc
          limit 1
       ) rc on true
      where c.school_id = $1
      order by c.name`,
    [req.params.schoolId]
  );
  res.json({ courses: rows });
}));

router.post('/schools/:schoolId/courses', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const schoolId = req.params.schoolId;
  const school = await one('select * from public.schools where id=$1', [schoolId]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  const b = req.body || {};
  if (!b.name) throw httpError(400, 'Course name is required.');
  const course = await one(
    `insert into public.courses (school_id, name, faculty, department, duration, qualification, entry_route, requirements, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,'published') returning *`,
    [schoolId, b.name, b.faculty||null, b.department||null, b.duration||null,
     b.qualification||null, b.entry_route||null, b.requirements||null]
  );
  await audit(req, 'create', 'course', course.id, course.name, { school_id: school.id });
  res.status(201).json({ course });
}));

router.patch('/courses/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const course = await one('select * from public.courses where id=$1', [req.params.id]);
  if (!course) throw httpError(404, 'Course not found.');
  assertSchoolScope(req.user, course.school_id);
  assertRepCanEdit(course, 'course');

  const allowed = ['name','faculty','department','duration','qualification','entry_route','requirements'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  updates.status = 'published';

  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(course.id);
  const updated = await one(
    `update public.courses set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'course', course.id, course.name);
  res.json({ course: updated });
}));

router.delete('/courses/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const course = await one('select * from public.courses where id=$1', [req.params.id]);
  if (!course) throw httpError(404, 'Course not found.');
  assertSchoolScope(req.user, course.school_id);
  await run('delete from public.courses where id=$1', [course.id]);
  await audit(req, 'delete', 'course', course.id, course.name);
  res.json({ ok: true });
}));

router.post('/courses/:id/send-back', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await sendBackContent(req, res, 'course', req.params.id);
}));
router.post('/courses/:id/archive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await archiveContent(req, res, 'course', req.params.id);
}));
router.post('/courses/:id/unarchive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await unarchiveContent(req, res, 'course', req.params.id);
}));

/* ---------- FEES ---------- */
router.get('/schools/:schoolId/fees', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  // ── CHANGED ── join latest review comment.
  const rows = await many(
    `select f.*, rc.comment as review_comment
       from public.fee_records f
       left join lateral (
         select comment
           from public.review_comments
          where submission_type = 'fee'
            and submission_target_id = f.id
          order by created_at desc
          limit 1
       ) rc on true
      where f.school_id = $1
      order by f.created_at desc`,
    [req.params.schoolId]
  );
  res.json({ fees: rows });
}));

router.post('/schools/:schoolId/fees', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const schoolId = req.params.schoolId;
  const school = await one('select * from public.schools where id=$1', [schoolId]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  const b = req.body || {};
  if (!b.session || !b.category || b.amount == null)
    throw httpError(400, 'session, category and amount are required.');
  if (!Number.isFinite(Number(b.amount)) || Number(b.amount) < 0)
    throw httpError(400, 'amount must be a non-negative number.');
  const fee = await one(
    `insert into public.fee_records (school_id, session, category, programme, level, student_category, amount, source_url, verified_date, notes, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'published') returning *`,
    [schoolId, b.session, b.category, b.programme||null, b.level||null, b.student_category||null,
     Number(b.amount), b.source_url||null, b.verified_date||null, b.notes||null]
  );
  await audit(req, 'create', 'fee', fee.id, `${b.session} ${b.category}`, { school_id: school.id });
  res.status(201).json({ fee });
}));

router.patch('/fees/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const fee = await one('select * from public.fee_records where id=$1', [req.params.id]);
  if (!fee) throw httpError(404, 'Fee not found.');
  assertSchoolScope(req.user, fee.school_id);
  assertRepCanEdit(fee, 'fee record');

  const allowed = ['session','category','programme','level','student_category','amount','source_url','verified_date','notes'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if ('amount' in updates && (!Number.isFinite(Number(updates.amount)) || Number(updates.amount) < 0))
    throw httpError(400, 'amount must be a non-negative number.');
  updates.status = 'published';

  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(fee.id);
  const updated = await one(
    `update public.fee_records set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'fee', fee.id, `fee ${fee.id}`);
  res.json({ fee: updated });
}));

router.delete('/fees/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const fee = await one('select * from public.fee_records where id=$1', [req.params.id]);
  if (!fee) throw httpError(404, 'Fee not found.');
  assertSchoolScope(req.user, fee.school_id);
  await run('delete from public.fee_records where id=$1', [fee.id]);
  await audit(req, 'delete', 'fee', fee.id, `fee ${fee.id}`);
  res.json({ ok: true });
}));

router.post('/fees/:id/send-back', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await sendBackContent(req, res, 'fee', req.params.id);
}));
router.post('/fees/:id/archive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await archiveContent(req, res, 'fee', req.params.id);
}));
router.post('/fees/:id/unarchive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await unarchiveContent(req, res, 'fee', req.params.id);
}));

/* ---------- ADMISSIONS ---------- */
router.get('/admissions', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  const scoped = scopedSchoolFilter(req.user, req.query.school_id);
  const clauses = []; const params = [];
  if (scoped.school_id) { params.push(scoped.school_id); clauses.push(`a.school_id = $${params.length}`); }
  if (req.query.status) { params.push(req.query.status); clauses.push(`a.status = $${params.length}`); }
  const sql = `select a.*, s.name as school_name from public.admission_notices a
    join public.schools s on s.id = a.school_id
    ${clauses.length ? 'where ' + clauses.join(' and ') : ''}
    order by a.created_at desc`;
  res.json({ admissions: await many(sql, params) });
}));

router.get('/schools/:schoolId/admissions', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  // ── CHANGED ── join latest review comment.
  const rows = await many(
    `select a.*, rc.comment as review_comment
       from public.admission_notices a
       left join lateral (
         select comment
           from public.review_comments
          where submission_type = 'admission'
            and submission_target_id = a.id
          order by created_at desc
          limit 1
       ) rc on true
      where a.school_id = $1
      order by a.created_at desc`,
    [req.params.schoolId]
  );
  res.json({ admissions: rows });
}));

router.post('/schools/:schoolId/admissions', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const schoolId = req.params.schoolId;
  const school = await one('select * from public.schools where id=$1', [schoolId]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  const b = req.body || {};
  if (!b.title || !b.session || !b.entry_route || !b.application_url || !b.source_url)
    throw httpError(400, 'title, session, entry_route, application_url and source_url are required.');
  if (!/^https?:\/\//i.test(b.application_url)) throw httpError(400, 'application_url must be an http(s) URL.');
  if (!/^https?:\/\//i.test(b.source_url))      throw httpError(400, 'source_url must be an http(s) URL.');
  if (b.open_date && b.close_date && new Date(b.close_date) < new Date(b.open_date))
    throw httpError(400, 'close_date cannot be before open_date.');
  const adm = await one(
    `insert into public.admission_notices
       (school_id, title, session, entry_route, open_date, close_date, extension_note,
        requirements, eligibility, application_url, source_url, notes, status, verification)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'published','unverified') returning *`,
    [schoolId, b.title, b.session, b.entry_route, b.open_date||null, b.close_date||null,
     b.extension_note||null, b.requirements||null, b.eligibility||null,
     b.application_url, b.source_url, b.notes||null]
  );
  await audit(req, 'create', 'admission', adm.id, adm.title, { school_id: school.id });
  res.status(201).json({ admission: adm });
}));

router.patch('/admissions/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const adm = await one('select * from public.admission_notices where id=$1', [req.params.id]);
  if (!adm) throw httpError(404, 'Admission not found.');
  assertSchoolScope(req.user, adm.school_id);
  assertRepCanEdit(adm, 'admission notice');

  const allowed = ['title','session','entry_route','open_date','close_date','extension_note','requirements','eligibility','application_url','source_url','notes'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if ('application_url' in updates && !/^https?:\/\//i.test(updates.application_url))
    throw httpError(400, 'application_url must be an http(s) URL.');
  updates.status = 'published';

  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(adm.id);
  const updated = await one(
    `update public.admission_notices set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'admission', adm.id, adm.title);
  res.json({ admission: updated });
}));

router.delete('/admissions/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const adm = await one('select * from public.admission_notices where id=$1', [req.params.id]);
  if (!adm) throw httpError(404, 'Admission not found.');
  assertSchoolScope(req.user, adm.school_id);
  await run('delete from public.admission_notices where id=$1', [adm.id]);
  await audit(req, 'delete', 'admission', adm.id, adm.title);
  res.json({ ok: true });
}));

router.post('/admissions/:id/verify', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const adm = await one('select * from public.admission_notices where id=$1', [req.params.id]);
  if (!adm) throw httpError(404, 'Admission not found.');
  if (!adm.source_url) throw httpError(400, 'An official source URL is required before verification.');
  await run(`update public.admission_notices set verification='verified', updated_at=now() where id=$1`, [adm.id]);
  await audit(req, 'verify', 'admission', adm.id, adm.title);
  res.json({ ok: true });
}));

router.post('/admissions/:id/send-back', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await sendBackContent(req, res, 'admission', req.params.id);
}));
router.post('/admissions/:id/archive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await archiveContent(req, res, 'admission', req.params.id);
}));
router.post('/admissions/:id/unarchive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await unarchiveContent(req, res, 'admission', req.params.id);
}));

/* ---------- CALENDAR ---------- */
router.get('/schools/:schoolId/calendar', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  // ── CHANGED ── join latest review comment.
  const rows = await many(
    `select e.*, rc.comment as review_comment
       from public.academic_events e
       left join lateral (
         select comment
           from public.review_comments
          where submission_type = 'calendar'
            and submission_target_id = e.id
          order by created_at desc
          limit 1
       ) rc on true
      where e.school_id = $1
      order by e.start_date`,
    [req.params.schoolId]
  );
  res.json({ events: rows });
}));

router.get('/schools/:schoolId/events', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  // ── CHANGED ── same join, same shape (this is a legacy alias for /calendar).
  const rows = await many(
    `select e.*, rc.comment as review_comment
       from public.academic_events e
       left join lateral (
         select comment
           from public.review_comments
          where submission_type = 'calendar'
            and submission_target_id = e.id
          order by created_at desc
          limit 1
       ) rc on true
      where e.school_id = $1
      order by e.start_date`,
    [req.params.schoolId]
  );
  res.json({ events: rows });
}));

router.post('/schools/:schoolId/calendar', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const schoolId = req.params.schoolId;
  const school = await one('select * from public.schools where id=$1', [schoolId]);
  if (!school) throw httpError(404, 'School not found.');
  assertSchoolScope(req.user, school.id);
  const b = req.body || {};
  if (!b.title || !b.type || !b.session || !b.start_date || !b.source_url)
    throw httpError(400, 'title, type, session, start_date and source_url are required.');
  if (b.end_date && new Date(b.end_date) < new Date(b.start_date))
    throw httpError(400, 'end_date cannot be before start_date.');
  if (!/^https?:\/\//i.test(b.source_url)) throw httpError(400, 'source_url must be an http(s) URL.');
  const ev = await one(
    `insert into public.academic_events
       (school_id, title, type, session, semester, start_date, end_date, notes, source_url, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'published') returning *`,
    [schoolId, b.title, b.type, b.session, b.semester||null, b.start_date,
     b.end_date||null, b.notes||null, b.source_url]
  );
  await audit(req, 'create', 'calendar', ev.id, ev.title, { school_id: school.id });
  res.status(201).json({ event: ev });
}));

router.patch('/calendar/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const ev = await one('select * from public.academic_events where id=$1', [req.params.id]);
  if (!ev) throw httpError(404, 'Event not found.');
  assertSchoolScope(req.user, ev.school_id);
  assertRepCanEdit(ev, 'calendar event');

  const allowed = ['title','type','session','semester','start_date','end_date','notes','source_url'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  updates.status = 'published';

  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(ev.id);
  const updated = await one(
    `update public.academic_events set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'calendar', ev.id, ev.title);
  res.json({ event: updated });
}));

router.delete('/calendar/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const ev = await one('select * from public.academic_events where id=$1', [req.params.id]);
  if (!ev) throw httpError(404, 'Event not found.');
  assertSchoolScope(req.user, ev.school_id);
  await run('delete from public.academic_events where id=$1', [ev.id]);
  await audit(req, 'delete', 'calendar', ev.id, ev.title);
  res.json({ ok: true });
}));

router.post('/calendar/:id/send-back', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await sendBackContent(req, res, 'calendar', req.params.id);
}));
router.post('/calendar/:id/archive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await archiveContent(req, res, 'calendar', req.params.id);
}));
router.post('/calendar/:id/unarchive', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  await unarchiveContent(req, res, 'calendar', req.params.id);
}));

/* ---------- EXAMS / SCHOLARSHIPS / TRENDING ---------- */
router.get('/exams', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  res.json({ exams: await many('select * from public.exams order by created_at desc') });
}));

router.post('/exams', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.body || !b.type || !b.session || !b.website)
    throw httpError(400, 'title, body, type, session and website are required.');
  if (!/^https?:\/\//i.test(b.website)) throw httpError(400, 'website must be an http(s) URL.');
  const row = await one(
    `insert into public.exams
       (title, body, type, session, description, eligibility, instructions, open_date, close_date,
        timetable_info, timetable_url, resources, resource_links, website, source_url, status, verification)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'draft','unverified') returning *`,
    [b.title, b.body, b.type, b.session, b.description||null, b.eligibility||null,
     b.instructions||null, b.open_date||null, b.close_date||null,
     b.timetable_info||null, b.timetable_url||null, b.resources||null,
     b.resource_links||null, b.website, b.source_url||null]
  );
  await audit(req, 'create', 'exam', row.id, row.title);
  res.status(201).json({ exam: row });
}));

router.patch('/exams/:id', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const row = await one('select * from public.exams where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  const allowed = ['title','body','type','session','description','eligibility','instructions','open_date','close_date','timetable_info','timetable_url','resources','resource_links','website','source_url','status'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(row.id);
  const updated = await one(
    `update public.exams set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'exam', row.id, row.title);
  res.json({ exam: updated });
}));

router.delete('/exams/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.exams where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  await run('delete from public.exams where id=$1', [row.id]);
  await audit(req, 'delete', 'exam', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/exams/:id/verify', authenticate, requireRole('owner','admin','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.exams where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
  await run(`update public.exams set verification='verified', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'verify', 'exam', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/exams/:id/publish', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.exams where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  if (row.verification !== 'verified')
    throw httpError(400, 'Exam must be verified before it can be published.');
  await run(`update public.exams set status='published', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'publish', 'exam', row.id, row.title);
  res.json({ ok: true });
}));

router.get('/scholarships', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  res.json({ scholarships: await many('select * from public.scholarships order by created_at desc') });
}));

router.post('/scholarships', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.sponsor || !b.category || !b.level || !b.apply_url)
    throw httpError(400, 'title, sponsor, category, level and apply_url are required.');
  if (!/^https?:\/\//i.test(b.apply_url)) throw httpError(400, 'apply_url must be an http(s) URL.');
  const row = await one(
    `insert into public.scholarships
       (title, sponsor, sponsor_type, category, level, location, deadline, eligibility,
        coverage, amount, currency, frequency, covered, not_covered, nationality, academic,
        documents, steps, contact, open_date, close_date, extension, apply_url, source_url,
        verification, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,'unverified','draft')
     returning *`,
    [b.title, b.sponsor, b.sponsor_type||null, b.category, b.level, b.location||null,
     b.deadline||null, b.eligibility||null, b.coverage||null, b.amount||null,
     b.currency||null, b.frequency||null, b.covered||null, b.not_covered||null,
     b.nationality||null, b.academic||null, b.documents||null, b.steps||null,
     b.contact||null, b.open_date||null, b.close_date||null, b.extension||null,
     b.apply_url, b.source_url||null]
  );
  await audit(req, 'create', 'scholarship', row.id, row.title);
  res.status(201).json({ scholarship: row });
}));

router.patch('/scholarships/:id', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const row = await one('select * from public.scholarships where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  const allowed = ['title','sponsor','sponsor_type','category','level','location','deadline','eligibility','coverage','amount','currency','frequency','covered','not_covered','nationality','academic','documents','steps','contact','open_date','close_date','extension','apply_url','source_url','status'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if ('apply_url' in updates && !/^https?:\/\//i.test(updates.apply_url))
    throw httpError(400, 'apply_url must be an http(s) URL.');
  if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(row.id);
  const updated = await one(
    `update public.scholarships set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'scholarship', row.id, row.title);
  res.json({ scholarship: updated });
}));

router.delete('/scholarships/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.scholarships where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  await run('delete from public.scholarships where id=$1', [row.id]);
  await audit(req, 'delete', 'scholarship', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/scholarships/:id/verify', authenticate, requireRole('owner','admin','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.scholarships where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
  await run(`update public.scholarships set verification='verified', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'verify', 'scholarship', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/scholarships/:id/publish', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.scholarships where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  if (row.verification !== 'verified')
    throw httpError(400, 'Scholarship must be verified before it can be published.');
  await run(`update public.scholarships set status='published', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'publish', 'scholarship', row.id, row.title);
  res.json({ ok: true });
}));

router.get('/trending', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  res.json({ stories: await many('select * from public.trending order by created_at desc') });
}));

router.post('/trending', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.category || !b.author || !b.body)
    throw httpError(400, 'title, category, author and body are required.');
  const row = await one(
    `insert into public.trending
       (title, category, author, summary, body, cover_media_id, alt_text, caption,
        source_url, source_date, verification, featured, scheduled_at, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unverified',$11,$12,'draft') returning *`,
    [b.title, b.category, b.author, b.summary||null, b.body, b.cover_media_id||null,
     b.alt_text||null, b.caption||null, b.source_url||null, b.source_date||null,
     b.featured ? true : false, b.scheduled_at||null]
  );
  await audit(req, 'create', 'trending', row.id, row.title);
  res.status(201).json({ story: row });
}));

router.patch('/trending/:id', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const row = await one('select * from public.trending where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  const allowed = ['title','category','author','summary','body','cover_media_id','alt_text','caption','source_url','source_date','featured','scheduled_at','status'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if ('featured' in updates) updates.featured = updates.featured ? true : false;
  if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(row.id);
  const updated = await one(
    `update public.trending set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );
  await audit(req, 'update', 'trending', row.id, row.title);
  res.json({ story: updated });
}));

router.delete('/trending/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.trending where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  await run('delete from public.trending where id=$1', [row.id]);
  await audit(req, 'delete', 'trending', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/trending/:id/verify', authenticate, requireRole('owner','admin','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.trending where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
  await run(`update public.trending set verification='verified', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'verify', 'trending', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/trending/:id/publish', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.trending where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  if (row.verification !== 'verified')
    throw httpError(400, 'Story must be verified before it can be published.');
  await run(`update public.trending set status='published', updated_at=now() where id=$1`, [row.id]);
  await audit(req, 'publish', 'trending', row.id, row.title);
  res.json({ ok: true });
}));

router.post('/trending/:id/schedule', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.trending where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  if (!req.body || !req.body.scheduled_at)
    throw httpError(400, 'scheduled_at is required.');
  await run(
    `update public.trending set status='scheduled', scheduled_at=$1, updated_at=now() where id=$2`,
    [req.body.scheduled_at, row.id]
  );
  await audit(req, 'schedule', 'trending', row.id, row.title, { scheduled_at: req.body.scheduled_at });
  res.json({ ok: true });
}));

/* ---------- MEDIA (Supabase Storage) ---------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/webp','image/svg+xml','application/pdf'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('File type not allowed.'));
    cb(null, true);
  },
});

router.post('/media', authenticate, requireRole('owner','admin','editor','school_manager'), upload.single('file'), asyncH(async (req, res) => {
  if (!req.file) throw httpError(400, 'A file is required.');

  const b = req.body || {};
  let schoolId = b.school_id ? String(b.school_id) : null;
  if (req.user.role === 'school_manager') {
    if (!req.user.school_id) throw httpError(403, 'No school assigned to this account.');
    schoolId = req.user.school_id;
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  const filename = crypto.randomBytes(12).toString('hex') + ext;

  const { error: uploadError } = await supabase.storage
    .from(MEDIA_BUCKET)
    .upload(filename, req.file.buffer, {
      contentType: req.file.mimetype,
      cacheControl: '3600',
      upsert: false,
    });

  if (uploadError) {
    console.error('[supabase storage]', uploadError.message);
    throw httpError(500, 'Media upload failed: ' + uploadError.message);
  }

  const { data: urlData } = supabase.storage
    .from(MEDIA_BUCKET)
    .getPublicUrl(filename);

  const publicUrl = urlData.publicUrl;

  const row = await one(
    `insert into public.media_assets
       (filename, original_name, mime_type, size, storage_path, public_url,
        display_name, alt_text, caption, category, tags, school_id, uploaded_by)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) returning *`,
    [
      filename, req.file.originalname, req.file.mimetype, req.file.size,
      filename, publicUrl,
      b.display_name || req.file.originalname, b.alt_text || null, b.caption || null,
      b.category || null, b.tags || null, schoolId, req.user.id
    ]
  );

  await audit(req, 'upload', 'media', row.id, row.display_name || row.original_name);
  res.status(201).json({ media: row });
}));

router.get('/media', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  const clauses = []; const params = [];
  if (req.user.role === 'school_manager') { params.push(req.user.school_id); clauses.push(`school_id = $${params.length}`); }
  if (req.query.school_id && req.user.role !== 'school_manager') { params.push(req.query.school_id); clauses.push(`school_id = $${params.length}`); }

  const rows = await many(
    `select * from public.media_assets ${clauses.length ? 'where ' + clauses.join(' and ') : ''} order by created_at desc`,
    params
  );

  if (rows.length) {
    const ids = rows.map(r => r.id);
    const placements = await many(
      `select id, media_id, page, slot, content_ref, is_active, updated_at
         from public.media_placements
        where is_active = true and media_id = ANY($1::uuid[])`,
      [ids]
    );
    const byMedia = {};
    for (const p of placements) (byMedia[p.media_id] ||= []).push(p);
    for (const r of rows) r.placements = byMedia[r.id] || [];
  } else {
    for (const r of rows) r.placements = [];
  }

  res.json({ media: rows });
}));

router.get('/schools/:schoolId/media', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  res.json({ media: await many('select * from public.media_assets where school_id=$1 order by created_at desc', [req.params.schoolId]) });
}));

router.patch('/media/:id', authenticate, requireRole('owner','admin','editor','school_manager'), asyncH(async (req, res) => {
  const row = await one('select * from public.media_assets where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Media not found.');
  if (req.user.role === 'school_manager' && !idsEqual(row.school_id, req.user.school_id))
    throw httpError(403, 'You can only edit media for your assigned institution.');
  const allowed = ['display_name','alt_text','caption','category','tags'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
  const keys = Object.keys(updates); const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(row.id);
  const updated = await one(`update public.media_assets set ${setSql} where id=$${values.length} returning *`, values);
  await audit(req, 'update', 'media', row.id, row.display_name || row.filename);
  res.json({ media: updated });
}));

router.delete('/media/:id', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
  const row = await one('select * from public.media_assets where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Media not found.');
  if (req.user.role === 'school_manager' && !idsEqual(row.school_id, req.user.school_id))
    throw httpError(403, 'You can only delete media for your assigned institution.');

  const activePlacements = await many(
    `select id, page, slot, content_ref from public.media_placements
      where media_id = $1 and is_active = true`,
    [row.id]
  );
  if (activePlacements.length) {
    throw httpError(
      409,
      `This file is used on ${activePlacements.length} placement(s). Unassign or replace it first.`,
      'media_in_use'
    );
  }

  const { error: removeError } = await supabase.storage
    .from(MEDIA_BUCKET)
    .remove([row.filename]);

  if (removeError) {
    console.error('[supabase storage remove]', removeError.message);
  }

  await run('delete from public.media_assets where id=$1', [row.id]);
  await audit(req, 'delete', 'media', row.id, row.display_name || row.filename);
  res.json({ ok: true });
}));

router.get('/media/placements', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const { page, slot, media_id } = req.query;
  const clauses = ['p.is_active = true'];
  const params = [];
  if (page)     { params.push(page);     clauses.push(`p.page = $${params.length}`); }
  if (slot)     { params.push(slot);     clauses.push(`p.slot = $${params.length}`); }
  if (media_id) { params.push(media_id); clauses.push(`p.media_id = $${params.length}`); }

  const rows = await many(
    `select p.*, m.public_url, m.alt_text, m.display_name, m.mime_type
       from public.media_placements p
       join public.media_assets m on m.id = p.media_id
      where ${clauses.join(' and ')}
      order by p.updated_at desc`,
    params
  );
  res.json({ placements: rows });
}));

router.post('/media/placements', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const { media_id, page, slot, content_ref } = req.body || {};
  if (!media_id || !page || !slot)
    throw httpError(400, 'media_id, page and slot are required.');

  if (!isValidPlacement(page, slot))
    throw httpError(400, `Unknown placement: ${page} / ${slot}.`);

  const media = await one('select * from public.media_assets where id=$1', [media_id]);
  if (!media) throw httpError(404, 'Media not found.');
  if (!/^image\//i.test(media.mime_type || ''))
    throw httpError(400, 'Only images can be placed on the website.');

  const ref = content_ref ? String(content_ref) : null;
  if (placementNeedsRef(page, slot) && !ref)
    throw httpError(400, `This slot requires a content_ref (e.g. school id).`);
  if (!placementNeedsRef(page, slot) && ref)
    throw httpError(400, `This slot is global and does not accept a content_ref.`);

  await run(
    `update public.media_placements
        set is_active = false, updated_at = now()
      where page = $1 and slot = $2
        and (content_ref is not distinct from $3)
        and is_active = true`,
    [page, slot, ref]
  );

  const row = await one(
    `insert into public.media_placements (media_id, page, slot, content_ref, is_active)
     values ($1,$2,$3,$4,true) returning *`,
    [media_id, page, slot, ref]
  );

  await audit(req, 'place_media', 'media_placement', row.id, `${page}/${slot}`, {
    media_id, content_ref: ref,
  });

  res.status(201).json({ placement: row });
}));

router.delete('/media/placements/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.media_placements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Placement not found.');
  await run('delete from public.media_placements where id=$1', [row.id]);
  await audit(req, 'unplace_media', 'media_placement', row.id, `${row.page}/${row.slot}`);
  res.json({ ok: true });
}));

/* ---------- USERS ---------- */
router.get('/users', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const rows = await many(
    `select u.*, s.name as school_name, s.slug as school_slug
       from public.users u
       left join public.schools s on s.id = u.school_id
      order by u.created_at desc`
  );
  res.json({ users: rows.map(publicUser) });
}));

router.post('/users', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.email || !b.role) throw httpError(400, 'name, email and role are required.');
  if (!['owner','admin','editor','reviewer','school_manager'].includes(b.role)) throw httpError(400, 'Invalid role.');

  let schoolId = null;
  if (b.role === 'school_manager') {
    if (!b.school_id) throw httpError(400, 'school_id is required for school managers.');
    const school = await one('select id, name from public.schools where id=$1', [b.school_id]);
    if (!school) throw httpError(400, `School id=${b.school_id} does not exist.`);
    schoolId = school.id;
  }

  if (await one('select 1 from public.users where lower(email)=lower($1)', [b.email]))
    throw httpError(409, 'An account with that email already exists.');

  const initialPassword = b.password || crypto.randomBytes(9).toString('base64').slice(0, 12);
  const hash = bcrypt.hashSync(initialPassword, 10);
  const status = b.role === 'school_manager' ? 'pending' : 'active';
  const user = await one(
    `insert into public.users (name, email, password_hash, role, school_id, status, must_change_password, notes)
     values ($1,$2,$3,$4,$5,$6,true,$7) returning *`,
    [b.name, b.email, hash, b.role, schoolId, status, b.notes || null]
  );
  await audit(req, 'create', 'user', user.id, user.email, { role: user.role, status: user.status, school_id: schoolId });
  res.status(201).json({ user: publicUser(user), initial_password: initialPassword, note: 'Share the initial password securely. The user must change it after first sign-in.' });
}));

router.post('/users/:id/assign-school', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const { school_id } = req.body || {};
  const user = await one('select * from public.users where id=$1', [req.params.id]);
  if (!user) throw httpError(404, 'User not found.');
  if (user.role !== 'school_manager') throw httpError(400, 'Only school_manager accounts can be assigned a school.');

  let newSchoolId = null;
  if (school_id != null && school_id !== '') {
    const school = await one('select id, name from public.schools where id=$1', [school_id]);
    if (!school) throw httpError(400, `School id=${school_id} does not exist.`);
    newSchoolId = school.id;
  }

  const updated = await one(
    `update public.users set school_id=$1, updated_at=now() where id=$2 returning *`,
    [newSchoolId, user.id]
  );

  await audit(req, 'assign_school', 'user', user.id, user.email, {
    previous_school_id: user.school_id,
    new_school_id: newSchoolId,
  });

  const enriched = await fetchUserWithSchool(updated.id);
  res.json({ ok: true, user: publicUser(enriched) });
}));

router.post('/users/:id/approve', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const user = await one('select * from public.users where id=$1', [req.params.id]);
  if (!user) throw httpError(404, 'User not found.');
  if (user.role === 'school_manager' && !user.school_id)
    throw httpError(400, 'Cannot approve a school manager without an assigned school. Use /users/:id/assign-school first.');

  const updated = await one(`update public.users set status='active', updated_at=now() where id=$1 returning *`, [user.id]);
  await audit(req, 'approve_user', 'user', user.id, user.email);
  await notify(user.id, user.school_id, 'Your account has been approved', 'You can now sign in to the CampusNaija school portal.');
  res.json({ ok: true, user: publicUser(updated) });
}));

router.post('/users/:id/suspend', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const user = await one('select * from public.users where id=$1', [req.params.id]);
  if (!user) throw httpError(404, 'User not found.');
  if (user.role === 'owner') throw httpError(400, 'Cannot suspend the platform owner.');
  await run(`update public.users set status='suspended', updated_at=now() where id=$1`, [user.id]);
  await audit(req, 'suspend_user', 'user', user.id, user.email);
  res.json({ ok: true });
}));

router.post('/users/:id/reactivate', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const user = await one('select * from public.users where id=$1', [req.params.id]);
  if (!user) throw httpError(404, 'User not found.');
  await run(`update public.users set status='active', updated_at=now() where id=$1`, [user.id]);
  await audit(req, 'reactivate_user', 'user', user.id, user.email);
  res.json({ ok: true });
}));

/* ---------- NOTIFICATIONS ---------- */
router.get('/notifications', authenticate, asyncH(async (req, res) => {
  const where = req.user.role === 'owner' ? '' : 'where (user_id = $1 or school_id = $2)';
  const params = req.user.role === 'owner' ? [] : [req.user.id, req.user.school_id || null];
  res.json({ notifications: await many(`select * from public.notifications ${where} order by created_at desc limit 100`, params) });
}));

router.post('/notifications/:id/read', authenticate, asyncH(async (req, res) => {
  const n = await one('select * from public.notifications where id=$1', [req.params.id]);
  if (!n) throw httpError(404, 'Notification not found.');
  if (req.user.role !== 'owner' && n.user_id !== req.user.id && !idsEqual(n.school_id, req.user.school_id))
    throw httpError(403, 'Not allowed.');
  await run('update public.notifications set is_read=true where id=$1', [n.id]);
  res.json({ ok: true });
}));

/* ---------- AUDIT ---------- */
router.get('/audit', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  res.json({ audit: await many('select * from public.audit_logs order by created_at desc limit 500') });
}));

/* ---------- SETTINGS ---------- */
router.get('/settings', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  res.json({ settings: await readSettings() });
}));

router.patch('/settings', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const b = req.body || {};
  const allowed = ['site_name','site_tagline','site_description','admin_email','require_review','require_verification_for_fees','auto_archive_expired','single_session','lockout_attempts','session_timeout'];
  const updates = {}; for (const k of allowed) if (k in b) updates[k] = String(b[k]);
  if (!Object.keys(updates).length) throw httpError(400, 'No settings to update.');
  for (const [k, v] of Object.entries(updates)) {
    await run(`insert into public.settings (key, value) values ($1,$2)
               on conflict (key) do update set value = excluded.value`, [k, v]);
  }
  await audit(req, 'update_settings', 'settings', null, null, { keys: Object.keys(updates) });
  res.json({ ok: true, settings: await readSettings() });
}));

/* ---------- HEALTH ---------- */
router.get('/health', asyncH(async (req, res) => {
  try {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('database health check timed out after 5s')), 5000)
    );
    const dbPromise = q('select now() as now');
    const r = await Promise.race([dbPromise, timeoutPromise]);

    let orphanManagers = 0;
    try {
      const orphanRow = await one(
        `select count(*)::int as c from public.users
          where role='school_manager' and school_id is null`
      );
      orphanManagers = orphanRow ? orphanRow.c : 0;
    } catch (_) {}

    let unverifiedSchools = 0;
    try {
      const legRow = await one(
        `select count(*)::int as c from public.schools
          where verification <> 'verified'`
      );
      unverifiedSchools = legRow ? legRow.c : 0;
    } catch (_) {}

    res.json({
      ok: true,
      time: r.rows[0].now,
      version: '1.8.1',
      media: 'supabase-storage',
      placements: true,
      school_verification_removed: true,
      uuid_scope_check: true,
      content_lifecycle: 'publish-now-send-back',
      review_comment_join: true,
      orphan_school_managers: orphanManagers,
      legacy_unverified_schools: unverifiedSchools,
    });
  } catch (e) {
    res.status(503).json({
      ok: false,
      error: 'Database unreachable: ' + e.message,
      hint: 'Check DATABASE_URL on Render. It should use the Supabase pooler (port 6543), and the Supabase project must not be paused.',
      version: '1.8.1',
    });
  }
}));

/* ============================================================
 * FRONTEND STATIC FILES
 * ============================================================ */
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  index: false,
  maxAge: '1h',
  fallthrough: true,
}));

app.get('/', (req, res, next) => {
  res.sendFile(path.join(PUBLIC_DIR, 'Home.html'), (err) => { if (err) next(); });
});

app.get(['/admin', '/admin/'], (req, res, next) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin', 'login.html'), (err) => { if (err) next(); });
});

app.get(
  ['/admin/login', '/admin/login.html', '/admin/Login', '/admin/Login.html'],
  (req, res, next) => {
    res.sendFile(path.join(PUBLIC_DIR, 'admin', 'login.html'), (err) => { if (err) next(); });
  }
);

app.get(['/SchoolAd', '/SchoolAd/'], (req, res, next) => {
  res.sendFile(path.join(PUBLIC_DIR, 'SchoolAd', 'login.html'), (err) => { if (err) next(); });
});

app.get(
  ['/SchoolAd/login', '/SchoolAd/login.html',
   '/SchoolAd/Login', '/SchoolAd/Login.html'],
  (req, res, next) => {
    res.sendFile(path.join(PUBLIC_DIR, 'SchoolAd', 'login.html'), (err) => { if (err) next(); });
  }
);

/* ============================================================
 * ERROR HANDLING
 * ============================================================ */
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) console.error('[error]', err);
  res.status(status).json({ error: err.message || 'Internal server error.', code: err.code });
});

/* ============================================================
 * START / SHUTDOWN
 * ============================================================ */
const httpServer = app.listen(PORT, () => {
  console.log(`CampusNaija backend listening on port ${PORT}`);
  console.log(`Owner email: ${OWNER_EMAIL}`);
  console.log(`Public dir: ${PUBLIC_DIR}`);
  console.log(`Media storage: Supabase bucket "${MEDIA_BUCKET}"`);
  console.log('API base: /api');
});

seed().catch(e => console.error('[seed]', e.message));

function shutdown(signal) {
  console.log(`[stop] ${signal}, shutting down...`);
  httpServer.close(async () => {
    try { await pool.end(); } catch (_) {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 8000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));