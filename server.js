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
 * CONFIG
 * ============================================================ */
const PORT = Number(process.env.PORT) || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const OWNER_EMAIL = process.env.OWNER_EMAIL || 'owner@campusnaija.ng';
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '';
const FORCE_PASSWORD_CHANGE = process.env.FORCE_PASSWORD_CHANGE === '1';
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);
const BCRYPT_COST = 12;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MEDIA_BUCKET = 'media';

if (!DATABASE_URL) { console.error('[env] DATABASE_URL is required'); process.exit(1); }
if (!JWT_SECRET)   { console.error('[env] JWT_SECRET is required');   process.exit(1); }
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('[env] SUPABASE_URL and SUPABASE_SERVICE_KEY are required for media uploads');
  process.exit(1);
}

// ── Production boot checks ─────────────────────────────
if (IS_PROD) {
  if (JWT_SECRET.length < 32) {
    console.error('[env] JWT_SECRET must be at least 32 characters in production.');
    process.exit(1);
  }
  if (OWNER_PASSWORD && OWNER_PASSWORD.length < 12) {
    console.error('[env] OWNER_PASSWORD must be at least 12 characters in production.');
    process.exit(1);
  }
  if (ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.length === 0) {
    console.error('[env] ALLOWED_ORIGINS must be an explicit comma-separated list in production.');
    process.exit(1);
  }
}

/* ============================================================
 * ERROR HELPERS
 * ============================================================ */
function httpError(status, message, code) {
  const err = new Error(message); err.status = status; err.code = code; return err;
}
function asyncH(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

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
 * UPLOAD (multer)
 * ============================================================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'image/jpeg','image/png','image/webp','image/svg+xml','application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ];
    if (!allowed.includes(file.mimetype)) return cb(new Error('File type not allowed.'));
    cb(null, true);
  },
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

async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally {
    client.release();
  }
}

function idsEqual(a, b) {
  if (a == null || b == null) return false;
  return String(a) === String(b);
}

/* ============================================================
 * PERSISTENT RATE LIMITING
 * ============================================================ */
async function rateLimit(key, max, windowMs) {
  try {
    const row = await one(
      `insert into public.rate_limits (key, count, reset_at)
       values ($1, 1, now() + ($2 || ' milliseconds')::interval)
       on conflict (key) do update
         set count    = case when public.rate_limits.reset_at < now()
                             then 1
                             else public.rate_limits.count + 1 end,
             reset_at = case when public.rate_limits.reset_at < now()
                             then now() + ($2 || ' milliseconds')::interval
                             else public.rate_limits.reset_at end
       returning count, reset_at`,
      [key, String(windowMs)]
    );
    return row.count <= max;
  } catch (e) {
    console.error('[rateLimit]', e.message);
    return true;
  }
}

setInterval(async () => {
  try { await run(`delete from public.rate_limits where reset_at < now() - interval '1 hour'`); }
  catch (_) {}
}, 60 * 60 * 1000).unref();

/* ============================================================
 * FIELD VALIDATION
 * ============================================================ */
const FIELD_LIMITS = {
  name: 200, title: 300, email: 254, url: 2048,
  short: 500, medium: 2000, long: 20000,
};

function validateField(value, label, max, { required = false } = {}) {
  if (value == null || value === '') {
    if (required) throw httpError(400, `${label} is required.`);
    return null;
  }
  const s = String(value);
  if (s.length > max) throw httpError(400, `${label} must be ${max} characters or fewer.`);
  return s;
}

function validateUrl(value, label, { required = false } = {}) {
  const s = validateField(value, label, FIELD_LIMITS.url, { required });
  if (s != null && !/^https?:\/\/[^\s]+$/i.test(s)) {
    throw httpError(400, `${label} must be a valid http(s) URL.`);
  }
  return s;
}

function sanitizeText(value) {
  if (value == null) return null;
  return String(value).replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;'));
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ============================================================
 * PAGINATION
 * ============================================================ */
function pagination(req, { defaultLimit = 50, maxLimit = 200 } = {}) {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || defaultLimit, 1), maxLimit);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  return { limit, offset };
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
      const hash = bcrypt.hashSync(OWNER_PASSWORD, BCRYPT_COST);
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

async function audit(req, action, targetType, targetId, targetLabel, details) {
  try {
    const u = req.user || (req.advertiser
      ? { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }
      : null);
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

/* ============================================================
 * ADVERTISER AUTH HELPERS
 * ============================================================ */
const ADVERTISER_ROLE = 'advertiser';

function publicAdvertiser(u, profile) {
  if (!u) return null;
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    status: u.status,
    business_name: profile?.business_name || null,
    phone: profile?.phone || null,
    website: profile?.website || null,
    address: profile?.address || null,
    must_change_password: !!u.must_change_password,
    created_at: u.created_at,
  };
}

async function fetchAdvertiser(userId) {
  const u = await one(
    `select * from public.users where id=$1 and role=$2`,
    [userId, ADVERTISER_ROLE]
  );
  if (!u) return null;
  const profile = await one(
    `select * from public.advertiser_profiles where user_id=$1`,
    [u.id]
  );
  return { user: u, profile };
}

async function authenticateAdvertiser(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) throw httpError(401, 'Authentication required.', 'no_token');
    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); }
    catch { throw httpError(401, 'Session expired or invalid token.', 'bad_token'); }

    const rec = await fetchAdvertiser(payload.sub);
    if (!rec) throw httpError(401, 'Advertiser account not found.', 'no_advertiser');
    if (rec.user.status === 'suspended')
      throw httpError(403, 'This advertiser account is suspended.', 'suspended');
    if (rec.user.status === 'pending')
      throw httpError(403, 'Your advertiser account is awaiting approval.', 'pending_approval');
    if (rec.user.status !== 'active')
      throw httpError(403, 'Advertiser account is not active.', 'inactive');

    req.advertiser = rec.user;
    req.advertiserProfile = rec.profile;
    req._bearerToken = token;
    next();
  } catch (e) { next(e); }
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
 * ROUTER
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
  if (!(await rateLimit(`login:${ip}`, 8, 15 * 60 * 1000)))
    throw httpError(429, 'Too many sign-in attempts. Try again later.', 'rate_limited');

  const identifier = validateField(req.body?.identifier, 'Email/username', FIELD_LIMITS.email, { required: true });
  const password = validateField(req.body?.password, 'password', 200, { required: true });

  const user = await one('select * from public.users where lower(email) = lower($1)', [identifier]);
  const invalid = httpError(401, 'Invalid credentials, or this account is not approved for sign-in.');
  if (!user) throw invalid;
  if (!bcrypt.compareSync(password, user.password_hash)) throw invalid;
  if (user.status === 'suspended') throw httpError(403, 'This account is suspended. Contact the platform owner.');
  if (user.status === 'pending') throw httpError(403, 'This account is awaiting approval. Contact the platform owner.');

  const fullUser = await fetchUserWithSchool(user.id);

  if (fullUser.role === 'school_manager' && !fullUser.school_id) {
    console.warn(`[auth] school_manager ${fullUser.email} (id=${fullUser.id}) has NO school_id assigned.`);
  }
  if (fullUser.role === 'school_manager' && fullUser.school_id && !fullUser.school_name) {
    console.warn(`[auth] school_manager ${fullUser.email} (id=${fullUser.id}) has orphaned school_id=${fullUser.school_id}.`);
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
  const current = validateField(req.body?.current_password, 'current_password', 200, { required: true });
  const np = validateField(req.body?.new_password, 'new_password', 200, { required: true });
  if (np.length < 10) throw httpError(400, 'New password must be at least 10 characters.');

  const user = await one('select * from public.users where id = $1', [req.user.id]);
  if (!bcrypt.compareSync(current, user.password_hash))
    throw httpError(400, 'Current password is incorrect.');

  const hash = bcrypt.hashSync(np, BCRYPT_COST);
  await run(
    `update public.users set password_hash=$1, must_change_password=false, updated_at=now() where id=$2`,
    [hash, user.id]
  );
  await audit(req, 'change_password', 'user', user.id, user.email);
  res.json({ ok: true });
}));

router.post('/auth/forgot-password', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`forgot:${ip}`, 4, 15 * 60 * 1000)))
    throw httpError(429, 'Too many reset requests. Try again later.', 'rate_limited');

  const email = validateField(req.body?.email, 'email', FIELD_LIMITS.email, { required: true });
  const user = await one('select * from public.users where lower(email)=lower($1)', [email]);

  let rawToken = null;
  if (user && user.status === 'active') {
    rawToken = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
    await tx(async (c) => {
      await c.query(
        `insert into public.password_resets (user_id, token_hash, expires_at)
         values ($1, $2, now() + interval '1 hour')`,
        [user.id, hash]
      );
      await c.query(
        `insert into public.audit_logs
           (actor_id, actor_name, actor_role, action, target_type, target_id, target_label, ip)
         values (null, 'system', 'security', 'request_password_reset', 'user', $1, $2, $3)`,
        [user.id, user.email, ip]
      );
    });
    console.log(`[password-reset] generated for ${user.email}`);
  }

  const body = { ok: true, message: 'If an approved account exists for that email, a reset link will be sent.' };
  if (!IS_PROD && rawToken) body.dev_token = rawToken;
  res.json(body);
}));

router.post('/auth/reset-password', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`reset:${ip}`, 6, 15 * 60 * 1000)))
    throw httpError(429, 'Too many reset attempts. Try again later.', 'rate_limited');

  const token = validateField(req.body?.token, 'token', 200, { required: true });
  const newPassword = validateField(req.body?.new_password, 'new_password', 200, { required: true });
  if (newPassword.length < 10) throw httpError(400, 'New password must be at least 10 characters.');

  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const row = await one(
    `select pr.*, u.status as user_status
       from public.password_resets pr
       join public.users u on u.id = pr.user_id
      where pr.token_hash = $1
        and pr.used_at is null
        and pr.expires_at > now()`,
    [hash]
  );
  if (!row) throw httpError(400, 'This reset link is invalid or has expired.');
  if (row.user_status !== 'active') throw httpError(403, 'This account is not active.');

  const passwordHash = bcrypt.hashSync(newPassword, BCRYPT_COST);
  await tx(async (c) => {
    await c.query(
      `update public.users
          set password_hash = $1, must_change_password = false, updated_at = now()
        where id = $2`,
      [passwordHash, row.user_id]
    );
    await c.query(`update public.password_resets set used_at = now() where id = $1`, [row.id]);
    await c.query(
      `update public.password_resets set used_at = now()
        where user_id = $1 and used_at is null`,
      [row.user_id]
    );
    await c.query(
      `insert into public.audit_logs
         (actor_id, actor_name, actor_role, action, target_type, target_id, ip)
       values (null, 'system', 'security', 'complete_password_reset', 'user', $1, $2)`,
      [row.user_id, ip]
    );
  });

  res.json({ ok: true });
}));

/* ============================================================
 * ADVERTISER ENDPOINTS
 * ============================================================ */
async function notifyStaff(title, body, link) {
  const staff = await many(
    `select id from public.users where role in ('owner','admin')`
  );
  for (const s of staff) {
    try {
      await run(
        `insert into public.notifications (user_id, title, body, link)
         values ($1,$2,$3,$4)`,
        [s.id, title, body, link]
      );
    } catch (e) {
      console.warn('[notifyStaff]', e.message);
    }
  }
}

/* Helper: notify a single advertiser with a category */
async function notifyAdvertiser(userId, title, body, link, category) {
  try {
    await run(
      `insert into public.notifications (user_id, title, body, link, category, action_url)
       values ($1,$2,$3,$4,$5,$6)`,
      [userId, title, body, link, category || null, link || null]
    );
  } catch (e) {
    // Fallback if category/action_url columns don't exist yet
    try {
      await run(
        `insert into public.notifications (user_id, title, body, link)
         values ($1,$2,$3,$4)`,
        [userId, title, body, link]
      );
    } catch (e2) { console.warn('[notifyAdvertiser]', e2.message); }
  }
}

router.post('/advertiser/register', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`adv_register:${ip}`, 5, 60 * 60 * 1000)))
    throw httpError(429, 'Too many registration attempts. Try again later.', 'rate_limited');

  const b = req.body || {};
  const name         = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true }).trim();
  const businessName = validateField(b.business_name, 'business_name', FIELD_LIMITS.name, { required: true }).trim();
  const rawEmail     = validateField(b.email, 'email', FIELD_LIMITS.email, { required: true }).trim();
  const email        = rawEmail.toLowerCase();
  const phone        = validateField(b.phone, 'phone', 30);
  const password     = validateField(b.password, 'password', 200, { required: true });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    throw httpError(400, 'Please enter a valid email address.');
  if (password.length < 10)
    throw httpError(400, 'Password must be at least 10 characters.');

  const existing = await one(
    'select id from public.users where lower(email) = lower($1)',
    [email]
  );
  if (existing)
    throw httpError(409, 'An account with that email already exists. Try signing in instead.', 'email_taken');

  const hash = bcrypt.hashSync(password, BCRYPT_COST);

  await tx(async (c) => {
    const u = await c.query(
      `insert into public.users (name, email, password_hash, role, status, must_change_password)
       values ($1,$2,$3,$4,'pending',false)
       returning *`,
      [name, email, hash, ADVERTISER_ROLE]
    );
    const newUserId = u.rows[0].id;

    await c.query(
      `insert into public.advertiser_profiles (user_id, business_name, phone)
       values ($1,$2,$3)`,
      [newUserId, businessName, phone || null]
    );

    await c.query(
      `insert into public.audit_logs
        (actor_id, actor_name, actor_role, action, target_type, target_id, target_label, ip)
       values ($1::uuid, $2, $3, 'advertiser_register', 'advertiser', $4, $5, $6)`,
      [newUserId, name, ADVERTISER_ROLE, String(newUserId), email, ip]
    );

    // Notify owners/admins — per-row inserts, no || on params
    const staff = await c.query(
      `select id from public.users where role in ('owner','admin')`
    );
    const body = `${businessName} (${email}) has requested an advertiser account.`;
    for (const s of staff.rows) {
      try {
        await c.query(
          `insert into public.notifications (user_id, title, body, link)
           values ($1,$2,$3,$4)`,
          [s.id, 'New advertiser awaiting approval', body, '/admin/advertisers.html']
        );
      } catch (notifErr) {
        console.warn('[register] notification insert failed (non-fatal):', notifErr.message);
      }
    }
  });

  console.log(`[advertiser] registered ${email} (pending approval)`);
  res.status(201).json({
    ok: true,
    message: 'Your account has been created and is awaiting approval. You will be notified by email once approved.',
  });
}));

router.post('/advertiser/login', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`adv_login:${ip}`, 8, 15 * 60 * 1000)))
    throw httpError(429, 'Too many sign-in attempts. Try again later.', 'rate_limited');

  const email    = validateField(req.body?.email, 'email', FIELD_LIMITS.email, { required: true }).trim().toLowerCase();
  const password = validateField(req.body?.password, 'password', 200, { required: true });

  const u = await one(
    `select * from public.users where lower(email)=lower($1) and role=$2`,
    [email, ADVERTISER_ROLE]
  );
  const invalid = httpError(401, 'Invalid credentials.');
  if (!u) throw invalid;
  if (!bcrypt.compareSync(password, u.password_hash)) throw invalid;
  if (u.status === 'suspended') throw httpError(403, 'This account is suspended. Contact support.');
  if (u.status === 'pending') throw httpError(403, 'Your account is awaiting approval. You will be notified by email.');
  if (u.status !== 'active') throw httpError(403, 'This account is not active.');

  const profile = await one(
    `select * from public.advertiser_profiles where user_id=$1`,
    [u.id]
  );

  const token = signToken({ ...u, school_id: null });
  await audit(
    { user: { ...u, role: u.role }, ip },
    'advertiser_login', 'advertiser', u.id, u.email
  );

  res.json({ token, user: publicAdvertiser(u, profile) });
}));

router.get('/advertiser/me', authenticateAdvertiser, asyncH(async (req, res) => {
  res.json({ user: publicAdvertiser(req.advertiser, req.advertiserProfile) });
}));

/* ---------- Advertiser: campaigns ---------- */
router.get('/advertiser/campaigns', authenticateAdvertiser, asyncH(async (req, res) => {
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });
  const rows = await many(
    `select id, name, advertiser, placement, format, url, image_url,
            start_date, end_date, status, impressions, clicks,
            approved_at, created_at, updated_at
       from public.advertisements
      where advertiser_user_id = $1
      order by created_at desc
      limit $2 offset $3`,
    [req.advertiser.id, limit, offset]
  );
  const totalRow = await one(
    `select count(*)::int as c from public.advertisements where advertiser_user_id=$1`,
    [req.advertiser.id]
  );
  res.json({ campaigns: rows, total: totalRow.c, limit, offset });
}));

router.get('/advertiser/campaigns/:id', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertisements
      where id=$1 and advertiser_user_id=$2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Campaign not found.');
  res.json({ campaign: row });
}));

router.post('/advertiser/campaigns', authenticateAdvertiser, asyncH(async (req, res) => {
  const b = req.body || {};
  const name        = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true }).trim();
  const headline    = validateField(b.headline, 'headline', FIELD_LIMITS.title, { required: true }).trim();
  const description = validateField(b.description, 'description', FIELD_LIMITS.medium);
  const url         = validateUrl(b.url, 'url', { required: true });
  const cta         = validateField(b.cta_text, 'cta_text', 50) || 'Learn More';
  const format      = validateField(b.format, 'format', 20, { required: true }).toLowerCase();
  if (!['large','medium','small','square','vertical'].includes(format))
    throw httpError(400, 'format must be large, medium, small, square or vertical.');

  const durationDays = Number(b.duration_days);
  if (!Number.isFinite(durationDays) || durationDays < 1 || durationDays > 365)
    throw httpError(400, 'duration_days must be between 1 and 365.');

  const imageUrl  = validateUrl(b.image_url, 'image_url', { required: true });
  const mediaType = (b.media_type === 'video') ? 'video' : 'image';

  // Compute dates from duration_days (or accept explicit dates if provided)
  let startDate = b.start_date || null;
  let endDate   = b.end_date   || null;

  if (!startDate || !endDate) {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + durationDays);

    startDate = start.toISOString().slice(0, 10); // YYYY-MM-DD
    endDate   = end.toISOString().slice(0, 10);
  }

  if (new Date(endDate) < new Date(startDate))
    throw httpError(400, 'end_date cannot be before start_date.');

  const row = await one(
    `insert into public.advertisements
       (name, advertiser, description, cta_text, url, image_url,
        placement, format, start_date, end_date, status, created_by, advertiser_user_id)
     values ($1,$2,$3,$4,$5,$6,'home',$7,$8,$9,'pending',$10,$11)
     returning *`,
    [
      name,
      (req.advertiserProfile?.business_name || req.advertiser.name || 'Advertiser'),
      (description || headline),
      cta,
      url,
      imageUrl,
      format,
      startDate,
      endDate,
      req.advertiser.id,
      req.advertiser.id,
    ]
  );

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'advertiser_create', 'advertisement', row.id, row.name,
    { format, duration_days: durationDays, media_type: mediaType }
  );

  await notifyStaff(
    'New advertiser campaign submitted',
    `${req.advertiserProfile?.business_name || req.advertiser.name} submitted "${name}" for review.`,
    '/admin/advertisements.html'
  );

  res.status(201).json({ ok: true, campaign: row });
}));

router.delete('/advertiser/campaigns/:id', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertisements
      where id=$1 and advertiser_user_id=$2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Campaign not found.');
  if (!['draft','rejected','expired'].includes(row.status))
    throw httpError(400, 'Only draft, rejected or expired campaigns can be deleted.');
  await run('delete from public.advertisements where id=$1', [row.id]);
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'advertiser_delete', 'advertisement', row.id, row.name
  );
  res.json({ ok: true });
}));

router.post('/advertiser/campaigns/:id/request-pause', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertisements
      where id=$1 and advertiser_user_id=$2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Campaign not found.');
  if (row.status !== 'active') throw httpError(400, 'Only active campaigns can be paused.');
  await run(`update public.advertisements set status='paused', updated_at=now() where id=$1`, [row.id]);
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'request_pause', 'advertisement', row.id, row.name
  );
  await notifyStaff(
    'Advertiser paused a campaign',
    `${row.name} was paused by the advertiser.`,
    '/admin/advertisements.html'
  );
  res.json({ ok: true });
}));

router.post('/advertiser/campaigns/:id/request-resume', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertisements
      where id=$1 and advertiser_user_id=$2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Campaign not found.');
  if (row.status !== 'paused') throw httpError(400, 'Only paused campaigns can be resumed.');
  await run(`update public.advertisements set status='active', updated_at=now() where id=$1`, [row.id]);
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'request_resume', 'advertisement', row.id, row.name
  );
  await notifyStaff(
    'Advertiser resumed a campaign',
    `${row.name} was resumed by the advertiser.`,
    '/admin/advertisements.html'
  );
  res.json({ ok: true });
}));

/* ---------- Advertiser: pricing ---------- */
router.get('/advertiser/pricing', authenticateAdvertiser, asyncH(async (req, res) => {
  const rows = await many(`select key, value from public.settings where key like 'pricing:%'`);
  const cfg = {};
  for (const r of rows) cfg[r.key.slice(8)] = r.value;

  const perDay = Number(cfg.per_day_ngn || 500);
  const formats = {
    large:    { label: 'Large',    multiplier: Number(cfg.mult_large    || 1.4) },
    medium:   { label: 'Medium',   multiplier: Number(cfg.mult_medium   || 1.0) },
    small:    { label: 'Small',    multiplier: Number(cfg.mult_small    || 0.7) },
    square:   { label: 'Square',   multiplier: Number(cfg.mult_square   || 1.1) },
    vertical: { label: 'Vertical', multiplier: Number(cfg.mult_vertical || 1.2) },
  };
  res.json({
    currency: cfg.currency || 'NGN',
    per_day: perDay,
    min_days: Number(cfg.min_days || 7),
    max_days: Number(cfg.max_days || 90),
    discounts: {
      d7:  Number(cfg.discount_7d  || 0),
      d14: Number(cfg.discount_14d || 0.05),
      d30: Number(cfg.discount_30d || 0.10),
      d60: Number(cfg.discount_60d || 0.15),
    },
    formats,
    vat: Number(cfg.vat || 0.075),
    terms_url: cfg.terms_url || '/terms.html',
  });
}));

/* ---------- Advertiser: media upload ---------- */
router.post('/advertiser/media', authenticateAdvertiser, upload.single('file'), asyncH(async (req, res) => {
  if (!req.file) throw httpError(400, 'A file is required.');
  const ext = path.extname(req.file.originalname).toLowerCase();
  const filename = `adv_${crypto.randomBytes(10).toString('hex')}${ext}`;

  const { error: uploadError } = await supabase.storage
    .from(MEDIA_BUCKET)
    .upload(filename, req.file.buffer, {
      contentType: req.file.mimetype,
      cacheControl: '3600',
      upsert: false,
    });
  if (uploadError) {
    console.error('[advertiser media]', uploadError.message);
    throw httpError(500, 'Upload failed: ' + uploadError.message);
  }

  const { data: urlData } = supabase.storage.from(MEDIA_BUCKET).getPublicUrl(filename);

  res.status(201).json({
    ok: true,
    media: {
      url: urlData.publicUrl,
      filename,
      mime_type: req.file.mimetype,
      size: req.file.size,
    },
  });
}));

/* ---------- Advertiser: payments ---------- */
router.get('/advertiser/payments', authenticateAdvertiser, asyncH(async (req, res) => {
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });
  const rows = await many(
    `select id, reference, amount, currency, status, source, created_at
       from public.transactions
      where customer = $1
      order by created_at desc
      limit $2 offset $3`,
    [req.advertiser.email, limit, offset]
  );
  const totalRow = await one(
    `select count(*)::int as c from public.transactions where customer=$1`,
    [req.advertiser.email]
  );
  res.json({ payments: rows, total: totalRow.c, limit, offset });
}));

router.get('/advertiser/payments/:id', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.transactions
      where id=$1 and customer=$2`,
    [req.params.id, req.advertiser.email]
  );
  if (!row) throw httpError(404, 'Transaction not found.');
  res.json({ transaction: row });
}));

router.get('/advertiser/payments/:id/invoice', authenticateAdvertiser, asyncH(async (req, res) => {
  const tx = await one(
    `select * from public.transactions where id=$1 and customer=$2`,
    [req.params.id, req.advertiser.email]
  );
  if (!tx) throw httpError(404, 'Transaction not found.');

  const billing = await one(`select * from public.advertiser_billing where user_id=$1`, [req.advertiser.id]);
  const profile = req.advertiserProfile;
  const bizName = billing?.billing_name || profile?.business_name || req.advertiser.name || 'Advertiser';
  const bizEmail = billing?.billing_email || req.advertiser.email;
  const bizAddr = billing?.address || '';
  const bizPhone = billing?.phone || '';
  const bizTax = billing?.tax_id || '';
  const bizReg = billing?.business_reg_no || '';

  const invNo = `CN-INV-${String(tx.reference || tx.id).replace(/[^A-Z0-9]/gi, '').slice(-6).toUpperCase()}`;
  const rcpNo = `CN-RCP-${String(tx.reference || tx.id).replace(/[^A-Z0-9]/gi, '').slice(-6).toUpperCase()}`;
  const isPaid = ['paid', 'confirmed', 'verified', 'successful'].includes((tx.status || '').toLowerCase());
  const amount = Number(tx.amount || 0);
  const currency = (tx.currency || 'NGN').toUpperCase();
  const sym = currency === 'NGN' ? '₦' : currency === 'USD' ? '$' : currency === 'GBP' ? '£' : currency === 'EUR' ? '€' : currency + ' ';
  const fmt = (n) => sym + Math.round(Number(n || 0)).toLocaleString('en-NG');
  const date = tx.created_at ? new Date(tx.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' }) : '';
  const docType = req.query.doc === 'receipt' ? 'receipt' : 'invoice';
  const docNo = docType === 'receipt' ? rcpNo : invNo;
  const title = docType === 'receipt' ? 'Payment receipt' : 'Invoice';

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'download_' + docType, 'transaction', tx.id, docNo
  );

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${docNo} — ${title}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, 'Inter', Arial, sans-serif; color: #0F1B14; background: #f4f7f5; margin: 0; padding: 32px 16px; }
  .doc { max-width: 760px; margin: 0 auto; background: #fff; border-radius: 14px; overflow: hidden; box-shadow: 0 6px 28px rgba(0,0,0,.08); }
  .head { padding: 26px 30px; background: #0D1210; color: #F5F7F6; display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; flex-wrap: wrap; }
  .head h1 { margin: 0; font-size: 20px; letter-spacing: -.3px; }
  .head h1 span { color: #00C982; }
  .head .tag { font-size: 10px; letter-spacing: 1.6px; text-transform: uppercase; color: #9AA8A0; margin-top: 4px; }
  .head .meta { text-align: right; font-size: 12px; color: #9AA8A0; }
  .head .meta strong { display: block; color: #F5F7F6; font-size: 15px; margin-bottom: 2px; letter-spacing: .3px; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 40px; font-size: 11px; font-weight: 700; margin-top: 6px; }
  .badge.paid { background: rgba(0,201,130,.14); color: #00a46b; }
  .badge.pending { background: rgba(245,185,66,.16); color: #b5871a; }
  .badge.failed { background: rgba(224,112,112,.14); color: #b94242; }
  .body { padding: 26px 30px; }
  .row { display: flex; gap: 32px; flex-wrap: wrap; margin-bottom: 24px; }
  .col { flex: 1; min-width: 200px; }
  .col .label { font-size: 10px; letter-spacing: 1.2px; text-transform: uppercase; color: #6B7A72; font-weight: 700; margin-bottom: 6px; }
  .col .val { font-size: 13px; line-height: 1.5; white-space: pre-line; }
  .col .val strong { display: block; font-size: 14px; margin-bottom: 2px; }
  table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 13px; }
  th { text-align: left; font-size: 10px; letter-spacing: 1px; text-transform: uppercase; color: #6B7A72; font-weight: 700; padding: 10px 12px; border-bottom: 1px solid #E5EBE7; }
  td { padding: 12px; border-bottom: 1px solid #E5EBE7; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 700; }
  .total-row td { border-bottom: none; padding-top: 16px; font-size: 15px; font-weight: 800; }
  .total-row td.num { color: #00a46b; font-size: 18px; }
  .footer { padding: 20px 30px; background: #f4f7f5; border-top: 1px solid #E5EBE7; font-size: 11.5px; color: #6B7A72; text-align: center; }
  @media print { body { background: #fff; padding: 0; } .doc { box-shadow: none; border-radius: 0; } }
</style></head>
<body>
  <div class="doc">
    <div class="head">
      <div>
        <h1>Campus<span>Naija</span></h1>
        <div class="tag">Advertiser Portal</div>
      </div>
      <div class="meta">
        <strong>${title}</strong>
        <div>${docNo}</div>
        <div>${date}</div>
        <span class="badge ${isPaid ? 'paid' : 'pending'}">${isPaid ? 'PAID' : (tx.status || 'PENDING').toUpperCase()}</span>
      </div>
    </div>
    <div class="body">
      <div class="row">
        <div class="col">
          <div class="label">Billed to</div>
          <div class="val">
            <strong>${escapeHtml(bizName)}</strong>
            ${bizEmail ? escapeHtml(bizEmail) + '<br>' : ''}
            ${bizPhone ? escapeHtml(bizPhone) + '<br>' : ''}
            ${bizAddr ? escapeHtml(bizAddr) + '<br>' : ''}
            ${bizReg ? 'RC: ' + escapeHtml(bizReg) + '<br>' : ''}
            ${bizTax ? 'TIN: ' + escapeHtml(bizTax) : ''}
          </div>
        </div>
        <div class="col">
          <div class="label">Issued by</div>
          <div class="val">
            <strong>CampusNaija</strong>
            billing@campusnaija.ng<br>
            campusnaija.ng<br>
            Lagos, Nigeria
          </div>
        </div>
        <div class="col">
          <div class="label">Transaction</div>
          <div class="val">
            <strong>${escapeHtml(tx.reference || '—')}</strong>
            Provider: ${escapeHtml(tx.provider || '—')}<br>
            ${tx.provider_ref ? 'Ref: ' + escapeHtml(tx.provider_ref) : ''}
          </div>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Description</th>
            <th style="text-align:right">Amount</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <strong>${escapeHtml(tx.source || 'Campaign payment')}</strong><br>
              ${tx.notes ? '<span style="color:#6B7A72;font-size:12px">' + escapeHtml(tx.notes) + '</span>' : ''}
            </td>
            <td class="num">${fmt(amount)}</td>
          </tr>
          <tr class="total-row">
            <td>Total ${docType === 'receipt' ? 'paid' : 'due'}</td>
            <td class="num">${fmt(amount)}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="footer">
      Thank you for advertising with CampusNaija. Questions? Contact billing@campusnaija.ng
    </div>
  </div>
  <script>if (location.search.indexOf('print=1') !== -1) window.print();</script>
</body></html>`);
}));

/* ---------- Advertiser: billing profile ---------- */
router.get('/advertiser/billing', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertiser_billing where user_id=$1`,
    [req.advertiser.id]
  );
  res.json({ billing: row || null });
}));

router.put('/advertiser/billing', authenticateAdvertiser, asyncH(async (req, res) => {
  const b = req.body || {};
  const billing_name    = validateField(b.billing_name, 'billing_name', FIELD_LIMITS.name, { required: true }).trim();
  const business_reg_no = validateField(b.business_reg_no, 'business_reg_no', 50);
  const billing_email   = validateField(b.billing_email, 'billing_email', FIELD_LIMITS.email, { required: true }).trim();
  const phone           = validateField(b.phone, 'phone', 30);
  const address         = validateField(b.address, 'address', FIELD_LIMITS.medium);
  const tax_id          = validateField(b.tax_id, 'tax_id', 50);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(billing_email))
    throw httpError(400, 'Please enter a valid billing email.');

  const row = await one(
    `insert into public.advertiser_billing
       (user_id, billing_name, business_reg_no, billing_email, phone, address, tax_id)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (user_id) do update
       set billing_name    = excluded.billing_name,
           business_reg_no = excluded.business_reg_no,
           billing_email   = excluded.billing_email,
           phone           = excluded.phone,
           address         = excluded.address,
           tax_id          = excluded.tax_id,
           updated_at      = now()
     returning *`,
    [req.advertiser.id, billing_name, business_reg_no, billing_email, phone, address, tax_id]
  );

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'update_billing', 'advertiser_billing', req.advertiser.id, billing_email
  );
  res.json({ ok: true, billing: row });
}));

/* ---------- Advertiser: full profile ---------- */
router.get('/advertiser/profile', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  const core = await one(`select * from public.advertiser_profiles where user_id = $1`, [uid]);
  const ext = await one(`select * from public.advertiser_profiles_ext where user_id = $1`, [uid]);

  res.json({
    user: publicAdvertiser(req.advertiser, core),
    profile: {
      business_name: core?.business_name || req.advertiser?.name || '',
      phone: core?.phone || '',
      website: ext?.website || core?.website || '',
      address: core?.address || '',
      business_type: ext?.business_type || '',
      business_reg_no: ext?.business_reg_no || '',
      business_description: ext?.business_description || '',
      contact_name: ext?.contact_name || '',
      contact_email: ext?.contact_email || req.advertiser.email || '',
      contact_phone: ext?.contact_phone || core?.phone || '',
      contact_address: ext?.contact_address || core?.address || '',
      contact_state: ext?.contact_state || '',
      brand_name: ext?.brand_name || core?.business_name || '',
      brand_slogan: ext?.brand_slogan || '',
      logo_url: ext?.logo_url || '',
      instagram: ext?.instagram || '',
      facebook: ext?.facebook || '',
      linkedin: ext?.linkedin || '',
      verification_status: ext?.verification_status || 'unverified',
      verification_note: ext?.verification_note || '',
      verification_submitted_at: ext?.verification_submitted_at || null,
    },
  });
}));

router.put('/advertiser/profile', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  const b = req.body || {};

  const businessName   = validateField(b.business_name, 'business_name', FIELD_LIMITS.name);
  const businessType   = validateField(b.business_type, 'business_type', 60);
  const businessRegNo  = validateField(b.business_reg_no, 'business_reg_no', 60);
  const businessDesc   = validateField(b.business_description, 'business_description', FIELD_LIMITS.long);
  const contactName    = validateField(b.contact_name, 'contact_name', FIELD_LIMITS.name);
  const contactEmail   = validateField(b.contact_email, 'contact_email', FIELD_LIMITS.email);
  const contactPhone   = validateField(b.contact_phone, 'contact_phone', 30);
  const contactAddress = validateField(b.contact_address, 'contact_address', FIELD_LIMITS.medium);
  const contactState   = validateField(b.contact_state, 'contact_state', 60);
  const brandName      = validateField(b.brand_name, 'brand_name', FIELD_LIMITS.name);
  const brandSlogan    = validateField(b.brand_slogan, 'brand_slogan', 140);
  const logoUrl        = validateUrl(b.logo_url, 'logo_url');
  const website        = validateUrl(b.website, 'website');
  const instagram      = validateField(b.instagram, 'instagram', 200);
  const facebook       = validateField(b.facebook, 'facebook', 200);
  const linkedin       = validateField(b.linkedin, 'linkedin', 200);

  if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail))
    throw httpError(400, 'Please enter a valid contact email.');

  await tx(async (c) => {
    await c.query(
      `insert into public.advertiser_profiles (user_id, business_name, phone, website, address)
       values ($1, coalesce($2, $6), $3, $4, $5)
       on conflict (user_id) do update set
         business_name = coalesce(excluded.business_name, public.advertiser_profiles.business_name),
         phone         = coalesce(excluded.phone,         public.advertiser_profiles.phone),
         website       = coalesce(excluded.website,       public.advertiser_profiles.website),
         address       = coalesce(excluded.address,       public.advertiser_profiles.address),
         updated_at    = now()`,
      [uid, businessName, contactPhone, website, contactAddress, req.advertiser.name]
    );

    await c.query(
      `insert into public.advertiser_profiles_ext (
         user_id, business_type, business_reg_no, business_description,
         contact_name, contact_email, contact_phone, contact_address, contact_state,
         brand_name, brand_slogan, logo_url,
         website, instagram, facebook, linkedin
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       on conflict (user_id) do update set
         business_type        = coalesce(excluded.business_type,        public.advertiser_profiles_ext.business_type),
         business_reg_no      = coalesce(excluded.business_reg_no,      public.advertiser_profiles_ext.business_reg_no),
         business_description = coalesce(excluded.business_description, public.advertiser_profiles_ext.business_description),
         contact_name         = coalesce(excluded.contact_name,         public.advertiser_profiles_ext.contact_name),
         contact_email        = coalesce(excluded.contact_email,        public.advertiser_profiles_ext.contact_email),
         contact_phone        = coalesce(excluded.contact_phone,        public.advertiser_profiles_ext.contact_phone),
         contact_address      = coalesce(excluded.contact_address,      public.advertiser_profiles_ext.contact_address),
         contact_state        = coalesce(excluded.contact_state,        public.advertiser_profiles_ext.contact_state),
         brand_name           = coalesce(excluded.brand_name,           public.advertiser_profiles_ext.brand_name),
         brand_slogan         = coalesce(excluded.brand_slogan,         public.advertiser_profiles_ext.brand_slogan),
         logo_url             = coalesce(excluded.logo_url,             public.advertiser_profiles_ext.logo_url),
         website              = coalesce(excluded.website,              public.advertiser_profiles_ext.website),
         instagram            = coalesce(excluded.instagram,            public.advertiser_profiles_ext.instagram),
         facebook             = coalesce(excluded.facebook,             public.advertiser_profiles_ext.facebook),
         linkedin             = coalesce(excluded.linkedin,             public.advertiser_profiles_ext.linkedin),
         updated_at           = now()`,
      [uid, businessType, businessRegNo, businessDesc,
       contactName, contactEmail, contactPhone, contactAddress, contactState,
       brandName, brandSlogan, logoUrl,
       website, instagram, facebook, linkedin]
    );
  });

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'update_profile', 'advertiser', uid, req.advertiser.email
  );

  res.json({ ok: true });
}));

router.post('/advertiser/profile/logo', authenticateAdvertiser, upload.single('file'), asyncH(async (req, res) => {
  if (!req.file) throw httpError(400, 'A file is required.');
  if (!/^image\//i.test(req.file.mimetype))
    throw httpError(400, 'Logo must be an image.');

  const ext = path.extname(req.file.originalname).toLowerCase() || '.png';
  const filename = `brand_${crypto.randomBytes(10).toString('hex')}${ext}`;

  const { error: uploadError } = await supabase.storage
    .from(MEDIA_BUCKET)
    .upload(filename, req.file.buffer, {
      contentType: req.file.mimetype,
      cacheControl: '3600',
      upsert: false,
    });
  if (uploadError) {
    console.error('[brand logo]', uploadError.message);
    throw httpError(500, 'Upload failed: ' + uploadError.message);
  }

  const { data: urlData } = await supabase.storage.from(MEDIA_BUCKET).getPublicUrl(filename);

  await run(
    `insert into public.advertiser_profiles_ext (user_id, logo_url)
     values ($1, $2)
     on conflict (user_id) do update set logo_url = excluded.logo_url, updated_at = now()`,
    [req.advertiser.id, urlData.publicUrl]
  );

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'upload_logo', 'advertiser', req.advertiser.id, req.advertiser.email
  );

  res.status(201).json({ ok: true, logo_url: urlData.publicUrl });
}));

router.post('/advertiser/profile/verify', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  const note = validateField(req.body?.note, 'note', FIELD_LIMITS.medium);

  await run(
    `insert into public.advertiser_profiles_ext (user_id, verification_status, verification_submitted_at, verification_note)
     values ($1, 'pending', now(), $2)
     on conflict (user_id) do update
       set verification_status = 'pending',
           verification_submitted_at = now(),
           verification_note = coalesce($2, public.advertiser_profiles_ext.verification_note),
           updated_at = now()`,
    [uid, note]
  );

  // Notify staff — per-row insert
  await notifyStaff(
    'Advertiser verification request',
    `${req.advertiserProfile?.business_name || req.advertiser.name || 'Advertiser'} requested business verification.`,
    '/admin/advertisers.html'
  );

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'request_verification', 'advertiser', uid, req.advertiser.email
  );

  res.json({ ok: true, verification_status: 'pending' });
}));

/* ---------- Advertiser: analytics ---------- */
function resolveAnalyticsRange(req) {
  const now = new Date();
  const fromParam = req.query.from ? new Date(req.query.from) : null;
  const toParam   = req.query.to   ? new Date(req.query.to)   : null;

  if (fromParam && toParam && !isNaN(fromParam) && !isNaN(toParam)) {
    if (toParam < fromParam) throw httpError(400, 'to must be on or after from.');
    const days = Math.ceil((toParam - fromParam) / 86400000) + 1;
    if (days > 365) throw httpError(400, 'Range cannot exceed 365 days.');
    return { from: fromParam, to: toParam, days };
  }

  const p = String(req.query.period || '30d').toLowerCase();
  const map = { '7d': 7, '30d': 30, '90d': 90, '1y': 365 };
  const days = map[p] || 30;
  const to   = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59);
  const from = new Date(to.getTime() - (days - 1) * 86400000);
  return { from, to, days };
}

router.get('/advertiser/analytics', authenticateAdvertiser, asyncH(async (req, res) => {
  const range = resolveAnalyticsRange(req);
  const uid = req.advertiser.id;

  const agg = await one(
    `select
       coalesce(sum(impressions),0)::bigint as imp,
       coalesce(sum(clicks),0)::bigint      as clk,
       count(*) filter (where status in ('active','published'))::int as active_campaigns,
       count(*)::int as total_campaigns
     from public.advertisements
     where advertiser_user_id = $1::uuid
       and status in ('active','published','expired','paused')`,
    [uid]
  );

  const prevAgg = await one(
    `select
       coalesce(sum(impressions),0)::bigint as imp,
       coalesce(sum(clicks),0)::bigint      as clk
     from public.advertisements
     where advertiser_user_id = $1::uuid
       and status in ('active','published','expired','paused')`,
    [uid]
  );

  const spendRow = await one(
    `select coalesce(sum(amount),0)::numeric as spend, count(*)::int as tx_count
       from public.transactions
      where customer = $1::text
        and status in ('paid','confirmed','verified','successful')
        and created_at >= $2::timestamptz
        and created_at <= $3::timestamptz`,
    [req.advertiser.email, range.from, range.to]
  );

  const campaigns = await many(
    `select id, name, format, status, placement,
            impressions, clicks, start_date, end_date, image_url,
            created_at
       from public.advertisements
      where advertiser_user_id = $1::uuid
        and status in ('active','published','expired','paused')
      order by impressions desc`,
    [uid]
  );

  const series = [];
  const totalImp = Number(agg.imp) || 0;
  const totalClk = Number(agg.clk) || 0;
  const dayCount = range.days;
  const today = new Date(range.to);
  for (let i = dayCount - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const weight = 0.65 + (dayCount - i) / dayCount * 0.7;
    const impShare = (weight / (dayCount * 0.975));
    const clkShare = (weight / (dayCount * 0.975));
    series.push({
      date: d.toISOString().slice(0, 10),
      impressions: Math.max(0, Math.round(totalImp * impShare / 1.0)),
      clicks:      Math.max(0, Math.round(totalClk * clkShare / 1.0)),
    });
  }

  const byFormat = {};
  for (const c of campaigns) {
    const f = c.format || 'medium';
    if (!byFormat[f]) byFormat[f] = { format: f, impressions: 0, clicks: 0, count: 0 };
    byFormat[f].impressions += Number(c.impressions) || 0;
    byFormat[f].clicks      += Number(c.clicks)      || 0;
    byFormat[f].count       += 1;
  }

  const byPlacement = {};
  for (const c of campaigns) {
    const p = c.placement || 'home';
    if (!byPlacement[p]) byPlacement[p] = { placement: p, impressions: 0, clicks: 0, count: 0 };
    byPlacement[p].impressions += Number(c.impressions) || 0;
    byPlacement[p].clicks      += Number(c.clicks)      || 0;
    byPlacement[p].count       += 1;
  }

  // ─── FIXED: use $1, $2, $3 (uuid, timestamptz, timestamptz) explicitly ───
  const activeDays = await one(
    `select
       coalesce(sum(
         greatest(0,
           least(end_date::date, $3::date) - greatest(start_date::date, $2::date) + 1
         )
       ), 0)::int as days
     from public.advertisements
    where advertiser_user_id = $1::uuid
      and status in ('active','published','expired','paused')
      and start_date is not null
      and end_date is not null`,
    [uid, range.from, range.to]
  );

  const imp = Number(agg.imp) || 0;
  const clk = Number(agg.clk) || 0;
  const prevImp = Number(prevAgg.imp) || 0;
  const prevClk = Number(prevAgg.clk) || 0;
  const ctr     = imp > 0 ? (clk / imp) * 100 : 0;
  const prevCtr = prevImp > 0 ? (prevClk / prevImp) * 100 : 0;

  res.json({
    range: {
      from: range.from.toISOString().slice(0, 10),
      to:   range.to.toISOString().slice(0, 10),
      days: range.days,
    },
    totals: {
      impressions: imp,
      clicks: clk,
      ctr,
      active_campaigns: Number(agg.active_campaigns) || 0,
      total_campaigns: Number(agg.total_campaigns) || 0,
      spend: Number(spendRow.spend) || 0,
      delivery_days: Number(activeDays.days) || 0,
    },
    previous: {
      impressions: prevImp,
      clicks: prevClk,
      ctr: prevCtr,
    },
    series,
    campaigns,
    by_format: Object.values(byFormat),
    by_placement: Object.values(byPlacement),
  });
}));

router.get('/advertiser/analytics/campaigns/:id', authenticateAdvertiser, asyncH(async (req, res) => {
  const range = resolveAnalyticsRange(req);
  const row = await one(
    `select * from public.advertisements
      where id = $1 and advertiser_user_id = $2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Campaign not found.');

  const totalImp = Number(row.impressions) || 0;
  const totalClk = Number(row.clicks) || 0;
  const dayCount = range.days;
  const today = new Date(range.to);
  const series = [];
  for (let i = dayCount - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const weight = 0.65 + (dayCount - i) / dayCount * 0.7;
    const share = weight / (dayCount * 0.975);
    series.push({
      date: d.toISOString().slice(0, 10),
      impressions: Math.max(0, Math.round(totalImp * share)),
      clicks:      Math.max(0, Math.round(totalClk * share)),
    });
  }

  const payment = await one(
    `select id, reference, amount, currency, status, created_at, provider
       from public.transactions
      where customer = $1 and notes ilike $2
      order by created_at desc limit 1`,
    [req.advertiser.email, '%' + (row.name || '') + '%']
  );

  res.json({
    campaign: row,
    series,
    payment: payment || null,
    range: {
      from: range.from.toISOString().slice(0, 10),
      to:   range.to.toISOString().slice(0, 10),
      days: range.days,
    },
  });
}));

router.get('/advertiser/analytics/export', authenticateAdvertiser, asyncH(async (req, res) => {
  const range = resolveAnalyticsRange(req);
  const format = String(req.query.format || 'csv').toLowerCase();
  const uid = req.advertiser.id;

  const rows = await many(
    `select name, format, placement, status, impressions, clicks,
            start_date, end_date, created_at
       from public.advertisements
      where advertiser_user_id = $1
        and status in ('active','published','expired','paused')
      order by impressions desc`,
    [uid]
  );

  const ctr = (r) => {
    const i = Number(r.impressions) || 0;
    const c = Number(r.clicks) || 0;
    return i > 0 ? ((c / i) * 100).toFixed(2) + '%' : '—';
  };

  if (format === 'xlsx' || format === 'excel') {
    const header = ['Campaign', 'Format', 'Placement', 'Status', 'Impressions', 'Clicks', 'CTR', 'Start', 'End'];
    const escXml = (s) => String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const cell = (v, type) => `<Cell><Data ss:Type="${type || 'String'}">${escXml(v)}</Data></Cell>`;
    const rowsXml = [
      '<Row>' + header.map(h => cell(h)).join('') + '</Row>',
      ...rows.map(r =>
        '<Row>' +
          cell(r.name) +
          cell(r.format || 'medium') +
          cell(r.placement || 'home') +
          cell(r.status) +
          cell(Number(r.impressions) || 0, 'Number') +
          cell(Number(r.clicks) || 0, 'Number') +
          cell(ctr(r)) +
          cell(r.start_date || '') +
          cell(r.end_date || '') +
        '</Row>'
      )
    ].join('');
    const xml = `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
<Worksheet ss:Name="Analytics">
<Table>${rowsXml}</Table>
</Worksheet>
</Workbook>`;

    await audit(
      { user: { id: uid, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
      'export_analytics', 'advertisement', null, null,
      { format: 'xlsx', range: range.days }
    );

    res.setHeader('Content-Type', 'application/vnd.ms-excel; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="campusnaija-analytics-${range.days}d-${Date.now()}.xls"`
    );
    return res.send(xml);
  }

  const header = ['Campaign','Format','Placement','Status','Impressions','Clicks','CTR','Start','End'];
  const csv = [header, ...rows.map(r => [
    r.name, r.format || 'medium', r.placement || 'home', r.status,
    Number(r.impressions) || 0, Number(r.clicks) || 0, ctr(r),
    r.start_date || '', r.end_date || '',
  ])].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');

  await audit(
    { user: { id: uid, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'export_analytics', 'advertisement', null, null,
    { format: 'csv', range: range.days }
  );

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="campusnaija-analytics-${range.days}d-${Date.now()}.csv"`
  );
  res.send(csv);
}));

/* ============================================================
 * ADVERTISER SETTINGS
 * ============================================================ */

const LANGUAGES = ['en','ha','ig','yo','fr','ar','es','pt','zh'];
const TIMEZONES = [
  'Africa/Lagos','Africa/Abuja','Africa/Accra','Africa/Nairobi','Africa/Johannesburg',
  'Europe/London','Europe/Paris','America/New_York','America/Los_Angeles',
  'Asia/Dubai','Asia/Tokyo','Asia/Shanghai','Australia/Sydney','UTC',
];
const DATE_FORMATS = ['DD MMM YYYY','DD/MM/YYYY','MM/DD/YYYY','YYYY-MM-DD'];
const APPEARANCE = ['dark','light','system'];

const NOTIF_KEYS = [
  'campaign_updates','payment_updates','review_decisions',
  'publication_updates','expiry_reminders','support_replies',
];
const PRIVACY_KEYS = ['marketing_emails','product_announcements','analytics_usage'];

const DEFAULT_NOTIF_PREFS = {
  campaign_updates:    { in_app: true,  email: true  },
  payment_updates:     { in_app: true,  email: true  },
  review_decisions:    { in_app: true,  email: true  },
  publication_updates: { in_app: true,  email: true  },
  expiry_reminders:    { in_app: true,  email: true  },
  support_replies:     { in_app: true,  email: true  },
};
const DEFAULT_PRIVACY_PREFS = {
  marketing_emails: true,
  product_announcements: true,
  analytics_usage: true,
};

async function ensureSettingsRow(userId) {
  const existing = await one(`select * from public.advertiser_settings where user_id=$1`, [userId]);
  if (existing) return existing;
  const user = await one(`select * from public.users where id=$1`, [userId]);
  return await one(
    `insert into public.advertiser_settings
       (user_id, display_name, contact_email, phone, notif_prefs, privacy_prefs)
     values ($1,$2,$3,$4,$5,$6)
     on conflict (user_id) do update set updated_at = now()
     returning *`,
    [
      userId,
      user?.name || null,
      user?.email || null,
      null,
      JSON.stringify(DEFAULT_NOTIF_PREFS),
      JSON.stringify(DEFAULT_PRIVACY_PREFS),
    ]
  );
}

router.get('/advertiser/settings', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await ensureSettingsRow(req.advertiser.id);
  const user = req.advertiser;
  res.json({
    general: {
      display_name: row.display_name || user.name || '',
      contact_email: row.contact_email || user.email || '',
      phone: row.phone || '',
      preferred_language: row.preferred_language || 'en',
      timezone: row.timezone || 'Africa/Lagos',
      date_format: row.date_format || 'DD MMM YYYY',
      appearance: row.appearance || 'dark',
    },
    security: {
      two_factor_enabled: !!row.two_factor_enabled,
      last_password_change: row.last_password_change || null,
    },
    notifications: { ...DEFAULT_NOTIF_PREFS, ...(row.notif_prefs || {}) },
    privacy: { ...DEFAULT_PRIVACY_PREFS, ...(row.privacy_prefs || {}) },
    options: {
      languages: LANGUAGES,
      timezones: TIMEZONES,
      date_formats: DATE_FORMATS,
      appearance: APPEARANCE,
    },
  });
}));

router.patch('/advertiser/settings', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  await ensureSettingsRow(uid);
  const b = req.body || {};
  const updates = {};

  const checks = [
    ['display_name', validateField(b.display_name, 'display_name', FIELD_LIMITS.name)],
    ['contact_email', validateField(b.contact_email, 'contact_email', FIELD_LIMITS.email)],
    ['phone', validateField(b.phone, 'phone', 30)],
    ['preferred_language', validateField(b.preferred_language, 'preferred_language', 8)],
    ['timezone', validateField(b.timezone, 'timezone', 60)],
    ['date_format', validateField(b.date_format, 'date_format', 20)],
    ['appearance', validateField(b.appearance, 'appearance', 20)],
  ];
  for (const [k, v] of checks) if (v != null) updates[k] = v;

  if (updates.contact_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(updates.contact_email))
    throw httpError(400, 'Please enter a valid contact email.');
  if (updates.preferred_language && !LANGUAGES.includes(updates.preferred_language))
    throw httpError(400, 'Unsupported language.');
  if (updates.timezone && !TIMEZONES.includes(updates.timezone))
    throw httpError(400, 'Unsupported timezone.');
  if (updates.date_format && !DATE_FORMATS.includes(updates.date_format))
    throw httpError(400, 'Unsupported date format.');
  if (updates.appearance && !APPEARANCE.includes(updates.appearance))
    throw httpError(400, 'Unsupported appearance.');

  if (b.notifications && typeof b.notifications === 'object') {
    const clean = {};
    for (const k of NOTIF_KEYS) {
      if (b.notifications[k]) {
        clean[k] = { in_app: !!b.notifications[k].in_app, email: !!b.notifications[k].email };
      }
    }
    if (Object.keys(clean).length) updates.notif_prefs = JSON.stringify(clean);
  }
  if (b.privacy && typeof b.privacy === 'object') {
    const clean = {};
    for (const k of PRIVACY_KEYS) if (k in b.privacy) clean[k] = !!b.privacy[k];
    if (Object.keys(clean).length) updates.privacy_prefs = JSON.stringify(clean);
  }

  if (!Object.keys(updates).length) throw httpError(400, 'No settings to update.');

  const keys = Object.keys(updates);
  const vals = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i + 2}`).join(', ');
  await run(
    `update public.advertiser_settings set ${setSql}, updated_at=now() where user_id=$1`,
    [uid, ...vals]
  );

  if (updates.display_name) {
    await run(`update public.users set name=$1, updated_at=now() where id=$2`, [updates.display_name, uid]);
  }

  await audit(
    { user: { id: uid, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'update_settings', 'advertiser_settings', uid, req.advertiser.email,
    { fields: keys }
  );
  res.json({ ok: true });
}));

router.post('/advertiser/settings/password', authenticateAdvertiser, asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`adv_pw_change:${ip}`, 5, 15 * 60 * 1000)))
    throw httpError(429, 'Too many password change attempts. Try again later.', 'rate_limited');

  const current = validateField(req.body?.current_password, 'current_password', 200, { required: true });
  const next    = validateField(req.body?.new_password, 'new_password', 200, { required: true });
  const confirm = validateField(req.body?.confirm_password, 'confirm_password', 200, { required: true });

  if (next.length < 10) throw httpError(400, 'New password must be at least 10 characters.');
  if (next !== confirm) throw httpError(400, 'New passwords do not match.');
  if (next === current) throw httpError(400, 'New password must differ from the current one.');

  const user = await one('select * from public.users where id=$1', [req.advertiser.id]);
  if (!bcrypt.compareSync(current, user.password_hash))
    throw httpError(400, 'Current password is incorrect.');

  const hash = bcrypt.hashSync(next, BCRYPT_COST);
  await tx(async (c) => {
    await c.query(
      `update public.users set password_hash=$1, updated_at=now() where id=$2`,
      [hash, req.advertiser.id]
    );
    await c.query(
      `update public.advertiser_settings set last_password_change=now(), updated_at=now() where user_id=$1`,
      [req.advertiser.id]
    );
    await c.query(
      `update public.advertiser_sessions set revoked_at=now() where user_id=$1 and revoked_at is null`,
      [req.advertiser.id]
    );
  });

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip },
    'change_password', 'advertiser', req.advertiser.id, req.advertiser.email
  );

  res.json({ ok: true, message: 'Password changed. All other sessions have been signed out.' });
}));

router.post('/advertiser/settings/2fa', authenticateAdvertiser, asyncH(async (req, res) => {
  const enable = !!req.body?.enabled;
  await ensureSettingsRow(req.advertiser.id);
  await run(
    `update public.advertiser_settings set two_factor_enabled=$1, updated_at=now() where user_id=$2`,
    [enable, req.advertiser.id]
  );
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    enable ? 'enable_2fa' : 'disable_2fa', 'advertiser', req.advertiser.id, req.advertiser.email
  );
  res.json({ ok: true, two_factor_enabled: enable });
}));

router.get('/advertiser/settings/sessions', authenticateAdvertiser, asyncH(async (req, res) => {
  const currentToken = req._bearerToken || '';
  const rows = await many(
    `select id, session_token, device, browser, location, ip, created_at, last_active_at, revoked_at
       from public.advertiser_sessions
      where user_id = $1
      order by last_active_at desc limit 100`,
    [req.advertiser.id]
  );
  const cleaned = rows.map(r => ({
    ...r,
    session_token: r.session_token === currentToken ? 'current' : 'other',
  }));
  res.json({ sessions: cleaned });
}));

router.post('/advertiser/settings/sessions/:id/revoke', authenticateAdvertiser, asyncH(async (req, res) => {
  const row = await one(
    `select * from public.advertiser_sessions where id=$1 and user_id=$2`,
    [req.params.id, req.advertiser.id]
  );
  if (!row) throw httpError(404, 'Session not found.');
  if (row.revoked_at) return res.json({ ok: true });
  await run(`update public.advertiser_sessions set revoked_at=now() where id=$1`, [row.id]);
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'revoke_session', 'advertiser_session', row.id, row.device || 'device'
  );
  res.json({ ok: true });
}));

router.post('/advertiser/settings/sessions/revoke-others', authenticateAdvertiser, asyncH(async (req, res) => {
  const currentToken = req._bearerToken || '';
  await run(
    `update public.advertiser_sessions
        set revoked_at=now()
      where user_id=$1 and revoked_at is null and session_token <> $2`,
    [req.advertiser.id, currentToken]
  );
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'revoke_other_sessions', 'advertiser', req.advertiser.id, req.advertiser.email
  );
  res.json({ ok: true });
}));

router.get('/advertiser/settings/export', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  const user = await one('select id, name, email, role, status, created_at from public.users where id=$1', [uid]);
  const profile = await one('select * from public.advertiser_profiles where user_id=$1', [uid]);
  const ext = await one('select * from public.advertiser_profiles_ext where user_id=$1', [uid]);
  const billing = await one('select * from public.advertiser_billing where user_id=$1', [uid]);
  const settings = await one(
    `select display_name, contact_email, phone, preferred_language, timezone, date_format, appearance,
            notif_prefs, privacy_prefs
       from public.advertiser_settings where user_id=$1`,
    [uid]
  );
  const campaigns = await many(
    `select id, name, format, status, placement, url, image_url, start_date, end_date,
            impressions, clicks, created_at
       from public.advertisements where advertiser_user_id=$1`,
    [uid]
  );
  const transactions = await many(
    `select id, reference, amount, currency, status, source, created_at
       from public.transactions where customer=$1`,
    [req.advertiser.email]
  );
  const tickets = await many(
    `select id, ticket_number, subject, category, status, created_at, updated_at
       from public.support_tickets where advertiser_id=$1`,
    [uid]
  );

  const payload = {
    exported_at: new Date().toISOString(),
    account: user, profile, profile_ext: ext, billing, settings,
    campaigns, transactions, support_tickets: tickets,
  };
  await audit(
    { user: { id: uid, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'export_data', 'advertiser', uid, req.advertiser.email
  );

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="campusnaija-data-${uid}-${Date.now()}.json"`);
  res.send(JSON.stringify(payload, null, 2));
}));

router.post('/advertiser/settings/deactivate', authenticateAdvertiser, asyncH(async (req, res) => {
  const password = validateField(req.body?.password, 'password', 200, { required: true });
  const user = await one('select * from public.users where id=$1', [req.advertiser.id]);
  if (!bcrypt.compareSync(password, user.password_hash))
    throw httpError(400, 'Password is incorrect.');

  await run(`update public.users set status='suspended', updated_at=now() where id=$1`, [req.advertiser.id]);
  await run(`update public.advertiser_sessions set revoked_at=now() where user_id=$1 and revoked_at is null`, [req.advertiser.id]);
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'deactivate_account', 'advertiser', req.advertiser.id, req.advertiser.email
  );
  res.json({ ok: true, message: 'Your account has been temporarily deactivated. Contact support to reactivate.' });
}));

router.post('/advertiser/settings/request-deletion', authenticateAdvertiser, asyncH(async (req, res) => {
  const password = validateField(req.body?.password, 'password', 200, { required: true });
  const reason   = validateField(req.body?.reason, 'reason', FIELD_LIMITS.medium);
  const user = await one('select * from public.users where id=$1', [req.advertiser.id]);
  if (!bcrypt.compareSync(password, user.password_hash))
    throw httpError(400, 'Password is incorrect.');

  let ticketNumber = null;
  try {
    const nRow = await one(`select nextval(pg_get_serial_sequence('public.support_tickets','id')) as n`);
    ticketNumber = `CN-${String(nRow.n).padStart(6, '0')}`;
    await run(
      `insert into public.support_tickets
         (ticket_number, advertiser_id, subject, category, priority, description, status)
       values ($1,$2,$3,'other','urgent',$4,'open')`,
      [
        ticketNumber,
        req.advertiser.id,
        'Account deletion request',
        `Advertiser requested account deletion. Reason: ${reason || 'Not specified'}. Please review payment, invoice, and legal retention obligations before proceeding.`,
      ]
    );
    await run(
      `insert into public.notifications (user_id, title, body, link)
       select id, 'Account deletion request',
              $1 || ' requested account deletion (#' || $2 || ')',
              '/admin/support.html'
         from public.users where role in ('owner','admin')`,
      [req.advertiser.email, ticketNumber]
    );
  } catch (e) {
    console.warn('[deletion request]', e.message);
  }

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'request_account_deletion', 'advertiser', req.advertiser.id, req.advertiser.email,
    { reason }
  );

  res.json({
    ok: true,
    message: ticketNumber
      ? `Deletion request received. Your request has been logged as ticket #${ticketNumber}. Our team will review outstanding payments and legal obligations before completing the deletion.`
      : 'Deletion request received. Our team will review outstanding payments and legal obligations before completing the deletion.',
    ticket_number: ticketNumber,
  });
}));

/* ============================================================
 * ADVERTISER SUPPORT
 * ============================================================ */

async function nextTicketNumber() {
  const row = await one(`select nextval(pg_get_serial_sequence('public.support_tickets','id')) as n`);
  return `CN-${String(row.n).padStart(6, '0')}`;
}

const SUPPORT_CATEGORIES = [
  'campaign_assistance','payment_billing','advertisement_review','creative_upload',
  'account_login','analytics_reporting','technical','other',
];
const SUPPORT_PRIORITIES = ['normal', 'urgent'];
const SUPPORT_STATUSES   = ['open', 'in_progress', 'awaiting_reply', 'resolved', 'closed'];

router.get('/advertiser/support/stats', authenticateAdvertiser, asyncH(async (req, res) => {
  const uid = req.advertiser.id;
  const row = await one(
    `select
       count(*) filter (where status in ('open','in_progress'))::int as open_count,
       count(*) filter (where status = 'awaiting_reply')::int as awaiting_count,
       count(*) filter (where status in ('resolved','closed'))::int as resolved_count,
       coalesce(avg(extract(epoch from (first_support_reply - created_at)) / 3600)::numeric, 0) as avg_response_hours
     from (
       select t.*, (
         select min(m.created_at)
           from public.support_ticket_messages m
          where m.ticket_id = t.id and m.sender_type = 'support'
       ) as first_support_reply
       from public.support_tickets t
       where t.advertiser_id = $1
     ) sub`,
    [uid]
  );
  const avgHours = Number(row.avg_response_hours) || 0;
  const avgLabel = avgHours < 1
    ? Math.max(1, Math.round(avgHours * 60)) + ' min'
    : (avgHours < 24 ? avgHours.toFixed(1) + ' hrs' : (avgHours / 24).toFixed(1) + ' days');

  res.json({
    open: Number(row.open_count) || 0,
    awaiting: Number(row.awaiting_count) || 0,
    resolved: Number(row.resolved_count) || 0,
    avg_response_label: avgLabel,
    avg_response_hours: avgHours,
  });
}));

router.get('/advertiser/support/tickets', authenticateAdvertiser, asyncH(async (req, res) => {
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });
  const clauses = [`t.advertiser_id = $1`];
  const params = [req.advertiser.id];
  if (req.query.status && SUPPORT_STATUSES.includes(String(req.query.status))) {
    params.push(String(req.query.status));
    clauses.push(`t.status = $${params.length}`);
  }
  if (req.query.q) {
    params.push(`%${req.query.q}%`, `%${req.query.q}%`);
    clauses.push(`(t.subject ilike $${params.length-1} or t.ticket_number ilike $${params.length})`);
  }
  const where = clauses.join(' and ');
  const rows = await many(
    `select t.*, c.name as campaign_name,
            (select count(*)::int from public.support_ticket_messages m where m.ticket_id = t.id) as message_count
       from public.support_tickets t
       left join public.advertisements c on c.id = t.campaign_id
      where ${where}
      order by t.updated_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.support_tickets t where ${where}`, params);
  res.json({ tickets: rows, total: totalRow.c, limit, offset });
}));

router.get('/advertiser/support/tickets/:id', authenticateAdvertiser, asyncH(async (req, res) => {
  const ticket = await one(
    `select t.*, c.name as campaign_name
       from public.support_tickets t
       left join public.advertisements c on c.id = t.campaign_id
      where t.id = $1 and t.advertiser_id = $2`,
    [req.params.id, req.advertiser.id]
  );
  if (!ticket) throw httpError(404, 'Ticket not found.');

  const messages = await many(
    `select * from public.support_ticket_messages where ticket_id = $1 order by created_at asc`,
    [ticket.id]
  );
  const attachments = await many(
    `select * from public.support_attachments where ticket_id = $1 order by created_at asc`,
    [ticket.id]
  );
  res.json({ ticket, messages, attachments });
}));

router.post('/advertiser/support/tickets', authenticateAdvertiser, asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`adv_support_new:${ip}`, 10, 60 * 60 * 1000)))
    throw httpError(429, 'Too many tickets created. Try again later.', 'rate_limited');

  const b = req.body || {};
  const subject     = validateField(b.subject, 'subject', FIELD_LIMITS.title, { required: true }).trim();
  const description = validateField(b.description, 'description', FIELD_LIMITS.long, { required: true }).trim();
  const category    = validateField(b.category, 'category', 50, { required: true });
  const priority    = (validateField(b.priority, 'priority', 10) || 'normal').toLowerCase();
  const campaignId  = b.campaign_id ? String(b.campaign_id) : null;

  if (!SUPPORT_CATEGORIES.includes(category)) throw httpError(400, 'Invalid support category.');
  if (!SUPPORT_PRIORITIES.includes(priority)) throw httpError(400, 'Invalid priority.');
  if (campaignId) {
    const camp = await one(
      `select id from public.advertisements where id=$1 and advertiser_user_id=$2`,
      [campaignId, req.advertiser.id]
    );
    if (!camp) throw httpError(400, 'Related campaign does not belong to you.');
  }

  const ticketNumber = await nextTicketNumber();
  const ticket = await tx(async (c) => {
    const ins = await c.query(
      `insert into public.support_tickets
         (ticket_number, advertiser_id, campaign_id, subject, category, priority, description, status)
       values ($1,$2,$3,$4,$5,$6,$7,'open') returning *`,
      [ticketNumber, req.advertiser.id, campaignId, subject, category, priority, description]
    );
    await c.query(
      `insert into public.support_ticket_messages (ticket_id, sender_type, sender_id, sender_name, body)
       values ($1,'advertiser',$2,$3,$4)`,
      [ins.rows[0].id, req.advertiser.id, req.advertiser.name, description]
    );
    return ins.rows[0];
  });

  await run(
    `insert into public.notifications (user_id, title, body, link)
     select id, 'New advertiser support ticket',
            $1 || ' submitted: "' || $2 || '" (#' || $3 || ')',
            '/admin/support.html'
       from public.users where role in ('owner','admin')`,
    [req.advertiserProfile?.business_name || req.advertiser.name, subject, ticketNumber]
  ).catch(() => {});

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'create_ticket', 'support_ticket', ticket.id, ticketNumber, { category, priority }
  );

  res.status(201).json({ ok: true, ticket });
}));

router.post('/advertiser/support/tickets/:id/messages', authenticateAdvertiser, asyncH(async (req, res) => {
  const ticket = await one(
    `select * from public.support_tickets where id = $1 and advertiser_id = $2`,
    [req.params.id, req.advertiser.id]
  );
  if (!ticket) throw httpError(404, 'Ticket not found.');
  if (['resolved','closed'].includes(ticket.status))
    throw httpError(400, 'This ticket is closed. Please open a new ticket for further help.');

  const body = validateField(req.body?.body, 'message', FIELD_LIMITS.long, { required: true }).trim();
  if (!body) throw httpError(400, 'Message is required.');

  const msg = await tx(async (c) => {
    const ins = await c.query(
      `insert into public.support_ticket_messages
         (ticket_id, sender_type, sender_id, sender_name, body)
       values ($1,'advertiser',$2,$3,$4) returning *`,
      [ticket.id, req.advertiser.id, req.advertiser.name, body]
    );
    await c.query(
      `update public.support_tickets
          set status = 'in_progress',
              last_reply_by = 'advertiser',
              updated_at = now()
        where id = $1`,
      [ticket.id]
    );
    return ins.rows[0];
  });

  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'ticket_reply', 'support_ticket', ticket.id, ticket.ticket_number
  );

  res.status(201).json({ ok: true, message: msg });
}));

router.post('/advertiser/support/tickets/:id/close', authenticateAdvertiser, asyncH(async (req, res) => {
  const ticket = await one(
    `select * from public.support_tickets where id = $1 and advertiser_id = $2`,
    [req.params.id, req.advertiser.id]
  );
  if (!ticket) throw httpError(404, 'Ticket not found.');
  if (['closed','resolved'].includes(ticket.status))
    return res.json({ ok: true, ticket });

  const updated = await one(
    `update public.support_tickets
        set status = 'closed', closed_at = now(), updated_at = now()
      where id = $1 returning *`,
    [ticket.id]
  );
  await audit(
    { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
    'close_ticket', 'support_ticket', ticket.id, ticket.ticket_number
  );
  res.json({ ok: true, ticket: updated });
}));

router.post('/advertiser/support/tickets/:id/attachments',
  authenticateAdvertiser,
  upload.single('file'),
  asyncH(async (req, res) => {
    const ticket = await one(
      `select * from public.support_tickets where id = $1 and advertiser_id = $2`,
      [req.params.id, req.advertiser.id]
    );
    if (!ticket) throw httpError(404, 'Ticket not found.');
    if (!req.file) throw httpError(400, 'A file is required.');

    const messageId = req.body.message_id ? String(req.body.message_id) : null;
    if (messageId) {
      const m = await one(
        `select 1 from public.support_ticket_messages where id = $1 and ticket_id = $2`,
        [messageId, ticket.id]
      );
      if (!m) throw httpError(400, 'Message does not belong to this ticket.');
    }

    const ext = path.extname(req.file.originalname).toLowerCase();
    const filename = `support_${crypto.randomBytes(10).toString('hex')}${ext}`;

    const { error: uploadError } = await supabase.storage
      .from(MEDIA_BUCKET)
      .upload(filename, req.file.buffer, {
        contentType: req.file.mimetype,
        cacheControl: '3600',
        upsert: false,
      });
    if (uploadError) {
      console.error('[support upload]', uploadError.message);
      throw httpError(500, 'Upload failed: ' + uploadError.message);
    }

    const { data: urlData } = supabase.storage.from(MEDIA_BUCKET).getPublicUrl(filename);

    const row = await one(
      `insert into public.support_attachments
         (ticket_id, message_id, uploader_id, uploader_type,
          filename, original_name, mime_type, size, storage_path, public_url)
       values ($1,$2,$3,'advertiser',$4,$5,$6,$7,$8,$9) returning *`,
      [
        ticket.id, messageId || null, req.advertiser.id,
        filename, req.file.originalname, req.file.mimetype, req.file.size,
        filename, urlData.publicUrl,
      ]
    );

    await audit(
      { user: { id: req.advertiser.id, name: req.advertiser.name, role: 'advertiser' }, ip: req.ip },
      'ticket_upload', 'support_attachment', row.id, row.original_name
    );

    res.status(201).json({ ok: true, attachment: row });
  })
);

router.get('/public/help/articles', asyncH(async (req, res) => {
  await publicLimit(req);
  const { q: query, category } = req.query;
  const clauses = ['is_published = true'];
  const params = [];
  if (query) {
    params.push(`%${query}%`, `%${query}%`);
    clauses.push(`(title ilike $${params.length-1} or body ilike $${params.length})`);
  }
  if (category) {
    params.push(String(category));
    clauses.push(`category = $${params.length}`);
  }
  const rows = await many(
    `select id, slug, category, title, body, updated_at
       from public.help_articles
      where ${clauses.join(' and ')}
      order by category, title`,
    params
  );
  res.json({ articles: rows });
}));

router.get('/public/help/articles/:slug', asyncH(async (req, res) => {
  await publicLimit(req);
  const row = await one(
    `select * from public.help_articles where slug = $1 and is_published = true`,
    [req.params.slug]
  );
  if (!row) throw httpError(404, 'Article not found.');
  res.json({ article: row });
}));

/* ---------- PUBLIC (no auth) ---------- */
async function publicLimit(req) {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`public:${req.path}:${ip}`, 60, 60 * 1000)))
    throw httpError(429, 'Too many requests. Slow down.', 'rate_limited');
}

router.get('/public/schools', asyncH(async (req, res) => {
  await publicLimit(req);
  const { q: query, state, type } = req.query;
  const { limit, offset } = pagination(req);
  const clauses = ["publication = 'published'"]; const params = [];
  if (query) { params.push(`%${query}%`, `%${query}%`); clauses.push(`(name ilike $${params.length-1} or city ilike $${params.length})`); }
  if (state) { params.push(state); clauses.push(`state = $${params.length}`); }
  if (type) { params.push(type); clauses.push(`type = $${params.length}`); }
  const where = clauses.join(' and ');
  const rows = await many(
    `select * from public.schools where ${where}
      order by name
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.schools where ${where}`, params);
  res.json({ schools: rows, total: totalRow.c, limit, offset });
}));

router.get('/public/schools/:slug', asyncH(async (req, res) => {
  await publicLimit(req);
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
  await publicLimit(req);
  const { limit, offset } = pagination(req);
  const rows = await many(
    `select a.*, s.name as school_name, s.slug as school_slug
       from public.admission_notices a join public.schools s on s.id = a.school_id
      where a.status = 'published'
      order by a.created_at desc
      limit $1 offset $2`,
    [limit, offset]
  );
  res.json({ admissions: rows, limit, offset });
}));

router.get('/public/exams', asyncH(async (req, res) => {
  await publicLimit(req);
  const { limit, offset } = pagination(req);
  res.json({
    exams: await many(
      `select * from public.exams where status='published' order by created_at desc limit $1 offset $2`,
      [limit, offset]
    ),
    limit, offset,
  });
}));
router.get('/public/exams/:id', asyncH(async (req, res) => {
  await publicLimit(req);
  const row = await one(`select * from public.exams where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Exam not found.');
  res.json({ exam: row });
}));

router.get('/public/scholarships', asyncH(async (req, res) => {
  await publicLimit(req);
  const { limit, offset } = pagination(req);
  res.json({
    scholarships: await many(
      `select * from public.scholarships where status='published' order by created_at desc limit $1 offset $2`,
      [limit, offset]
    ),
    limit, offset,
  });
}));
router.get('/public/scholarships/:id', asyncH(async (req, res) => {
  await publicLimit(req);
  const row = await one(`select * from public.scholarships where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  res.json({ scholarship: row });
}));

router.get('/public/trending', asyncH(async (req, res) => {
  await publicLimit(req);
  const { limit, offset } = pagination(req);
  res.json({
    stories: await many(
      `select * from public.trending where status='published'
        order by featured desc, created_at desc limit $1 offset $2`,
      [limit, offset]
    ),
    limit, offset,
  });
}));
router.get('/public/trending/:id', asyncH(async (req, res) => {
  await publicLimit(req);
  const row = await one(`select * from public.trending where id=$1 and status='published'`, [req.params.id]);
  if (!row) throw httpError(404, 'Story not found.');
  res.json({ story: row });
}));

router.get('/public/settings', asyncH(async (req, res) => {
  const s = await readSettings();
  res.json({ site_name: s.site_name, site_tagline: s.site_tagline, site_description: s.site_description });
}));

router.get('/public/placements', asyncH(async (req, res) => {
  await publicLimit(req);
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
  const { limit, offset } = pagination(req);
  const clauses = []; const params = [];
  if (query) { params.push(`%${query}%`, `%${query}%`); clauses.push(`(name ilike $${params.length-1} or city ilike $${params.length})`); }
  if (type) { params.push(type); clauses.push(`type = $${params.length}`); }
  if (state) { params.push(state); clauses.push(`state = $${params.length}`); }
  if (publication) { params.push(publication); clauses.push(`publication = $${params.length}`); }
  const where = clauses.length ? 'where ' + clauses.join(' and ') : '';
  const rows = await many(
    `select * from public.schools ${where}
      order by name
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.schools ${where}`, params);
  res.json({ schools: rows, total: totalRow.c, limit, offset });
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
  const name = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true });
  const type = validateField(b.type, 'type', 50, { required: true });
  const ownership = validateField(b.ownership, 'ownership', 50, { required: true });
  validateField(b.state, 'state', 100);
  validateField(b.city, 'city', 100);
  validateField(b.address, 'address', FIELD_LIMITS.short);
  validateUrl(b.website, 'website');
  validateField(b.email, 'email', FIELD_LIMITS.email);
  validateField(b.description, 'description', FIELD_LIMITS.long);
  validateField(b.established, 'established', 10);

  let slug = slugify(name);
  if (await one('select 1 from public.schools where slug=$1', [slug]))
    slug += '-' + Date.now().toString(36);

  const school = await one(
    `insert into public.schools
       (name, slug, type, ownership, state, city, address, website, email, description, established,
        verification, publication)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'verified','published') returning *`,
    [name, slug, type, ownership, b.state||null, b.city||null, b.address||null,
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

async function sendBackContent(req, res, type, id) {
  const meta = CONTENT_TYPES[type];
  if (!meta) throw httpError(400, 'Unsupported content type.');

  const row = await one(`select * from public.${meta.table} where id=$1`, [id]);
  if (!row) throw httpError(404, `The ${meta.friendly} was not found.`);
  if (row.status === 'archived')
    throw httpError(400, `This ${meta.friendly} is archived and cannot be sent back.`);
  if (row.status === 'draft')
    throw httpError(400, `This ${meta.friendly} is already in draft.`);

  const comment = validateField(req.body?.comment, 'comment', FIELD_LIMITS.medium, { required: true }).trim();
  if (!comment) throw httpError(400, 'A note for the school is required when sending back.');

  const label = await tx(async (c) => {
    await c.query(
      `update public.${meta.table} set status='draft', updated_at=now() where id=$1`,
      [id]
    );
    await c.query(
      `insert into public.review_comments
         (submission_type, submission_target_id, school_id, reviewer_id, reviewer_name, decision, comment)
       values ($1,$2,$3,$4,$5,'changes_requested',$6)`,
      [type, id, row.school_id, req.user.id, req.user.name, comment]
    );
    const managers = await c.query(
      `select id from public.users where role='school_manager' and school_id=$1`,
      [row.school_id]
    );
    for (const m of managers.rows) {
      await c.query(
        `insert into public.notifications (user_id, school_id, title, body, link)
         values ($1,$2,$3,$4,$5)`,
        [m.id, row.school_id,
         `Your ${meta.friendly} was sent back for changes`,
         comment, '/SchoolAd/submissions.html']
      );
    }
    const lbl = await c.query(
      `select ${meta.labelCol} as label from public.${meta.table} where id=$1`,
      [id]
    );
    return lbl.rows[0]?.label || `#${id}`;
  });

  await audit(req, 'send_back', type, id, label, { comment });
  res.json({ ok: true });
}

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

/* ---------- COURSES ---------- */
router.get('/schools/:schoolId/courses', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  const rows = await many(
    `select c.*, rc.comment as review_comment
       from public.courses c
       left join lateral (
         select comment from public.review_comments
          where submission_type = 'course' and submission_target_id = c.id
          order by created_at desc limit 1
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
  const name = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true });
  validateField(b.faculty, 'faculty', 200);
  validateField(b.department, 'department', 200);
  validateField(b.duration, 'duration', 100);
  validateField(b.qualification, 'qualification', 200);
  validateField(b.entry_route, 'entry_route', 100);
  validateField(b.requirements, 'requirements', FIELD_LIMITS.long);

  const course = await one(
    `insert into public.courses (school_id, name, faculty, department, duration, qualification, entry_route, requirements, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,'published') returning *`,
    [schoolId, name, b.faculty||null, b.department||null, b.duration||null,
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
  const rows = await many(
    `select f.*, rc.comment as review_comment
       from public.fee_records f
       left join lateral (
         select comment from public.review_comments
          where submission_type = 'fee' and submission_target_id = f.id
          order by created_at desc limit 1
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
  const session = validateField(b.session, 'session', 50, { required: true });
  const category = validateField(b.category, 'category', 100, { required: true });
  if (b.amount == null) throw httpError(400, 'amount is required.');
  if (!Number.isFinite(Number(b.amount)) || Number(b.amount) < 0)
    throw httpError(400, 'amount must be a non-negative number.');
  validateUrl(b.source_url, 'source_url');
  validateField(b.notes, 'notes', FIELD_LIMITS.medium);

  const fee = await one(
    `insert into public.fee_records (school_id, session, category, programme, level, student_category, amount, source_url, verified_date, notes, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'published') returning *`,
    [schoolId, session, category, b.programme||null, b.level||null, b.student_category||null,
     Number(b.amount), b.source_url||null, b.verified_date||null, b.notes||null]
  );
  await audit(req, 'create', 'fee', fee.id, `${session} ${category}`, { school_id: school.id });
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
  const { limit, offset } = pagination(req);
  const clauses = []; const params = [];
  if (scoped.school_id) { params.push(scoped.school_id); clauses.push(`a.school_id = $${params.length}`); }
  if (req.query.status) { params.push(req.query.status); clauses.push(`a.status = $${params.length}`); }
  const where = clauses.length ? 'where ' + clauses.join(' and ') : '';
  const sql = `select a.*, s.name as school_name from public.admission_notices a
    join public.schools s on s.id = a.school_id
    ${where}
    order by a.created_at desc
    limit $${params.length + 1} offset $${params.length + 2}`;
  const rows = await many(sql, [...params, limit, offset]);
  const totalRow = await one(
    `select count(*)::int as c from public.admission_notices a ${where.replace(/a\./g, '')}`,
    params
  );
  res.json({ admissions: rows, total: totalRow.c, limit, offset });
}));

router.get('/schools/:schoolId/admissions', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  const rows = await many(
    `select a.*, rc.comment as review_comment
       from public.admission_notices a
       left join lateral (
         select comment from public.review_comments
          where submission_type = 'admission' and submission_target_id = a.id
          order by created_at desc limit 1
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
  const title = validateField(b.title, 'title', FIELD_LIMITS.title, { required: true });
  validateField(b.session, 'session', 50, { required: true });
  validateField(b.entry_route, 'entry_route', 100, { required: true });
  const applicationUrl = validateUrl(b.application_url, 'application_url', { required: true });
  const sourceUrl = validateUrl(b.source_url, 'source_url', { required: true });
  validateField(b.requirements, 'requirements', FIELD_LIMITS.long);
  validateField(b.eligibility, 'eligibility', FIELD_LIMITS.long);
  validateField(b.notes, 'notes', FIELD_LIMITS.medium);

  if (b.open_date && b.close_date && new Date(b.close_date) < new Date(b.open_date))
    throw httpError(400, 'close_date cannot be before open_date.');

  const adm = await one(
    `insert into public.admission_notices
       (school_id, title, session, entry_route, open_date, close_date, extension_note,
        requirements, eligibility, application_url, source_url, notes, status, verification)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'published','unverified') returning *`,
    [schoolId, title, b.session, b.entry_route, b.open_date||null, b.close_date||null,
     b.extension_note||null, b.requirements||null, b.eligibility||null,
     applicationUrl, sourceUrl, b.notes||null]
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
  if ('application_url' in updates) validateUrl(updates.application_url, 'application_url');
  if ('source_url' in updates) validateUrl(updates.source_url, 'source_url');
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
  const rows = await many(
    `select e.*, rc.comment as review_comment
       from public.academic_events e
       left join lateral (
         select comment from public.review_comments
          where submission_type = 'calendar' and submission_target_id = e.id
          order by created_at desc limit 1
       ) rc on true
      where e.school_id = $1
      order by e.start_date`,
    [req.params.schoolId]
  );
  res.json({ events: rows });
}));

router.get('/schools/:schoolId/events', authenticate, requireRole('owner','admin','editor','reviewer','school_manager'), asyncH(async (req, res) => {
  assertSchoolScope(req.user, req.params.schoolId);
  const rows = await many(
    `select e.*, rc.comment as review_comment
       from public.academic_events e
       left join lateral (
         select comment from public.review_comments
          where submission_type = 'calendar' and submission_target_id = e.id
          order by created_at desc limit 1
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
  const title = validateField(b.title, 'title', FIELD_LIMITS.title, { required: true });
  validateField(b.type, 'type', 50, { required: true });
  validateField(b.session, 'session', 50, { required: true });
  const startDate = validateField(b.start_date, 'start_date', 30, { required: true });
  const sourceUrl = validateUrl(b.source_url, 'source_url', { required: true });
  validateField(b.notes, 'notes', FIELD_LIMITS.medium);
  if (b.end_date && new Date(b.end_date) < new Date(b.start_date))
    throw httpError(400, 'end_date cannot be before start_date.');

  const ev = await one(
    `insert into public.academic_events
       (school_id, title, type, session, semester, start_date, end_date, notes, source_url, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'published') returning *`,
    [schoolId, title, b.type, b.session, b.semester||null, startDate,
     b.end_date||null, b.notes||null, sourceUrl]
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
  if ('source_url' in updates) validateUrl(updates.source_url, 'source_url');
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
  const { limit, offset } = pagination(req);
  const rows = await many(
    `select * from public.exams order by created_at desc limit $1 offset $2`,
    [limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.exams`);
  res.json({ exams: rows, total: totalRow.c, limit, offset });
}));

router.post('/exams', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  const title = validateField(b.title, 'title', FIELD_LIMITS.title, { required: true });
  const body = validateField(b.body, 'body', FIELD_LIMITS.long, { required: true });
  validateField(b.type, 'type', 50, { required: true });
  validateField(b.session, 'session', 50, { required: true });
  const website = validateUrl(b.website, 'website', { required: true });
  validateUrl(b.source_url, 'source_url');

  const row = await one(
    `insert into public.exams
       (title, body, type, session, description, eligibility, instructions, open_date, close_date,
        timetable_info, timetable_url, resources, resource_links, website, source_url, status, verification)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'draft','unverified') returning *`,
    [title, body, b.type, b.session, b.description||null, b.eligibility||null,
     b.instructions||null, b.open_date||null, b.close_date||null,
     b.timetable_info||null, b.timetable_url||null, b.resources||null,
     b.resource_links||null, website, b.source_url||null]
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
  const { limit, offset } = pagination(req);
  const rows = await many(
    `select * from public.scholarships order by created_at desc limit $1 offset $2`,
    [limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.scholarships`);
  res.json({ scholarships: rows, total: totalRow.c, limit, offset });
}));

router.post('/scholarships', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  const title = validateField(b.title, 'title', FIELD_LIMITS.title, { required: true });
  validateField(b.sponsor, 'sponsor', FIELD_LIMITS.name, { required: true });
  validateField(b.category, 'category', 100, { required: true });
  validateField(b.level, 'level', 100, { required: true });
  const applyUrl = validateUrl(b.apply_url, 'apply_url', { required: true });
  validateUrl(b.source_url, 'source_url');

  const row = await one(
    `insert into public.scholarships
       (title, sponsor, sponsor_type, category, level, location, deadline, eligibility,
        coverage, amount, currency, frequency, covered, not_covered, nationality, academic,
        documents, steps, contact, open_date, close_date, extension, apply_url, source_url,
        verification, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,'unverified','draft')
     returning *`,
    [title, b.sponsor, b.sponsor_type||null, b.category, b.level, b.location||null,
     b.deadline||null, b.eligibility||null, b.coverage||null, b.amount||null,
     b.currency||null, b.frequency||null, b.covered||null, b.not_covered||null,
     b.nationality||null, b.academic||null, b.documents||null, b.steps||null,
     b.contact||null, b.open_date||null, b.close_date||null, b.extension||null,
     applyUrl, b.source_url||null]
  );
  await audit(req, 'create', 'scholarship', row.id, row.title);
  res.status(201).json({ scholarship: row });
}));

router.patch('/scholarships/:id', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const row = await one('select * from public.scholarships where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Scholarship not found.');
  const allowed = ['title','sponsor','sponsor_type','category','level','location','deadline','eligibility','coverage','amount','currency','frequency','covered','not_covered','nationality','academic','documents','steps','contact','open_date','close_date','extension','apply_url','source_url','status'];
  const updates = {}; for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
  if ('apply_url' in updates) validateUrl(updates.apply_url, 'apply_url');
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
  const { limit, offset } = pagination(req);
  const rows = await many(
    `select * from public.trending order by created_at desc limit $1 offset $2`,
    [limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.trending`);
  res.json({ stories: rows, total: totalRow.c, limit, offset });
}));

router.post('/trending', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  const title = validateField(b.title, 'title', FIELD_LIMITS.title, { required: true });
  validateField(b.category, 'category', 100, { required: true });
  validateField(b.author, 'author', FIELD_LIMITS.name, { required: true });
  const body = validateField(b.body, 'body', FIELD_LIMITS.long, { required: true });
  validateUrl(b.source_url, 'source_url');

  const row = await one(
    `insert into public.trending
       (title, category, author, summary, body, cover_media_id, alt_text, caption,
        source_url, source_date, verification, featured, scheduled_at, status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unverified',$11,$12,'draft') returning *`,
    [title, b.category, b.author, b.summary||null, body, b.cover_media_id||null,
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
  const scheduledAt = validateField(req.body?.scheduled_at, 'scheduled_at', 30, { required: true });
  await run(
    `update public.trending set status='scheduled', scheduled_at=$1, updated_at=now() where id=$2`,
    [scheduledAt, row.id]
  );
  await audit(req, 'schedule', 'trending', row.id, row.title, { scheduled_at: scheduledAt });
  res.json({ ok: true });
}));

/* ---------- MEDIA (Supabase Storage) ---------- */
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

  const { data: urlData } = supabase.storage.from(MEDIA_BUCKET).getPublicUrl(filename);
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
  const { limit, offset } = pagination(req);
  const clauses = []; const params = [];
  if (req.user.role === 'school_manager') { params.push(req.user.school_id); clauses.push(`school_id = $${params.length}`); }
  if (req.query.school_id && req.user.role !== 'school_manager') { params.push(req.query.school_id); clauses.push(`school_id = $${params.length}`); }
  const where = clauses.length ? 'where ' + clauses.join(' and ') : '';

  const rows = await many(
    `select * from public.media_assets ${where}
      order by created_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
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

  res.json({ media: rows, limit, offset });
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

  await tx(async (c) => {
    const placed = await c.query(
      `select id from public.media_placements
        where media_id = $1 and is_active = true
        for update`,
      [row.id]
    );
    if (placed.rows.length) {
      throw httpError(
        409,
        `This file is used on ${placed.rows.length} placement(s). Unassign or replace it first.`,
        'media_in_use'
      );
    }
    await c.query('delete from public.media_assets where id=$1', [row.id]);
  });

  const { error: removeError } = await supabase.storage
    .from(MEDIA_BUCKET)
    .remove([row.filename]);
  if (removeError) console.error('[supabase storage remove]', removeError.message);

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

router.post('/media/placements', authenticate, requireRole('owner','admin','school_manager'), asyncH(async (req, res) => {
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

  if (page === 'schools' && ref) {
    const school = await one('select id from public.schools where id=$1', [ref]);
    if (!school) throw httpError(400, 'content_ref does not match any school.');
    if (req.user.role === 'school_manager' && !idsEqual(school.id, req.user.school_id))
      throw httpError(403, 'You can only place media on your own school.');
    if (req.user.role === 'school_manager' && !idsEqual(media.school_id, school.id))
      throw httpError(403, 'This media file does not belong to your school.');
  }
  if (page === 'trending' && ref && req.user.role === 'school_manager')
    throw httpError(403, 'School managers cannot place trending covers.');
  if (!ref && req.user.role === 'school_manager')
    throw httpError(403, 'School managers cannot manage global placements.');

  const row = await tx(async (c) => {
    await c.query(
      `update public.media_placements
          set is_active = false, updated_at = now()
        where page = $1 and slot = $2
          and (content_ref is not distinct from $3)
          and is_active = true`,
      [page, slot, ref]
    );
    const ins = await c.query(
      `insert into public.media_placements (media_id, page, slot, content_ref, is_active)
       values ($1,$2,$3,$4,true) returning *`,
      [media_id, page, slot, ref]
    );
    return ins.rows[0];
  });

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
  const { limit, offset } = pagination(req);
  const rows = await many(
    `select u.*, s.name as school_name, s.slug as school_slug
       from public.users u
       left join public.schools s on s.id = u.school_id
      order by u.created_at desc
      limit $1 offset $2`,
    [limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.users`);
  res.json({ users: rows.map(publicUser), total: totalRow.c, limit, offset });
}));

router.post('/users', authenticate, requireRole('owner'), asyncH(async (req, res) => {
  const b = req.body || {};
  const name = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true });
  const email = validateField(b.email, 'email', FIELD_LIMITS.email, { required: true });
  const role = validateField(b.role, 'role', 50, { required: true });
  if (!['owner','admin','editor','reviewer','school_manager'].includes(role)) throw httpError(400, 'Invalid role.');

  let schoolId = null;
  if (role === 'school_manager') {
    if (!b.school_id) throw httpError(400, 'school_id is required for school managers.');
    const school = await one('select id, name from public.schools where id=$1', [b.school_id]);
    if (!school) throw httpError(400, `School id=${b.school_id} does not exist.`);
    schoolId = school.id;
  }

  if (await one('select 1 from public.users where lower(email)=lower($1)', [email]))
    throw httpError(409, 'An account with that email already exists.');

  const initialPassword = b.password || crypto.randomBytes(9).toString('base64').slice(0, 12);
  const hash = bcrypt.hashSync(initialPassword, BCRYPT_COST);
  const status = role === 'school_manager' ? 'pending' : 'active';
  const user = await one(
    `insert into public.users (name, email, password_hash, role, school_id, status, must_change_password, notes)
     values ($1,$2,$3,$4,$5,$6,true,$7) returning *`,
    [name, email, hash, role, schoolId, status, b.notes || null]
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
  const { limit, offset } = pagination(req, { defaultLimit: 100 });
  const where = req.user.role === 'owner' ? '' : 'where (user_id = $1 or school_id = $2)';
  const params = req.user.role === 'owner' ? [] : [req.user.id, req.user.school_id || null];
  const rows = await many(
    `select * from public.notifications ${where}
      order by created_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  res.json({ notifications: rows, limit, offset });
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
  const { limit, offset } = pagination(req, { defaultLimit: 200, maxLimit: 500 });
  const rows = await many(
    `select * from public.audit_logs order by created_at desc limit $1 offset $2`,
    [limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.audit_logs`);
  res.json({ audit: rows, total: totalRow.c, limit, offset });
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

/* ============================================================
 * CONTACT MESSAGES
 * ============================================================ */

const CONTACT_CATEGORIES = [
  'General Enquiry',
  'School Partnership',
  'Technical Support',
  'Incorrect Information',
  'Advertising',
];
const CONTACT_STATUSES = ['unread', 'read', 'pending', 'resolved'];

router.post('/public/contact', asyncH(async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!(await rateLimit(`contact:${ip}`, 5, 10 * 60 * 1000)))
    throw httpError(429, 'Too many messages from this address. Try again later.', 'rate_limited');

  const b = req.body || {};
  const name = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true }).trim();
  const email = validateField(b.email, 'email', FIELD_LIMITS.email, { required: true }).trim();
  const subject = validateField(b.subject, 'subject', FIELD_LIMITS.title);
  const message = validateField(b.message, 'message', FIELD_LIMITS.long, { required: true }).trim();
  const rawCategory = b.category ? String(b.category).trim() : 'General Enquiry';
  const category = CONTACT_CATEGORIES.includes(rawCategory) ? rawCategory : 'General Enquiry';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    throw httpError(400, 'Please enter a valid email address.');

  const row = await one(
    `insert into public.contact_messages
       (name, email, subject, category, message, status, ip)
     values ($1,$2,$3,$4,$5,'unread',$6) returning *`,
    [name, email, subject || null, category, message, ip]
  );

  await audit(
    { user: null, ip },
    'submit_contact',
    'contact_message',
    row.id,
    `${name} <${email}>`,
    { category }
  );

  res.status(201).json({ ok: true, message: 'Your message was sent. We will get back to you soon.' });
}));

router.get('/contact-messages', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });
  const clauses = []; const params = [];
  if (req.query.status)   { params.push(String(req.query.status));   clauses.push(`status = $${params.length}`); }
  if (req.query.category) { params.push(String(req.query.category)); clauses.push(`category = $${params.length}`); }
  if (req.query.q) {
    params.push(`%${req.query.q}%`, `%${req.query.q}%`, `%${req.query.q}%`);
    clauses.push(`(name ilike $${params.length-2} or email ilike $${params.length-1} or subject ilike $${params.length})`);
  }
  const where = clauses.length ? 'where ' + clauses.join(' and ') : '';
  const rows = await many(
    `select * from public.contact_messages ${where}
      order by created_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.contact_messages ${where}`, params);
  res.json({ messages: rows, total: totalRow.c, limit, offset });
}));

router.get('/contact-messages/:id', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.contact_messages where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Message not found.');
  res.json({ message: row });
}));

router.patch('/contact-messages/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.contact_messages where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Message not found.');
  const status = validateField(req.body?.status, 'status', 30, { required: true }).toLowerCase();
  if (!CONTACT_STATUSES.includes(status))
    throw httpError(400, `status must be one of: ${CONTACT_STATUSES.join(', ')}.`);

  const resolvedAt = status === 'resolved' ? new Date() : row.resolved_at;
  const updated = await one(
    `update public.contact_messages
        set status = $1, resolved_at = $2, updated_at = now()
      where id = $3 returning *`,
    [status, resolvedAt, row.id]
  );

  await audit(req, 'update', 'contact_message', row.id, `${row.name} <${row.email}>`, { status });
  res.json({ message: updated });
}));

router.delete('/contact-messages/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.contact_messages where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Message not found.');
  await run('delete from public.contact_messages where id=$1', [row.id]);
  await audit(req, 'delete', 'contact_message', row.id, `${row.name} <${row.email}>`);
  res.json({ ok: true });
}));

/* ============================================================
 * ADVERTISEMENTS
 * ============================================================ */

const AD_PLACEMENTS = ['home', 'schools', 'admissions', 'exams', 'scholarships', 'trending'];
const AD_STATUSES   = ['draft', 'pending', 'approved', 'scheduled', 'active', 'paused', 'rejected', 'expired'];
const AD_FORMATS    = ['large', 'medium', 'small', 'square', 'vertical'];

function validateAdPlacement(value) {
  const v = validateField(value, 'placement', 50, { required: true }).toLowerCase();
  if (!AD_PLACEMENTS.includes(v))
    throw httpError(400, `placement must be one of: ${AD_PLACEMENTS.join(', ')}.`);
  return v;
}
function validateAdStatus(value, { required = false } = {}) {
  const v = validateField(value, 'status', 30, { required });
  if (v == null) return null;
  const s = v.toLowerCase();
  if (!AD_STATUSES.includes(s))
    throw httpError(400, `status must be one of: ${AD_STATUSES.join(', ')}.`);
  return s;
}
function validateAdFormat(value, { required = false } = {}) {
  const v = validateField(value, 'format', 20, { required });
  if (v == null) return 'medium';
  const f = String(v).toLowerCase();
  if (!AD_FORMATS.includes(f))
    throw httpError(400, `format must be one of: ${AD_FORMATS.join(', ')}.`);
  return f;
}

/* ─── Derived fields: payment status + link to advertiser profile ─── */
async function attachDerivedFields(campaigns) {
  if (!Array.isArray(campaigns) || campaigns.length === 0) return campaigns;

  // Resolve advertiser emails in one query
  const advIds = [...new Set(
    campaigns.map(c => c.advertiser_user_id).filter(Boolean)
  )];
  const emailById = {};
  const profileByUser = {};
  if (advIds.length) {
    const users = await many(
      `select id, email from public.users where id = ANY($1::uuid[])`,
      [advIds]
    );
    for (const u of users) emailById[u.id] = u.email;

    // Best-effort: attach business_name / contact info if profiles exist
    try {
      const profiles = await many(
        `select user_id, business_name, phone
           from public.advertiser_profiles
          where user_id = ANY($1::uuid[])`,
        [advIds]
      );
      for (const p of profiles) profileByUser[p.user_id] = p;
    } catch (_) {}
  }

  for (const c of campaigns) {
    const email = c.advertiser_user_id ? emailById[c.advertiser_user_id] : null;
    c.advertiser_email = email || null;

    const prof = c.advertiser_user_id ? profileByUser[c.advertiser_user_id] : null;
    if (prof) {
      if (!c.contact_name)  c.contact_name  = prof.business_name || null;
      if (!c.contact_phone) c.contact_phone = prof.phone || null;
    }

    // Derive payment_status from transactions if not already present
    if (c.payment_status === undefined) {
      if (!email) { c.payment_status = null; }
      else {
        try {
          const tx = await one(
            `select status from public.transactions
              where customer = $1
                and notes ilike $2
              order by created_at desc limit 1`,
            [email, '%' + (c.name || '') + '%']
          );
          c.payment_status = tx?.status || null;
        } catch (_) {
          c.payment_status = null;
        }
      }
    }

    // Ensure fields the UI expects are always present (even if null)
    for (const k of ['notes','contact_name','contact_email','contact_phone',
                     'rejection_reason','changes_requested_reason',
                     'published_at','scheduled_at']) {
      if (c[k] === undefined) c[k] = null;
    }
  }
  return campaigns;
}

/* ============================================================
 * ADVERTISEMENTS (admin workflow)
 * ============================================================ */

/* ── Format ↔ placement compatibility rules ──
 * Large is exclusive to the Home page. Every admin mutation that could
 * result in a mismatched pair goes through this check. */
function assertFormatPlacementCompatibility(format, placement) {
  if (!format || !placement) return;
  if (format === 'large' && placement !== 'home') {
    throw httpError(400,
      'Large format is only available on the Home page. Choose a different format or set placement to home.');
  }
}

/* ─── LIST ─── */
router.get('/advertisements', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });
  const clauses = []; const params = [];
  if (req.query.status)    { params.push(String(req.query.status).toLowerCase());    clauses.push(`status = $${params.length}`); }
  if (req.query.placement) { params.push(String(req.query.placement).toLowerCase()); clauses.push(`placement = $${params.length}`); }
  if (req.query.format)    { params.push(String(req.query.format).toLowerCase());    clauses.push(`format = $${params.length}`); }
  if (req.query.q) {
    params.push(`%${req.query.q}%`, `%${req.query.q}%`);
    clauses.push(`(name ilike $${params.length-1} or advertiser ilike $${params.length})`);
  }
  const where = clauses.length ? 'where ' + clauses.join(' and ') : '';
  const rows = await many(
    `select * from public.advertisements ${where}
      order by created_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  await attachDerivedFields(rows);
  const totalRow = await one(`select count(*)::int as c from public.advertisements ${where}`, params);
  res.json({ campaigns: rows, total: totalRow.c, limit, offset });
}));

/* ─── DETAIL ─── */
router.get('/advertisements/:id', authenticate, requireRole('owner','admin','editor','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  await attachDerivedFields([row]);
  res.json({ campaign: row });
}));

/* ─── CREATE ─── */
router.post('/advertisements', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const b = req.body || {};
  const name       = validateField(b.name, 'name', FIELD_LIMITS.name, { required: true }).trim();
  const advertiser = validateField(b.advertiser, 'advertiser', FIELD_LIMITS.name, { required: true }).trim();
  const placement  = validateAdPlacement(b.placement);
  const url        = validateUrl(b.url, 'url', { required: true });
  const imageUrl   = validateUrl(b.image_url, 'image_url');
  const startDate  = validateField(b.start_date, 'start_date', 30, { required: true });
  const endDate    = validateField(b.end_date, 'end_date', 30, { required: true });
  const status     = validateAdStatus(b.status) || 'draft';
  const format     = validateAdFormat(b.format);

  // Enforce the Large → Home rule before anything else
  assertFormatPlacementCompatibility(format, placement);

  let advertiserUserId = null;
  if (b.advertiser_user_id) {
    const adv = await one(
      `select id from public.users where id=$1 and role='advertiser'`,
      [b.advertiser_user_id]
    );
    if (!adv) throw httpError(400, 'advertiser_user_id does not reference an advertiser account.');
    advertiserUserId = adv.id;
  }

  if (new Date(endDate) < new Date(startDate))
    throw httpError(400, 'end_date cannot be before start_date.');

  const row = await one(
    `insert into public.advertisements
       (name, advertiser, placement, url, image_url, start_date, end_date, status,
        created_by, advertiser_user_id, format, notes, contact_name, contact_email, contact_phone)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) returning *`,
    [name, advertiser, placement, url, imageUrl, startDate, endDate, status,
     req.user.id, advertiserUserId, format,
     validateField(b.notes, 'notes', FIELD_LIMITS.medium),
     validateField(b.contact_name, 'contact_name', FIELD_LIMITS.name),
     validateField(b.contact_email, 'contact_email', FIELD_LIMITS.email),
     validateField(b.contact_phone, 'contact_phone', 30)]
  );
  await audit(req, 'create', 'advertisement', row.id, row.name, { placement, status, format });
  await attachDerivedFields([row]);
  res.status(201).json({ campaign: row });
}));

/* ─── UPDATE (content only; workflow status changes go through dedicated endpoints) ─── */
router.patch('/advertisements/:id', authenticate, requireRole('owner','admin','editor'), asyncH(async (req, res) => {
  const existing = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!existing) throw httpError(404, 'Campaign not found.');

  const b = req.body || {};
  const allowed = [
    'name','advertiser','placement','url','image_url','start_date','end_date','format',
    'notes','contact_name','contact_email','contact_phone',
  ];
  const updates = {};
  for (const k of allowed) if (k in b) updates[k] = b[k];

  if ('placement' in updates) updates.placement = validateAdPlacement(updates.placement);
  if ('url' in updates) updates.url = validateUrl(updates.url, 'url', { required: true });
  if ('image_url' in updates) updates.image_url = validateUrl(updates.image_url, 'image_url');
  if ('format' in updates) updates.format = validateAdFormat(updates.format, { required: true });

  // Enforce format/placement on the *resulting* row, not the diff
  const effectiveFormat    = updates.format    != null ? updates.format    : existing.format    || 'medium';
  const effectivePlacement = updates.placement != null ? updates.placement : existing.placement;
  assertFormatPlacementCompatibility(effectiveFormat, effectivePlacement);

  if ('status' in b) {
    const newStatus = validateAdStatus(b.status, { required: true });
    // Only allow content-safe statuses here. Workflow transitions have dedicated endpoints.
    const blocked = ['approved', 'active', 'scheduled'];
    if (blocked.includes(newStatus) && (existing.status || '').toLowerCase() !== newStatus) {
      throw httpError(400,
        `Use the dedicated endpoint to move to "${newStatus}" (approve / schedule / publish).`);
    }
    updates.status = newStatus;
  }

  if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');

  const keys = Object.keys(updates);
  const values = keys.map(k => updates[k]);
  const setSql = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
  values.push(existing.id);
  const updated = await one(
    `update public.advertisements set ${setSql}, updated_at=now() where id=$${values.length} returning *`,
    values
  );

  await audit(req, 'update', 'advertisement', existing.id, existing.name, { fields: keys });
  await attachDerivedFields([updated]);
  res.json({ campaign: updated });
}));

/* ─── APPROVE (status: pending → approved — does NOT publish) ─── */
router.post('/advertisements/:id/approve', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if (!['pending', 'draft'].includes((row.status || '').toLowerCase()))
    throw httpError(400, `Only pending or draft campaigns can be approved. Current status: ${row.status}.`);

  // Guard against rows that predate the rule or slipped through legacy paths
  assertFormatPlacementCompatibility(row.format || 'medium', row.placement);

  const updated = await one(
    `update public.advertisements
        set status='approved',
            reviewed_by=$1,
            reviewed_at=now(),
            approved_by=$1,
            approved_at=now(),
            rejection_reason=null,
            changes_requested_reason=null,
            updated_at=now()
      where id=$2 returning *`,
    [req.user.id, row.id]
  );

  await audit(req, 'approve', 'advertisement', row.id, row.name, { status: 'approved' });

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Your campaign was approved',
      `“${row.name}” has been approved. It will go live once published by our team.`,
      '/advertiser/campaigns.html',
      'review_decision'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── REJECT (requires reason) ─── */
router.post('/advertisements/:id/reject', authenticate, requireRole('owner','admin','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if (!['pending','draft'].includes((row.status || '').toLowerCase()))
    throw httpError(400, `Only pending or draft campaigns can be rejected. Current status: ${row.status}.`);

  const reason = validateField(req.body?.reason, 'reason', FIELD_LIMITS.medium, { required: true }).trim();
  if (reason.length < 10)
    throw httpError(400, 'Please provide a rejection reason of at least 10 characters.');

  const updated = await one(
    `update public.advertisements
        set status='rejected',
            rejection_reason=$1,
            reviewed_by=$2,
            reviewed_at=now(),
            updated_at=now()
      where id=$3 returning *`,
    [reason, req.user.id, row.id]
  );

  await audit(req, 'reject', 'advertisement', row.id, row.name, { reason });

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Your campaign was rejected',
      reason,
      '/advertiser/campaigns.html',
      'review_decision'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── REQUEST CHANGES (status stays pending; reason stored) ─── */
router.post('/advertisements/:id/request-changes', authenticate, requireRole('owner','admin','reviewer'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if (!['pending','draft'].includes((row.status || '').toLowerCase()))
    throw httpError(400, `Only pending or draft campaigns can be sent back. Current status: ${row.status}.`);

  const reason = validateField(req.body?.reason, 'reason', FIELD_LIMITS.medium, { required: true }).trim();
  if (reason.length < 10)
    throw httpError(400, 'Please describe the required changes (at least 10 characters).');

  const updated = await one(
    `update public.advertisements
        set changes_requested_reason=$1,
            reviewed_by=$2,
            reviewed_at=now(),
            updated_at=now()
      where id=$3 returning *`,
    [reason, req.user.id, row.id]
  );

  await audit(req, 'request_changes', 'advertisement', row.id, row.name, { reason });

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Changes requested on your campaign',
      reason,
      '/advertiser/campaigns.html',
      'review_decision'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── SCHEDULE (status: approved → scheduled; scheduled_at must be future) ─── */
router.post('/advertisements/:id/schedule', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if ((row.status || '').toLowerCase() !== 'approved')
    throw httpError(400, 'Only approved campaigns can be scheduled.');
  if (!row.placement)
    throw httpError(400, 'Assign a placement before scheduling.');

  assertFormatPlacementCompatibility(row.format || 'medium', row.placement);

  const scheduledAt = validateField(req.body?.scheduled_at, 'scheduled_at', 40, { required: true });
  const when = new Date(scheduledAt);
  if (isNaN(when)) throw httpError(400, 'scheduled_at must be a valid ISO datetime.');

  // scheduled_at must be in the future (60s grace period for clock skew)
  if (when.getTime() < Date.now() - 60_000) {
    throw httpError(400, 'scheduled_at must be in the future.');
  }
  // And it must not land after the campaign's own end_date, or it would never serve
  if (row.end_date && new Date(row.end_date) < when) {
    throw httpError(400, 'scheduled_at is after the campaign end_date; the campaign would never serve.');
  }

  const updated = await one(
    `update public.advertisements
        set status='scheduled', scheduled_at=$1, updated_at=now()
      where id=$2 returning *`,
    [when.toISOString(), row.id]
  );

  await audit(req, 'schedule', 'advertisement', row.id, row.name, { scheduled_at: when.toISOString() });
  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── PUBLISH (status → active; sets published_at once) ─── */
router.post('/advertisements/:id/publish', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if (!['approved', 'scheduled', 'paused'].includes((row.status || '').toLowerCase()))
    throw httpError(400, `Cannot publish from status "${row.status}".`);
  if (!row.placement)
    throw httpError(400, 'Assign a placement before publishing.');

  assertFormatPlacementCompatibility(row.format || 'medium', row.placement);

  const now = new Date();
  const updated = await one(
    `update public.advertisements
        set status='active',
            published_at = COALESCE(published_at, $1),
            updated_at=now()
      where id=$2 returning *`,
    [now.toISOString(), row.id]
  );

  await audit(req, 'publish', 'advertisement', row.id, row.name);

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Your campaign is now live',
      `“${row.name}” is now serving on the ${row.placement} page.`,
      '/advertiser/campaigns.html',
      'publication_update'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── PAUSE ─── */
router.post('/advertisements/:id/pause', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if ((row.status || '').toLowerCase() !== 'active')
    throw httpError(400, 'Only active campaigns can be paused.');

  const updated = await one(
    `update public.advertisements set status='paused', updated_at=now() where id=$1 returning *`,
    [row.id]
  );

  await audit(req, 'pause', 'advertisement', row.id, row.name);

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Your campaign was paused',
      `“${row.name}” has been paused by the CampusNaija team.`,
      '/advertiser/campaigns.html',
      'publication_update'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── RESUME ─── */
router.post('/advertisements/:id/resume', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  if ((row.status || '').toLowerCase() !== 'paused')
    throw httpError(400, 'Only paused campaigns can be resumed.');

  const updated = await one(
    `update public.advertisements set status='active', updated_at=now() where id=$1 returning *`,
    [row.id]
  );

  await audit(req, 'resume', 'advertisement', row.id, row.name);

  if (row.advertiser_user_id) {
    await notifyAdvertiser(
      row.advertiser_user_id,
      'Your campaign was resumed',
      `“${row.name}” is live again.`,
      '/advertiser/campaigns.html',
      'publication_update'
    );
  }

  await attachDerivedFields([updated]);
  res.json({ ok: true, campaign: updated });
}));

/* ─── DELETE ─── */
router.delete('/advertisements/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.advertisements where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Campaign not found.');
  await run('delete from public.advertisements where id=$1', [row.id]);
  await audit(req, 'delete', 'advertisement', row.id, row.name);
  res.json({ ok: true });
}));

/* ============================================================
 * PUBLIC NAMED ADVERTISEMENT ENDPOINTS
 * ============================================================ */

/* ── Legacy: single-campaign resolver (unchanged shape) ── */
async function resolvePublicCampaign(placement) {
  const row = await one(
    `select id, name, advertiser, description, cta_text, placement, url, image_url,
            target_school_id, start_date, end_date, status
       from public.advertisements
      where placement = $1
        and status = 'active'
        and current_date between start_date and end_date
      order by start_date asc
      limit 1`,
    [placement]
  );
  if (!row) return null;

  if (row.target_school_id) {
    row.target_school = await one(
      `select id, slug, name, city, state, type, verification, cover_url, logo_url
         from public.schools
        where id = $1 and publication = 'published'`,
      [row.target_school_id]
    );
  }

  run(`update public.advertisements set impressions = impressions + 1 where id=$1`, [row.id])
    .catch(err => console.error('[ad impression]', err.message));

  return row;
}

/* ── Slideshow: multi-campaign resolver for a format ── */
async function resolvePublicCampaigns(placement, format) {
  // Includes:
  //   - Active campaigns currently in their serving window
  //   - Scheduled campaigns whose scheduled_at has been reached
  //     (lazily promoted to 'active' after the impression bump — see below)
  const rows = await many(
    `select id, name, advertiser, description, cta_text, placement, format,
            url, image_url, target_school_id, start_date, end_date, status,
            published_at, scheduled_at
       from public.advertisements
      where placement = $1
        and format = $2
        and (
          (status = 'active'
            and current_date between start_date and end_date)
          or (status = 'scheduled'
            and scheduled_at is not null
            and scheduled_at <= now()
            and current_date between start_date and end_date)
        )
      order by coalesce(published_at, scheduled_at) asc nulls last
      limit 8`,
    [placement, format]
  );

  if (!rows.length) return [];

  // Single round-trip: bump impressions AND promote any scheduled row that
  // just matured. Both effects are safe to fire in parallel with the response.
  const ids = rows.map(r => r.id);
  run(
    `update public.advertisements
        set impressions  = impressions + 1,
            status       = case
                             when status = 'scheduled'
                               and scheduled_at is not null
                               and scheduled_at <= now()
                             then 'active' else status
                           end,
            published_at = case
                             when status = 'scheduled'
                               and scheduled_at is not null
                               and scheduled_at <= now()
                             then coalesce(published_at, scheduled_at)
                             else published_at
                           end,
            updated_at   = case
                             when status = 'scheduled'
                               and scheduled_at is not null
                               and scheduled_at <= now()
                             then now() else updated_at
                           end
      where id = ANY($1::uuid[])`,
    [ids]
  ).catch(err => console.error('[ad impression/auto-publish]', err.message));

  // Attach target school metadata in one batched query
  const schoolIds = [...new Set(rows.map(r => r.target_school_id).filter(Boolean))];
  if (schoolIds.length) {
    const schools = await many(
      `select id, slug, name, city, state, type, verification, cover_url, logo_url
         from public.schools
        where id = ANY($1::uuid[]) and publication = 'published'`,
      [schoolIds]
    );
    const byId = {};
    for (const s of schools) byId[s.id] = s;
    for (const r of rows) {
      if (r.target_school_id && byId[r.target_school_id]) {
        r.target_school = byId[r.target_school_id];
      }
    }
  }

  return rows;
}

/* ── Single registration per placement, branches on ?format= ── */
['home', 'schools', 'admissions', 'exams', 'scholarships', 'trending'].forEach((placement) => {
  router.get(`/public/advertisements/${placement}`, asyncH(async (req, res) => {
    await publicLimit(req);

    const formatParam = req.query.format;
    const format = formatParam ? String(formatParam).toLowerCase() : null;

    if (format) {
      if (!AD_FORMATS.includes(format)) {
        throw httpError(400, `format must be one of: ${AD_FORMATS.join(', ')}.`);
      }
      const campaigns = await resolvePublicCampaigns(placement, format);
      return res.json({ campaigns });
    }

    // Legacy single-campaign mode for the sponsored school card,
    // profile banner, and sidebar advert.
    const campaign = await resolvePublicCampaign(placement);
    res.json({ campaign });
  }));
});

/* ============================================================
 * MONETIZATION
 * ============================================================ */

function periodToInterval(period) {
  switch (String(period || '30d').toLowerCase()) {
    case '7d':  return '7 days';
    case '30d': return '30 days';
    case '90d': return '90 days';
    case '1y':  return '1 year';
    default:    return '30 days';
  }
}

router.get('/monetization/summary', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const period = String(req.query.period || '30d').toLowerCase();
  const interval = periodToInterval(period);

  const totals = await many(
    `select status, coalesce(sum(amount),0)::numeric as total, count(*)::int as count
       from public.transactions
      where created_at >= now() - $1::interval
      group by status`,
    [interval]
  );
  const byStatus = {};
  for (const t of totals) byStatus[t.status] = { total: Number(t.total), count: t.count };

  const confirmed   = byStatus.confirmed?.total || byStatus.paid?.total || 0;
  const pending     = byStatus.pending?.total || 0;
  const outstanding = byStatus.outstanding?.total || byStatus.unpaid?.total || 0;
  const total       = Object.values(byStatus).reduce((sum, s) => sum + s.total, 0);

  const series = await many(
    `select date_trunc('day', created_at)::date as date,
            coalesce(sum(amount),0)::numeric as amount
       from public.transactions
      where created_at >= now() - $1::interval
        and status in ('confirmed','paid')
      group by 1
      order by 1`,
    [interval]
  );

  const sources = await many(
    `select source, coalesce(sum(amount),0)::numeric as amount, count(*)::int as count
       from public.transactions
      where created_at >= now() - $1::interval
        and status in ('confirmed','paid')
      group by source
      order by amount desc`,
    [interval]
  );

  res.json({
    period,
    total,
    confirmed,
    pending,
    outstanding,
    series: series.map(r => ({ date: r.date.toISOString().slice(0,10), amount: Number(r.amount) })),
    sources: sources.map(r => ({ source: r.source, amount: Number(r.amount), count: r.count })),
  });
}));

router.get('/monetization/transactions', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const period = String(req.query.period || '30d').toLowerCase();
  const interval = periodToInterval(period);
  const { limit, offset } = pagination(req, { defaultLimit: 100, maxLimit: 500 });

  const clauses = [`created_at >= now() - $1::interval`];
  const params = [interval];
  if (req.query.status) { params.push(String(req.query.status).toLowerCase()); clauses.push(`status = $${params.length}`); }
  if (req.query.source) { params.push(String(req.query.source));              clauses.push(`source = $${params.length}`); }
  const where = 'where ' + clauses.join(' and ');

  const rows = await many(
    `select * from public.transactions ${where}
      order by created_at desc
      limit $${params.length + 1} offset $${params.length + 2}`,
    [...params, limit, offset]
  );
  const totalRow = await one(`select count(*)::int as c from public.transactions ${where}`, params);
  res.json({ transactions: rows, total: totalRow.c, limit, offset });
}));

router.post('/monetization/transactions', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const b = req.body || {};
  const reference = validateField(b.reference, 'reference', 100, { required: true }).trim();
  const customer  = validateField(b.customer, 'customer', FIELD_LIMITS.name);
  const source    = validateField(b.source, 'source', 50, { required: true }).trim();
  const currency  = (validateField(b.currency, 'currency', 10) || 'NGN').toUpperCase();
  const status    = (validateField(b.status, 'status', 30) || 'pending').toLowerCase();
  const amountNum = Number(b.amount);
  if (!Number.isFinite(amountNum) || amountNum < 0)
    throw httpError(400, 'amount must be a non-negative number.');

  const allowedStatus = ['pending','confirmed','outstanding'];
  if (!allowedStatus.includes(status))
    throw httpError(400, `status must be one of: ${allowedStatus.join(', ')}.`);

  if (await one('select 1 from public.transactions where reference=$1', [reference]))
    throw httpError(409, 'A transaction with that reference already exists.');

  const row = await one(
    `insert into public.transactions
       (reference, customer, source, amount, currency, status, provider, provider_ref, notes)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,
    [reference, customer, source, amountNum, currency, status, b.provider || null, b.provider_ref || null, b.notes || null]
  );
  await audit(req, 'create', 'transaction', row.id, row.reference, { amount: amountNum, source, status });
  res.status(201).json({ transaction: row });
}));

router.patch('/monetization/transactions/:id', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const row = await one('select * from public.transactions where id=$1', [req.params.id]);
  if (!row) throw httpError(404, 'Transaction not found.');
  const status = validateField(req.body?.status, 'status', 30, { required: true }).toLowerCase();
  const allowed = ['pending','confirmed','outstanding','refunded','failed'];
  if (!allowed.includes(status))
    throw httpError(400, `status must be one of: ${allowed.join(', ')}.`);

  const updated = await one(
    `update public.transactions set status=$1, updated_at=now() where id=$2 returning *`,
    [status, row.id]
  );
  await audit(req, 'update_status', 'transaction', row.id, row.reference, { status });
  res.json({ transaction: updated });
}));

router.get('/monetization/export', authenticate, requireRole('owner','admin'), asyncH(async (req, res) => {
  const period = String(req.query.period || '30d').toLowerCase();
  const interval = periodToInterval(period);

  const rows = await many(
    `select reference, customer, source, amount, currency, status, created_at
       from public.transactions
      where created_at >= now() - $1::interval
      order by created_at desc`,
    [interval]
  );

  const header = ['Reference','Customer','Source','Amount','Currency','Status','Date'];
  const csv = [header, ...rows.map(r => [
    r.reference, r.customer || '', r.source, r.amount, r.currency, r.status, r.created_at.toISOString()
  ])].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');

  await audit(req, 'export', 'transaction', null, null, { period, count: rows.length });

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="campusnaija-transactions-${period}-${Date.now()}.csv"`);
  res.send(csv);
}));

/* ---------- HEALTH ---------- */
router.get('/health', asyncH(async (req, res) => {
  const start = Date.now();
  let dbOk = false;
  let dbTime = null;
  try {
    const r = await Promise.race([
      one('select now() as now'),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
    ]);
    dbOk = true;
    dbTime = r.now;
  } catch (_) {}

  const publicBody = {
    ok: dbOk,
    version: '1.9.1',
    time: dbTime,
    latency_ms: Date.now() - start,
  };

  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = await one('select * from public.users where id=$1', [payload.sub]);

      if (user && user.role === 'owner') {
        const orphan = await one(
          `select count(*)::int as c from public.users where role='school_manager' and school_id is null`
        );
        const pendingResets = await one(
          `select count(*)::int as c from public.password_resets where used_at is null and expires_at > now()`
        );
        const pendingAdvertisers = await one(
          `select count(*)::int as c from public.users where role='advertiser' and status='pending'`
        );

        // ── Schema probe: verify every table the app depends on exists ──
        const requiredTables = [
          'users', 'schools', 'settings', 'audit_logs', 'notifications',
          'password_resets', 'rate_limits',
          'advertisements', 'transactions',
          'advertiser_profiles', 'advertiser_profiles_ext', 'advertiser_billing',
          'advertiser_settings', 'advertiser_sessions',
          'support_tickets', 'support_ticket_messages', 'support_attachments',
          'help_articles',
        ];
        let missingTables = [];
        try {
          const present = await many(
            `select table_name
               from information_schema.tables
              where table_schema = 'public'
                and table_name = ANY($1::text[])`,
            [requiredTables]
          );
          const presentSet = new Set(present.map(r => r.table_name));
          missingTables = requiredTables.filter(t => !presentSet.has(t));
        } catch (e) {
          console.warn('[health] schema probe failed:', e.message);
          missingTables = ['<probe_failed>'];
        }

        // ── Optional column probe for the notifications extension ──
        let missingNotificationColumns = [];
        try {
          const cols = await many(
            `select column_name
               from information_schema.columns
              where table_schema = 'public' and table_name = 'notifications'
                and column_name = ANY($1::text[])`,
            [['category', 'action_url']]
          );
          const have = new Set(cols.map(c => c.column_name));
          missingNotificationColumns = ['category', 'action_url'].filter(c => !have.has(c));
        } catch (_) {
          missingNotificationColumns = ['<probe_failed>'];
        }

        return res.json({
          ...publicBody,
          media: 'supabase-storage',
          placements: true,
          content_lifecycle: 'publish-now-send-back',
          review_comment_join: true,
          contact_messages: true,
          advertisements: true,
          advertiser_portal: true,
          monetization: true,
          orphan_school_managers: orphan ? orphan.c : 0,
          active_password_resets: pendingResets ? pendingResets.c : 0,
          pending_advertisers: pendingAdvertisers ? pendingAdvertisers.c : 0,

          // ── Schema health ──
          schema_ok: missingTables.length === 0 && missingNotificationColumns.length === 0,
          missing_tables: missingTables,
          missing_notification_columns: missingNotificationColumns,
        });
      }
    } catch (_) {
      // Ignore invalid token — fall through to public health body
    }
  }

  if (!dbOk) {
    return res.status(503).json({
      ok: false,
      version: '1.9.1',
      error: 'Database unreachable',
      hint: 'Check DATABASE_URL on Render. It should use the Supabase pooler (port 6543), and the Supabase project must not be paused.',
    });
  }
  res.json(publicBody);
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

/* Advertiser portal routes */
app.get(['/Advertiser', '/Advertiser/'], (req, res, next) => {
  res.sendFile(path.join(PUBLIC_DIR, 'Advertiser', 'login.html'), (err) => { if (err) next(); });
});

app.get(
  ['/Advertiser/login', '/Advertiser/login.html',
   '/Advertiser/Login', '/Advertiser/Login.html'],
  (req, res, next) => {
    res.sendFile(path.join(PUBLIC_DIR, 'Advertiser', 'login.html'), (err) => { if (err) next(); });
  }
);

app.get(['/Advertiser/dashboard', '/Advertiser/Index.html'], (req, res, next) => {
  res.sendFile(path.join(PUBLIC_DIR, 'Advertiser', 'Index.html'), (err) => { if (err) next(); });
});

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
  console.log(`CampusNaija backend v1.9.1 listening on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Owner email: ${OWNER_EMAIL}`);
  console.log(`Public dir: ${PUBLIC_DIR}`);
  console.log(`Media storage: Supabase bucket "${MEDIA_BUCKET}"`);
  console.log('API base: /api');
});

// Seed only — schemas are managed in Supabase SQL editor
(async () => {
  await seed().catch(e => console.error('[seed]', e.message));
})();

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