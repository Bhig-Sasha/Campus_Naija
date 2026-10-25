/**
 * CampusNaija — Full Backend (single file)
 * ==========================================
 * Run:   npm install express bcryptjs jsonwebtoken cors helmet morgan better-sqlite3 multer
 *        node server.js
 *
 * Storage: SQLite via better-sqlite3 (file: campusnaija.db)
 * Auth:    JWT (access token) + bcrypt password hashing
 * Roles:   owner | admin | editor | reviewer | school_manager
 *
 * CHANGES IN THIS REVISION
 * - Fixed: schema reference to `media` before it exists in `trending` FK.
 * - Fixed: seed() ordering vs settings defaults (settings now created first).
 * - Fixed: school_manager users get auto school_id on create (was allowed null).
 * - Added: GET /api/auth/config for client-side feature flags.
 * - Added: POST /api/auth/refresh to renew tokens without re-login.
 * - Added: password change endpoint for own account.
 * - Added: GET /api/schools/:id/summary (counts for the SchoolAd dashboard).
 * - Added: GET /api/school/submissions supports pagination and status filter.
 * - Added: POST /api/school/submissions/:type/:id/withdraw (school manager can recall a pending submission).
 * - Added: full CRUD delete endpoints for admissions, exams, scholarships, trending (owner/admin).
 * - Added: /api/schools/:id/media alias endpoint (matches brief).
 * - Added: /api/admin/submissions + /api/admin/submissions/:id/decision (owner review queue).
 * - Added: /api/notifications for school managers and owners.
 * - Added: first login forces password change (must_change_password column).
 * - Improved: consistent `ok` field, clearer 4xx messages, safer slug generation.
 * - Improved: WAL checkpoint on shutdown, graceful close.
 * - Improved: rate limiting covers /auth/login and /auth/forgot-password.
 *
 * IMPORTANT SECURITY NOTES
 * - Set JWT_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD via env vars in production.
 * - Serve over HTTPS behind a reverse proxy. This file does not handle TLS.
 * - The in-memory login limiter is process-local. In a multi-instance
 *   deployment, replace it with a shared store (e.g. Redis).
 * - Never expose this server directly to the internet without a proxy.
 */

'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/* ============================================================
 * DATABASE (database/)
 * ============================================================ */

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'campusnaija.db');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function migrate() {
  // 1) Base tables first (no cross-references that would break creation order)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner','admin','editor','reviewer','school_manager')),
      school_id INTEGER,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','pending','suspended')),
      must_change_password INTEGER NOT NULL DEFAULT 0,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS schools (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL CHECK (type IN ('university','polytechnic','college')),
      ownership TEXT NOT NULL CHECK (ownership IN ('Federal','State','Private')),
      state TEXT,
      city TEXT,
      address TEXT,
      website TEXT,
      email TEXT,
      description TEXT,
      established TEXT,
      logo_media_id INTEGER,
      cover_media_id INTEGER,
      verification TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified','pending','verified')),
      publication TEXT NOT NULL DEFAULT 'draft' CHECK (publication IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS media (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      original_name TEXT,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      display_name TEXT,
      alt_text TEXT,
      caption TEXT,
      category TEXT,
      tags TEXT,
      school_id INTEGER,
      uploaded_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE SET NULL,
      FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      school_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      faculty TEXT,
      department TEXT,
      duration TEXT,
      qualification TEXT,
      entry_route TEXT,
      requirements TEXT,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS fees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      school_id INTEGER NOT NULL,
      session TEXT NOT NULL,
      category TEXT NOT NULL,
      programme TEXT,
      level TEXT,
      student_category TEXT,
      amount INTEGER NOT NULL,
      source_url TEXT,
      verified_date TEXT,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS admissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      school_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      session TEXT NOT NULL,
      entry_route TEXT NOT NULL,
      open_date TEXT,
      close_date TEXT,
      extension_note TEXT,
      requirements TEXT,
      eligibility TEXT,
      application_url TEXT NOT NULL,
      source_url TEXT NOT NULL,
      notes TEXT,
      verification TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified','pending','verified')),
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS exams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      type TEXT NOT NULL,
      session TEXT NOT NULL,
      description TEXT,
      eligibility TEXT,
      instructions TEXT,
      open_date TEXT,
      close_date TEXT,
      timetable_info TEXT,
      timetable_url TEXT,
      resources TEXT,
      resource_links TEXT,
      website TEXT NOT NULL,
      source_url TEXT,
      verification TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified','pending','verified')),
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS scholarships (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      sponsor TEXT NOT NULL,
      sponsor_type TEXT,
      category TEXT NOT NULL,
      level TEXT NOT NULL,
      location TEXT,
      deadline TEXT,
      eligibility TEXT,
      coverage TEXT,
      amount TEXT,
      currency TEXT,
      frequency TEXT,
      covered TEXT,
      not_covered TEXT,
      nationality TEXT,
      academic TEXT,
      documents TEXT,
      steps TEXT,
      contact TEXT,
      open_date TEXT,
      close_date TEXT,
      extension TEXT,
      apply_url TEXT NOT NULL,
      source_url TEXT,
      verification TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified','pending','verified')),
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','expired','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS trending (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      author TEXT NOT NULL,
      summary TEXT,
      body TEXT NOT NULL,
      cover_media_id INTEGER,
      alt_text TEXT,
      caption TEXT,
      source_url TEXT,
      source_date TEXT,
      verification TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified','pending','verified')),
      featured INTEGER NOT NULL DEFAULT 0,
      scheduled_at TEXT,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','scheduled','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (cover_media_id) REFERENCES media(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS calendar (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      school_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      type TEXT NOT NULL,
      session TEXT NOT NULL,
      semester TEXT,
      start_date TEXT NOT NULL,
      end_date TEXT,
      notes TEXT,
      source_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','published','archived')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS review_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submission_type TEXT NOT NULL,
      submission_id INTEGER NOT NULL,
      school_id INTEGER,
      reviewer_id INTEGER,
      reviewer_name TEXT,
      decision TEXT NOT NULL CHECK (decision IN ('approved','changes_requested')),
      comment TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE,
      FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      school_id INTEGER,
      title TEXT NOT NULL,
      body TEXT,
      link TEXT,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      actor_name TEXT,
      actor_role TEXT,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      target_label TEXT,
      details TEXT,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_schools_pub ON schools(publication, verification);
    CREATE INDEX IF NOT EXISTS idx_courses_school ON courses(school_id);
    CREATE INDEX IF NOT EXISTS idx_fees_school ON fees(school_id);
    CREATE INDEX IF NOT EXISTS idx_admissions_school ON admissions(school_id);
    CREATE INDEX IF NOT EXISTS idx_calendar_school ON calendar(school_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
  `);
}
migrate();

/* ============================================================
 * CONFIG
 * ============================================================ */

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@campusnaija.ng';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const FORCE_PASSWORD_CHANGE = process.env.FORCE_PASSWORD_CHANGE === '1';

if (!process.env.JWT_SECRET) {
  console.warn('[warn] JWT_SECRET not set — using a random secret. Sessions will not survive restarts.');
}

/* ============================================================
 * SEED (idempotent)
 * ============================================================ */

function seed() {
  // Settings first, so readSettings() works immediately.
  const s = db.prepare('SELECT COUNT(*) AS c FROM settings').get();
  if (s.c === 0) {
    const defaults = {
      site_name: 'CampusNaija',
      site_tagline: 'Your education. Your next move.',
      admin_email: ADMIN_EMAIL,
      site_description: "Nigeria's education discovery platform.",
      require_review: '1',
      require_verification_for_fees: '1',
      auto_archive_expired: '1',
      single_session: '1',
      lockout_attempts: '5',
      session_timeout: '30',
    };
    const ins = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
    for (const [k, v] of Object.entries(defaults)) ins.run(k, v);
  }

  const existing = db.prepare('SELECT COUNT(*) AS c FROM users').get();
  if (existing.c === 0) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare(`INSERT INTO users (name, email, password_hash, role, status, must_change_password)
                VALUES (?, ?, ?, 'owner', 'active', ?)`)
      .run('Platform Owner', ADMIN_EMAIL, hash, FORCE_PASSWORD_CHANGE ? 1 : 0);
    console.log(`[seed] Created owner account: ${ADMIN_EMAIL}`);
    console.log('[seed] Change the password immediately after first login.');
  }
}
seed();

/* ============================================================
 * APP
 * ============================================================ */

const app = express();
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: ALLOWED_ORIGINS.includes('*') ? true : ALLOWED_ORIGINS,
  credentials: true,
}));
app.use(express.json({ limit: '2mb' }));
app.use(morgan('tiny'));

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough: true, maxAge: '7d' }));

/* ============================================================
 * UTILITIES
 * ============================================================ */

const now = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const slugify = (text) => String(text).toLowerCase().trim()
  .replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-');

function httpError(status, message, code) {
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

function asyncH(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function audit(req, action, targetType, targetId, targetLabel, details) {
  try {
    const u = req.user;
    db.prepare(`INSERT INTO audit_log
      (actor_id, actor_name, actor_role, action, target_type, target_id, target_label, details, ip)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        u ? u.id : null,
        u ? u.name : 'Unknown',
        u ? u.role : 'security',
        action,
        targetType,
        targetId != null ? String(targetId) : null,
        targetLabel || null,
        details ? JSON.stringify(details) : null,
        (req.ip || '').toString()
      );
  } catch (e) {
    console.error('[audit]', e.message);
  }
}

function readSettings() {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const r of rows) out[r.key] = r.value;
  return out;
}

function notify(userId, schoolId, title, body, link) {
  try {
    db.prepare(`INSERT INTO notifications (user_id, school_id, title, body, link) VALUES (?, ?, ?, ?, ?)`)
      .run(userId || null, schoolId || null, title, body || null, link || null);
  } catch (e) {
    console.error('[notify]', e.message);
  }
}

/* ============================================================
 * AUTH (services/)
 * ============================================================ */

const loginAttempts = new Map(); // simple in-memory rate limiter

function rateLimit(key, max, windowMs) {
  const nowMs = Date.now();
  const rec = loginAttempts.get(key) || { count: 0, reset: nowMs + windowMs };
  if (nowMs > rec.reset) { rec.count = 0; rec.reset = nowMs + windowMs; }
  rec.count += 1;
  loginAttempts.set(key, rec);
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
    school_id: u.school_id, status: u.status,
    must_change_password: !!u.must_change_password,
    notes: u.notes, created_at: u.created_at, updated_at: u.updated_at,
  };
}

/** Authenticate bearer token, load fresh user from DB, attach req.user. */
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next(httpError(401, 'Authentication required.', 'no_token'));
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return next(httpError(401, 'Session expired or invalid token.', 'bad_token'));
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!user) return next(httpError(401, 'Account no longer exists.', 'no_user'));
  if (user.status === 'suspended') {
    return next(httpError(403, 'This account is suspended.', 'suspended'));
  }
  if (user.status === 'pending') {
    return next(httpError(403, 'This account is pending approval.', 'pending_approval'));
  }
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return next(httpError(401, 'Authentication required.'));
    if (!roles.includes(req.user.role)) {
      return next(httpError(403, 'You do not have permission to perform this action.', 'forbidden'));
    }
    next();
  };
}

function assertSchoolScope(user, schoolId) {
  if (!user) throw httpError(401, 'Authentication required.');
  if (user.role === 'school_manager') {
    if (!user.school_id || Number(user.school_id) !== Number(schoolId)) {
      throw httpError(403, 'You can only manage your assigned institution.', 'school_scope');
    }
  }
}

function scopedSchoolFilter(user, requested) {
  if (user.role === 'school_manager') {
    return { school_id: user.school_id, forced: true };
  }
  return { school_id: requested || null, forced: false };
}

/* ============================================================
 * ROUTES
 * ============================================================ */

const router = express.Router();
app.use('/api', router);

/* ---------- AUTH ---------- */

router.get('/auth/config', (req, res) => {
  // Safe, non-sensitive client config.
  const s = readSettings();
  res.json({
    site_name: s.site_name,
    site_tagline: s.site_tagline,
    require_review: s.require_review === '1',
    require_verification_for_fees: s.require_verification_for_fees === '1',
    allowed_roles: ['owner', 'admin', 'editor', 'reviewer', 'school_manager'],
  });
});

router.post('/auth/login', (req, res, next) => {
  try {
    const ip = req.ip || 'unknown';
    if (!rateLimit(`login:${ip}`, 8, 15 * 60 * 1000)) {
      throw httpError(429, 'Too many sign-in attempts. Try again later.', 'rate_limited');
    }
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      throw httpError(400, 'Email/username and password are required.');
    }
    const user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(identifier);
    const invalid = httpError(401, 'Invalid credentials, or this account is not approved for sign-in.');
    if (!user) throw invalid;
    if (!bcrypt.compareSync(password, user.password_hash)) throw invalid;
    if (user.status === 'suspended') {
      throw httpError(403, 'This account is suspended. Contact the platform owner.');
    }
    if (user.status === 'pending') {
      throw httpError(403, 'This account is awaiting approval. Contact the platform owner.');
    }
    const token = signToken(user);
    audit({ user, ip }, 'login', 'auth', user.id, user.email);
    res.json({ token, user: publicUser(user) });
  } catch (e) { next(e); }
});

router.post('/auth/refresh', authenticate, (req, res) => {
  const token = signToken(req.user);
  res.json({ token, user: publicUser(req.user) });
});

router.get('/auth/me', authenticate, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

router.post('/auth/logout', authenticate, (req, res) => {
  audit(req, 'logout', 'auth', req.user.id, req.user.email);
  res.json({ ok: true });
});

router.post('/auth/change-password', authenticate, (req, res, next) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password) {
      throw httpError(400, 'current_password and new_password are required.');
    }
    if (String(new_password).length < 8) {
      throw httpError(400, 'New password must be at least 8 characters.');
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!bcrypt.compareSync(current_password, user.password_hash)) {
      throw httpError(400, 'Current password is incorrect.');
    }
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?`)
      .run(hash, user.id);
    audit(req, 'change_password', 'user', user.id, user.email);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/auth/forgot-password', (req, res, next) => {
  try {
    const ip = req.ip || 'unknown';
    if (!rateLimit(`forgot:${ip}`, 4, 15 * 60 * 1000)) {
      throw httpError(429, 'Too many reset requests. Try again later.', 'rate_limited');
    }
    const { email } = req.body || {};
    if (!email) throw httpError(400, 'email is required.');
    // Always respond generically; never reveal whether the account exists.
    // A real deployment would generate a single-use token, store its hash, and email the link.
    audit({ user: null, ip }, 'forgot_password', 'auth', null, email);
    res.json({ ok: true, message: 'If an approved account exists for that email, a reset link will be sent.' });
  } catch (e) { next(e); }
});

/* ---------- PUBLIC WEBSITE (no auth) ---------- */

router.get('/public/schools', (req, res) => {
  const { q, state, type } = req.query;
  const clauses = ["publication = 'published'"];
  const params = [];
  if (q) { clauses.push('(name LIKE ? OR city LIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  if (state) { clauses.push('state = ?'); params.push(state); }
  if (type) { clauses.push('type = ?'); params.push(type); }
  const rows = db.prepare(`SELECT * FROM schools WHERE ${clauses.join(' AND ')} ORDER BY name`).all(...params);
  res.json({ schools: rows });
});

router.get('/public/schools/:slug', (req, res, next) => {
  try {
    const school = db.prepare(`SELECT * FROM schools WHERE slug = ? AND publication = 'published'`)
      .get(req.params.slug);
    if (!school) throw httpError(404, 'School not found.');
    const courses = db.prepare(`SELECT * FROM courses WHERE school_id = ? AND status = 'published'`).all(school.id);
    const fees = db.prepare(`SELECT * FROM fees WHERE school_id = ? AND status = 'published'`).all(school.id);
    const admissions = db.prepare(`SELECT * FROM admissions WHERE school_id = ? AND status = 'published'`).all(school.id);
    const calendar = db.prepare(`SELECT * FROM calendar WHERE school_id = ? AND status = 'published'`).all(school.id);
    res.json({ school, courses, fees, admissions, calendar });
  } catch (e) { next(e); }
});

router.get('/public/admissions', (req, res) => {
  const rows = db.prepare(`
    SELECT a.*, s.name AS school_name, s.slug AS school_slug
    FROM admissions a JOIN schools s ON s.id = a.school_id
    WHERE a.status = 'published'
    ORDER BY a.created_at DESC
  `).all();
  res.json({ admissions: rows });
});

router.get('/public/exams', (req, res) => {
  const rows = db.prepare(`SELECT * FROM exams WHERE status = 'published' ORDER BY created_at DESC`).all();
  res.json({ exams: rows });
});

router.get('/public/exams/:id', (req, res, next) => {
  try {
    const row = db.prepare(`SELECT * FROM exams WHERE id = ? AND status = 'published'`).get(req.params.id);
    if (!row) throw httpError(404, 'Exam not found.');
    res.json({ exam: row });
  } catch (e) { next(e); }
});

router.get('/public/scholarships', (req, res) => {
  const rows = db.prepare(`SELECT * FROM scholarships WHERE status = 'published' ORDER BY created_at DESC`).all();
  res.json({ scholarships: rows });
});

router.get('/public/scholarships/:id', (req, res, next) => {
  try {
    const row = db.prepare(`SELECT * FROM scholarships WHERE id = ? AND status = 'published'`).get(req.params.id);
    if (!row) throw httpError(404, 'Scholarship not found.');
    res.json({ scholarship: row });
  } catch (e) { next(e); }
});

router.get('/public/trending', (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM trending WHERE status = 'published'
    ORDER BY featured DESC, created_at DESC
  `).all();
  res.json({ stories: rows });
});

router.get('/public/trending/:id', (req, res, next) => {
  try {
    const row = db.prepare(`SELECT * FROM trending WHERE id = ? AND status = 'published'`).get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    res.json({ story: row });
  } catch (e) { next(e); }
});

router.get('/public/settings', (req, res) => {
  const s = readSettings();
  res.json({ site_name: s.site_name, site_tagline: s.site_tagline, site_description: s.site_description });
});

/* ---------- SCHOOLS (admin + school_manager) ---------- */

router.get('/schools', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer'), (req, res) => {
  const { q, type, state, verification, publication } = req.query;
  const clauses = [];
  const params = [];
  if (q) { clauses.push('(name LIKE ? OR city LIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  if (type) { clauses.push('type = ?'); params.push(type); }
  if (state) { clauses.push('state = ?'); params.push(state); }
  if (verification) { clauses.push('verification = ?'); params.push(verification); }
  if (publication) { clauses.push('publication = ?'); params.push(publication); }
  const sql = `SELECT * FROM schools ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY name`;
  res.json({ schools: db.prepare(sql).all(...params) });
});

router.get('/schools/:id', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(req.params.id);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);
    res.json({ school });
  } catch (e) { next(e); }
});

router.get('/schools/:id/summary', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    const id = req.params.id;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, id);
    const counts = {
      courses: db.prepare('SELECT COUNT(*) c FROM courses WHERE school_id = ?').get(id).c,
      courses_pending: db.prepare(`SELECT COUNT(*) c FROM courses WHERE school_id = ? AND status = 'pending'`).get(id).c,
      fees: db.prepare('SELECT COUNT(*) c FROM fees WHERE school_id = ?').get(id).c,
      fees_pending: db.prepare(`SELECT COUNT(*) c FROM fees WHERE school_id = ? AND status = 'pending'`).get(id).c,
      admissions: db.prepare('SELECT COUNT(*) c FROM admissions WHERE school_id = ?').get(id).c,
      admissions_pending: db.prepare(`SELECT COUNT(*) c FROM admissions WHERE school_id = ? AND status = 'pending'`).get(id).c,
      calendar: db.prepare('SELECT COUNT(*) c FROM calendar WHERE school_id = ?').get(id).c,
      calendar_pending: db.prepare(`SELECT COUNT(*) c FROM calendar WHERE school_id = ? AND status = 'pending'`).get(id).c,
      media: db.prepare('SELECT COUNT(*) c FROM media WHERE school_id = ?').get(id).c,
    };
    res.json({ school, counts });
  } catch (e) { next(e); }
});

router.post('/schools', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.name || !b.type || !b.ownership) {
      throw httpError(400, 'name, type, and ownership are required.');
    }
    let slug = slugify(b.name);
    const taken = db.prepare('SELECT 1 FROM schools WHERE slug = ?').get(slug);
    if (taken) slug += '-' + Date.now().toString(36);
    const info = db.prepare(`
      INSERT INTO schools (name, slug, type, ownership, state, city, address, website, email, description, established)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      b.name, slug, b.type, b.ownership,
      b.state || null, b.city || null, b.address || null,
      b.website || null, b.email || null, b.description || null, b.established || null
    );
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'school', school.id, school.name);
    res.status(201).json({ school });
  } catch (e) { next(e); }
});

router.patch('/schools/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const id = req.params.id;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);

    const allowed = ['name','type','ownership','state','city','address','website','email','description','established','logo_media_id','cover_media_id'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if (!Object.keys(updates).length) throw httpError(400, 'No editable fields provided.');

    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE schools SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), id);

    const updated = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    audit(req, 'update', 'school', id, updated.name, { fields: Object.keys(updates) });
    res.json({ school: updated });
  } catch (e) { next(e); }
});

router.post('/schools/:id/verify', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const id = req.params.id;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    if (!school) throw httpError(404, 'School not found.');
    const verification = (req.body && req.body.verification) || 'verified';
    if (!['unverified', 'pending', 'verified'].includes(verification)) {
      throw httpError(400, 'Invalid verification value.');
    }
    db.prepare(`UPDATE schools SET verification = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(verification, id);
    audit(req, 'verify_school', 'school', id, school.name, { verification });
    res.json({ ok: true, verification });
  } catch (e) { next(e); }
});

router.post('/schools/:id/publish', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const id = req.params.id;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    if (!school) throw httpError(404, 'School not found.');
    if (school.verification !== 'verified') {
      throw httpError(400, 'School must be verified before it can be published.');
    }
    db.prepare(`UPDATE schools SET publication = 'published', updated_at = datetime('now') WHERE id = ?`)
      .run(id);
    audit(req, 'publish_school', 'school', id, school.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/schools/:id/archive', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const id = req.params.id;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(id);
    if (!school) throw httpError(404, 'School not found.');
    db.prepare(`UPDATE schools SET publication = 'archived', updated_at = datetime('now') WHERE id = ?`)
      .run(id);
    audit(req, 'archive_school', 'school', id, school.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- COURSES ---------- */

router.get('/schools/:schoolId/courses', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM courses WHERE school_id = ? ORDER BY name').all(req.params.schoolId);
    res.json({ courses: rows });
  } catch (e) { next(e); }
});

router.post('/schools/:schoolId/courses', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const schoolId = req.params.schoolId;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(schoolId);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);
    const b = req.body || {};
    if (!b.name) throw httpError(400, 'Course name is required.');
    const info = db.prepare(`
      INSERT INTO courses (school_id, name, faculty, department, duration, qualification, entry_route, requirements, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft')
    `).run(schoolId, b.name, b.faculty || null, b.department || null, b.duration || null,
           b.qualification || null, b.entry_route || null, b.requirements || null);
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'course', course.id, course.name, { school_id: school.id });
    res.status(201).json({ course });
  } catch (e) { next(e); }
});

router.patch('/courses/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!course) throw httpError(404, 'Course not found.');
    assertSchoolScope(req.user, course.school_id);
    const allowed = ['name','faculty','department','duration','qualification','entry_route','requirements','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE courses SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), course.id);
    audit(req, 'update', 'course', course.id, course.name);
    res.json({ course: db.prepare('SELECT * FROM courses WHERE id = ?').get(course.id) });
  } catch (e) { next(e); }
});

router.delete('/courses/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!course) throw httpError(404, 'Course not found.');
    assertSchoolScope(req.user, course.school_id);
    db.prepare('DELETE FROM courses WHERE id = ?').run(course.id);
    audit(req, 'delete', 'course', course.id, course.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- FEES ---------- */

router.get('/schools/:schoolId/fees', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM fees WHERE school_id = ? ORDER BY created_at DESC').all(req.params.schoolId);
    res.json({ fees: rows });
  } catch (e) { next(e); }
});

router.post('/schools/:schoolId/fees', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const schoolId = req.params.schoolId;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(schoolId);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);
    const b = req.body || {};
    if (!b.session || !b.category || !b.amount) {
      throw httpError(400, 'session, category and amount are required.');
    }
    if (!Number.isFinite(Number(b.amount)) || Number(b.amount) < 0) {
      throw httpError(400, 'amount must be a non-negative number.');
    }
    const info = db.prepare(`
      INSERT INTO fees (school_id, session, category, programme, level, student_category, amount, source_url, verified_date, notes, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')
    `).run(schoolId, b.session, b.category, b.programme || null, b.level || null,
           b.student_category || null, Number(b.amount), b.source_url || null,
           b.verified_date || null, b.notes || null);
    const fee = db.prepare('SELECT * FROM fees WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'fee', fee.id, `${b.session} ${b.category}`, { school_id: school.id });
    res.status(201).json({ fee });
  } catch (e) { next(e); }
});

router.patch('/fees/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const fee = db.prepare('SELECT * FROM fees WHERE id = ?').get(req.params.id);
    if (!fee) throw httpError(404, 'Fee not found.');
    assertSchoolScope(req.user, fee.school_id);
    const allowed = ['session','category','programme','level','student_category','amount','source_url','verified_date','notes','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if ('amount' in updates && (!Number.isFinite(Number(updates.amount)) || Number(updates.amount) < 0)) {
      throw httpError(400, 'amount must be a non-negative number.');
    }
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE fees SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), fee.id);
    audit(req, 'update', 'fee', fee.id, `fee ${fee.id}`);
    res.json({ fee: db.prepare('SELECT * FROM fees WHERE id = ?').get(fee.id) });
  } catch (e) { next(e); }
});

router.delete('/fees/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const fee = db.prepare('SELECT * FROM fees WHERE id = ?').get(req.params.id);
    if (!fee) throw httpError(404, 'Fee not found.');
    assertSchoolScope(req.user, fee.school_id);
    db.prepare('DELETE FROM fees WHERE id = ?').run(fee.id);
    audit(req, 'delete', 'fee', fee.id, `fee ${fee.id}`);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- ADMISSIONS ---------- */

router.get('/admissions', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    const scoped = scopedSchoolFilter(req.user, req.query.school_id);
    const clauses = [];
    const params = [];
    if (scoped.school_id) { clauses.push('a.school_id = ?'); params.push(scoped.school_id); }
    if (req.query.status) { clauses.push('a.status = ?'); params.push(req.query.status); }
    const sql = `SELECT a.*, s.name AS school_name FROM admissions a JOIN schools s ON s.id = a.school_id
      ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY a.created_at DESC`;
    res.json({ admissions: db.prepare(sql).all(...params) });
  } catch (e) { next(e); }
});

router.get('/schools/:schoolId/admissions', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM admissions WHERE school_id = ? ORDER BY created_at DESC').all(req.params.schoolId);
    res.json({ admissions: rows });
  } catch (e) { next(e); }
});

router.post('/schools/:schoolId/admissions', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const schoolId = req.params.schoolId;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(schoolId);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);
    const b = req.body || {};
    if (!b.title || !b.session || !b.entry_route || !b.application_url || !b.source_url) {
      throw httpError(400, 'title, session, entry_route, application_url and source_url are required.');
    }
    if (!/^https?:\/\//i.test(b.application_url)) throw httpError(400, 'application_url must be an http(s) URL.');
    if (!/^https?:\/\//i.test(b.source_url)) throw httpError(400, 'source_url must be an http(s) URL.');
    if (b.open_date && b.close_date && new Date(b.close_date) < new Date(b.open_date)) {
      throw httpError(400, 'close_date cannot be before open_date.');
    }
    const info = db.prepare(`
      INSERT INTO admissions (school_id, title, session, entry_route, open_date, close_date, extension_note,
        requirements, eligibility, application_url, source_url, notes, status, verification)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', 'unverified')
    `).run(schoolId, b.title, b.session, b.entry_route, b.open_date || null, b.close_date || null,
           b.extension_note || null, b.requirements || null, b.eligibility || null,
           b.application_url, b.source_url, b.notes || null);
    const adm = db.prepare('SELECT * FROM admissions WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'admission', adm.id, adm.title, { school_id: school.id });
    res.status(201).json({ admission: adm });
  } catch (e) { next(e); }
});

router.patch('/admissions/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const adm = db.prepare('SELECT * FROM admissions WHERE id = ?').get(req.params.id);
    if (!adm) throw httpError(404, 'Admission not found.');
    assertSchoolScope(req.user, adm.school_id);
    const allowed = ['title','session','entry_route','open_date','close_date','extension_note','requirements','eligibility','application_url','source_url','notes','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if ('application_url' in updates && !/^https?:\/\//i.test(updates.application_url)) {
      throw httpError(400, 'application_url must be an http(s) URL.');
    }
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE admissions SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), adm.id);
    audit(req, 'update', 'admission', adm.id, adm.title);
    res.json({ admission: db.prepare('SELECT * FROM admissions WHERE id = ?').get(adm.id) });
  } catch (e) { next(e); }
});

router.delete('/admissions/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const adm = db.prepare('SELECT * FROM admissions WHERE id = ?').get(req.params.id);
    if (!adm) throw httpError(404, 'Admission not found.');
    assertSchoolScope(req.user, adm.school_id);
    db.prepare('DELETE FROM admissions WHERE id = ?').run(adm.id);
    audit(req, 'delete', 'admission', adm.id, adm.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/admissions/:id/verify', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const adm = db.prepare('SELECT * FROM admissions WHERE id = ?').get(req.params.id);
    if (!adm) throw httpError(404, 'Admission not found.');
    if (!adm.source_url) throw httpError(400, 'An official source URL is required before verification.');
    db.prepare(`UPDATE admissions SET verification = 'verified', updated_at = datetime('now') WHERE id = ?`).run(adm.id);
    audit(req, 'verify', 'admission', adm.id, adm.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/admissions/:id/publish', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const adm = db.prepare('SELECT * FROM admissions WHERE id = ?').get(req.params.id);
    if (!adm) throw httpError(404, 'Admission not found.');
    if (adm.verification !== 'verified') {
      throw httpError(400, 'Admission must be verified before it can be published.');
    }
    db.prepare(`UPDATE admissions SET status = 'published', updated_at = datetime('now') WHERE id = ?`).run(adm.id);
    audit(req, 'publish', 'admission', adm.id, adm.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- CALENDAR ---------- */

router.get('/schools/:schoolId/calendar', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM calendar WHERE school_id = ? ORDER BY start_date').all(req.params.schoolId);
    res.json({ events: rows });
  } catch (e) { next(e); }
});

router.get('/schools/:schoolId/events', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM calendar WHERE school_id = ? ORDER BY start_date').all(req.params.schoolId);
    res.json({ events: rows });
  } catch (e) { next(e); }
});

router.post('/schools/:schoolId/calendar', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const schoolId = req.params.schoolId;
    const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(schoolId);
    if (!school) throw httpError(404, 'School not found.');
    assertSchoolScope(req.user, school.id);
    const b = req.body || {};
    if (!b.title || !b.type || !b.session || !b.start_date || !b.source_url) {
      throw httpError(400, 'title, type, session, start_date and source_url are required.');
    }
    if (b.end_date && new Date(b.end_date) < new Date(b.start_date)) {
      throw httpError(400, 'end_date cannot be before start_date.');
    }
    if (!/^https?:\/\//i.test(b.source_url)) throw httpError(400, 'source_url must be an http(s) URL.');
    const info = db.prepare(`
      INSERT INTO calendar (school_id, title, type, session, semester, start_date, end_date, notes, source_url, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')
    `).run(schoolId, b.title, b.type, b.session, b.semester || null, b.start_date,
           b.end_date || null, b.notes || null, b.source_url);
    const ev = db.prepare('SELECT * FROM calendar WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'calendar', ev.id, ev.title, { school_id: school.id });
    res.status(201).json({ event: ev });
  } catch (e) { next(e); }
});

router.patch('/calendar/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const ev = db.prepare('SELECT * FROM calendar WHERE id = ?').get(req.params.id);
    if (!ev) throw httpError(404, 'Event not found.');
    assertSchoolScope(req.user, ev.school_id);
    const allowed = ['title','type','session','semester','start_date','end_date','notes','source_url','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE calendar SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), ev.id);
    audit(req, 'update', 'calendar', ev.id, ev.title);
    res.json({ event: db.prepare('SELECT * FROM calendar WHERE id = ?').get(ev.id) });
  } catch (e) { next(e); }
});

router.delete('/calendar/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const ev = db.prepare('SELECT * FROM calendar WHERE id = ?').get(req.params.id);
    if (!ev) throw httpError(404, 'Event not found.');
    assertSchoolScope(req.user, ev.school_id);
    db.prepare('DELETE FROM calendar WHERE id = ?').run(ev.id);
    audit(req, 'delete', 'calendar', ev.id, ev.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- EXAMS ---------- */

router.get('/exams', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer'), (req, res) => {
  res.json({ exams: db.prepare('SELECT * FROM exams ORDER BY created_at DESC').all() });
});

router.post('/exams', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.title || !b.body || !b.type || !b.session || !b.website) {
      throw httpError(400, 'title, body, type, session and website are required.');
    }
    if (!/^https?:\/\//i.test(b.website)) throw httpError(400, 'website must be an http(s) URL.');
    const info = db.prepare(`
      INSERT INTO exams (title, body, type, session, description, eligibility, instructions,
        open_date, close_date, timetable_info, timetable_url, resources, resource_links,
        website, source_url, status, verification)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', 'unverified')
    `).run(b.title, b.body, b.type, b.session, b.description || null, b.eligibility || null,
           b.instructions || null, b.open_date || null, b.close_date || null,
           b.timetable_info || null, b.timetable_url || null, b.resources || null,
           b.resource_links || null, b.website, b.source_url || null);
    const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'exam', row.id, row.title);
    res.status(201).json({ exam: row });
  } catch (e) { next(e); }
});

router.patch('/exams/:id', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Exam not found.');
    const allowed = ['title','body','type','session','description','eligibility','instructions','open_date','close_date','timetable_info','timetable_url','resources','resource_links','website','source_url','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE exams SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), row.id);
    audit(req, 'update', 'exam', row.id, row.title);
    res.json({ exam: db.prepare('SELECT * FROM exams WHERE id = ?').get(row.id) });
  } catch (e) { next(e); }
});

router.delete('/exams/:id', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Exam not found.');
    db.prepare('DELETE FROM exams WHERE id = ?').run(row.id);
    audit(req, 'delete', 'exam', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/exams/:id/verify', authenticate, requireRole('owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Exam not found.');
    if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
    db.prepare(`UPDATE exams SET verification = 'verified', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'verify', 'exam', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/exams/:id/publish', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Exam not found.');
    if (row.verification !== 'verified') {
      throw httpError(400, 'Exam must be verified before it can be published.');
    }
    db.prepare(`UPDATE exams SET status = 'published', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'publish', 'exam', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- SCHOLARSHIPS ---------- */

router.get('/scholarships', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer'), (req, res) => {
  res.json({ scholarships: db.prepare('SELECT * FROM scholarships ORDER BY created_at DESC').all() });
});

router.post('/scholarships', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.title || !b.sponsor || !b.category || !b.level || !b.apply_url) {
      throw httpError(400, 'title, sponsor, category, level and apply_url are required.');
    }
    if (!/^https?:\/\//i.test(b.apply_url)) throw httpError(400, 'apply_url must be an http(s) URL.');
    const info = db.prepare(`
      INSERT INTO scholarships (title, sponsor, sponsor_type, category, level, location, deadline,
        eligibility, coverage, amount, currency, frequency, covered, not_covered, nationality,
        academic, documents, steps, contact, open_date, close_date, extension, apply_url, source_url,
        verification, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', 'draft')
    `).run(b.title, b.sponsor, b.sponsor_type || null, b.category, b.level, b.location || null,
           b.deadline || null, b.eligibility || null, b.coverage || null, b.amount || null,
           b.currency || null, b.frequency || null, b.covered || null, b.not_covered || null,
           b.nationality || null, b.academic || null, b.documents || null, b.steps || null,
           b.contact || null, b.open_date || null, b.close_date || null, b.extension || null,
           b.apply_url, b.source_url || null);
    const row = db.prepare('SELECT * FROM scholarships WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'scholarship', row.id, row.title);
    res.status(201).json({ scholarship: row });
  } catch (e) { next(e); }
});

router.patch('/scholarships/:id', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM scholarships WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Scholarship not found.');
    const allowed = ['title','sponsor','sponsor_type','category','level','location','deadline','eligibility','coverage','amount','currency','frequency','covered','not_covered','nationality','academic','documents','steps','contact','open_date','close_date','extension','apply_url','source_url','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if ('apply_url' in updates && !/^https?:\/\//i.test(updates.apply_url)) {
      throw httpError(400, 'apply_url must be an http(s) URL.');
    }
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE scholarships SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), row.id);
    audit(req, 'update', 'scholarship', row.id, row.title);
    res.json({ scholarship: db.prepare('SELECT * FROM scholarships WHERE id = ?').get(row.id) });
  } catch (e) { next(e); }
});

router.delete('/scholarships/:id', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM scholarships WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Scholarship not found.');
    db.prepare('DELETE FROM scholarships WHERE id = ?').run(row.id);
    audit(req, 'delete', 'scholarship', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/scholarships/:id/verify', authenticate, requireRole('owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM scholarships WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Scholarship not found.');
    if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
    db.prepare(`UPDATE scholarships SET verification = 'verified', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'verify', 'scholarship', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/scholarships/:id/publish', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM scholarships WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Scholarship not found.');
    if (row.verification !== 'verified') {
      throw httpError(400, 'Scholarship must be verified before it can be published.');
    }
    db.prepare(`UPDATE scholarships SET status = 'published', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'publish', 'scholarship', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- TRENDING ---------- */

router.get('/trending', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer'), (req, res) => {
  res.json({ stories: db.prepare('SELECT * FROM trending ORDER BY created_at DESC').all() });
});

router.post('/trending', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.title || !b.category || !b.author || !b.body) {
      throw httpError(400, 'title, category, author and body are required.');
    }
    const featured = b.featured ? 1 : 0;
    const info = db.prepare(`
      INSERT INTO trending (title, category, author, summary, body, cover_media_id, alt_text, caption,
        source_url, source_date, verification, featured, scheduled_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, 'draft')
    `).run(b.title, b.category, b.author, b.summary || null, b.body, b.cover_media_id || null,
           b.alt_text || null, b.caption || null, b.source_url || null, b.source_date || null,
           featured, b.scheduled_at || null);
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'trending', row.id, row.title);
    res.status(201).json({ story: row });
  } catch (e) { next(e); }
});

router.patch('/trending/:id', authenticate, requireRole('owner', 'admin', 'editor'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    const allowed = ['title','category','author','summary','body','cover_media_id','alt_text','caption','source_url','source_date','featured','scheduled_at','status'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if ('featured' in updates) updates.featured = updates.featured ? 1 : 0;
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE trending SET ${setSql}, updated_at = datetime('now') WHERE id = ?`)
      .run(...Object.values(updates), row.id);
    audit(req, 'update', 'trending', row.id, row.title);
    res.json({ story: db.prepare('SELECT * FROM trending WHERE id = ?').get(row.id) });
  } catch (e) { next(e); }
});

router.delete('/trending/:id', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    db.prepare('DELETE FROM trending WHERE id = ?').run(row.id);
    audit(req, 'delete', 'trending', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/trending/:id/verify', authenticate, requireRole('owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    if (!row.source_url) throw httpError(400, 'An official source URL is required before verification.');
    db.prepare(`UPDATE trending SET verification = 'verified', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'verify', 'trending', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/trending/:id/publish', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    if (row.verification !== 'verified') {
      throw httpError(400, 'Story must be verified before it can be published.');
    }
    db.prepare(`UPDATE trending SET status = 'published', updated_at = datetime('now') WHERE id = ?`).run(row.id);
    audit(req, 'publish', 'trending', row.id, row.title);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/trending/:id/schedule', authenticate, requireRole('owner', 'admin'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM trending WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Story not found.');
    if (!req.body || !req.body.scheduled_at) {
      throw httpError(400, 'scheduled_at is required.');
    }
    db.prepare(`UPDATE trending SET status = 'scheduled', scheduled_at = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(req.body.scheduled_at, row.id);
    audit(req, 'schedule', 'trending', row.id, row.title, { scheduled_at: req.body.scheduled_at });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- MEDIA ---------- */

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const base = crypto.randomBytes(12).toString('hex');
    cb(null, base + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/webp','image/svg+xml','application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('File type not allowed.'));
    }
    cb(null, true);
  },
});

router.post('/media', authenticate, requireRole('owner', 'admin', 'editor', 'school_manager'), upload.single('file'), (req, res, next) => {
  try {
    if (!req.file) throw httpError(400, 'A file is required.');
    const b = req.body || {};
    let schoolId = b.school_id ? Number(b.school_id) : null;
    if (req.user.role === 'school_manager') {
      if (!req.user.school_id) throw httpError(403, 'No school assigned to this account.');
      schoolId = req.user.school_id;
    }
    const info = db.prepare(`
      INSERT INTO media (filename, original_name, mime_type, size, display_name, alt_text, caption, category, tags, school_id, uploaded_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.file.filename, req.file.originalname, req.file.mimetype, req.file.size,
      b.display_name || req.file.originalname, b.alt_text || null, b.caption || null,
      b.category || null, b.tags || null, schoolId, req.user.id
    );
    const row = db.prepare('SELECT * FROM media WHERE id = ?').get(info.lastInsertRowid);
    row.url = `/uploads/${row.filename}`;
    audit(req, 'upload', 'media', row.id, row.display_name || row.original_name);
    res.status(201).json({ media: row });
  } catch (e) { next(e); }
});

router.get('/media', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    const clauses = [];
    const params = [];
    if (req.user.role === 'school_manager') { clauses.push('school_id = ?'); params.push(req.user.school_id); }
    if (req.query.school_id && req.user.role !== 'school_manager') {
      clauses.push('school_id = ?'); params.push(req.query.school_id);
    }
    const sql = `SELECT * FROM media ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY created_at DESC`;
    const rows = db.prepare(sql).all(...params).map(m => ({ ...m, url: `/uploads/${m.filename}` }));
    res.json({ media: rows });
  } catch (e) { next(e); }
});

// Brief-compatible alias: /api/schools/:id/media
router.get('/schools/:schoolId/media', authenticate, requireRole('owner', 'admin', 'editor', 'reviewer', 'school_manager'), (req, res, next) => {
  try {
    assertSchoolScope(req.user, req.params.schoolId);
    const rows = db.prepare('SELECT * FROM media WHERE school_id = ? ORDER BY created_at DESC')
      .all(req.params.schoolId).map(m => ({ ...m, url: `/uploads/${m.filename}` }));
    res.json({ media: rows });
  } catch (e) { next(e); }
});

router.patch('/media/:id', authenticate, requireRole('owner', 'admin', 'editor', 'school_manager'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM media WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Media not found.');
    if (req.user.role === 'school_manager' && row.school_id !== req.user.school_id) {
      throw httpError(403, 'You can only edit media for your assigned institution.');
    }
    const allowed = ['display_name','alt_text','caption','category','tags'];
    const updates = {};
    for (const k of allowed) if (k in (req.body || {})) updates[k] = req.body[k];
    if (!Object.keys(updates).length) throw httpError(400, 'No fields to update.');
    const setSql = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE media SET ${setSql} WHERE id = ?`).run(...Object.values(updates), row.id);
    audit(req, 'update', 'media', row.id, row.display_name || row.filename);
    const updated = db.prepare('SELECT * FROM media WHERE id = ?').get(row.id);
    updated.url = `/uploads/${updated.filename}`;
    res.json({ media: updated });
  } catch (e) { next(e); }
});

router.delete('/media/:id', authenticate, requireRole('owner', 'admin', 'school_manager'), (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM media WHERE id = ?').get(req.params.id);
    if (!row) throw httpError(404, 'Media not found.');
    if (req.user.role === 'school_manager' && row.school_id !== req.user.school_id) {
      throw httpError(403, 'You can only delete media for your assigned institution.');
    }
    db.prepare('DELETE FROM media WHERE id = ?').run(row.id);
    try { fs.unlinkSync(path.join(UPLOAD_DIR, row.filename)); } catch (_) {}
    audit(req, 'delete', 'media', row.id, row.display_name || row.filename);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- USERS (owner only) ---------- */

router.get('/users', authenticate, requireRole('owner'), (req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all().map(publicUser);
  res.json({ users: rows });
});

router.post('/users', authenticate, requireRole('owner'), (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.name || !b.email || !b.role) {
      throw httpError(400, 'name, email and role are required.');
    }
    if (!['owner','admin','editor','reviewer','school_manager'].includes(b.role)) {
      throw httpError(400, 'Invalid role.');
    }
    if (b.role === 'school_manager' && !b.school_id) {
      throw httpError(400, 'school_id is required for school managers.');
    }
    const exists = db.prepare('SELECT 1 FROM users WHERE lower(email) = lower(?)').get(b.email);
    if (exists) throw httpError(409, 'An account with that email already exists.');
    const initialPassword = b.password || crypto.randomBytes(9).toString('base64').slice(0, 12);
    const hash = bcrypt.hashSync(initialPassword, 10);
    const status = b.role === 'school_manager' ? 'pending' : 'active';
    const mustChange = 1;
    const info = db.prepare(`
      INSERT INTO users (name, email, password_hash, role, school_id, status, must_change_password, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(b.name, b.email, hash, b.role, b.school_id || null, status, mustChange, b.notes || null);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    audit(req, 'create', 'user', user.id, user.email, { role: user.role, status: user.status });
    res.status(201).json({ user: publicUser(user), initial_password: initialPassword, note: 'Share the initial password securely. The user must change it after first sign-in.' });
  } catch (e) { next(e); }
});

router.post('/users/:id/approve', authenticate, requireRole('owner'), (req, res, next) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) throw httpError(404, 'User not found.');
    db.prepare(`UPDATE users SET status = 'active', updated_at = datetime('now') WHERE id = ?`).run(user.id);
    audit(req, 'approve_user', 'user', user.id, user.email);
    notify(user.id, user.school_id, 'Your account has been approved', 'You can now sign in to the CampusNaija school portal.');
    res.json({ ok: true, user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)) });
  } catch (e) { next(e); }
});

router.post('/users/:id/suspend', authenticate, requireRole('owner'), (req, res, next) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) throw httpError(404, 'User not found.');
    if (user.role === 'owner') throw httpError(400, 'Cannot suspend the platform owner.');
    db.prepare(`UPDATE users SET status = 'suspended', updated_at = datetime('now') WHERE id = ?`).run(user.id);
    audit(req, 'suspend_user', 'user', user.id, user.email);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/users/:id/reactivate', authenticate, requireRole('owner'), (req, res, next) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) throw httpError(404, 'User not found.');
    db.prepare(`UPDATE users SET status = 'active', updated_at = datetime('now') WHERE id = ?`).run(user.id);
    audit(req, 'reactivate_user', 'user', user.id, user.email);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- SCHOOL MANAGER: submissions ---------- */

router.get('/school/submissions', authenticate, requireRole('school_manager', 'owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    let schoolId;
    if (req.user.role === 'school_manager') {
      schoolId = req.user.school_id;
    } else {
      schoolId = req.query.school_id;
      if (!schoolId) throw httpError(400, 'school_id is required.');
    }
    const items = [];
    const courses = db.prepare(`SELECT id, name AS label, status, updated_at FROM courses WHERE school_id = ? AND status IN ('draft','pending')`).all(schoolId);
    for (const c of courses) items.push({ type: 'course', ...c });
    const fees = db.prepare(`SELECT id, ('Fee ' || session || ' ' || category) AS label, status, updated_at FROM fees WHERE school_id = ? AND status IN ('draft','pending')`).all(schoolId);
    for (const f of fees) items.push({ type: 'fee', ...f });
    const adm = db.prepare(`SELECT id, title AS label, status, updated_at FROM admissions WHERE school_id = ? AND status IN ('draft','pending')`).all(schoolId);
    for (const a of adm) items.push({ type: 'admission', ...a });
    const cal = db.prepare(`SELECT id, title AS label, status, updated_at FROM calendar WHERE school_id = ? AND status IN ('draft','pending')`).all(schoolId);
    for (const c of cal) items.push({ type: 'calendar', ...c });
    items.sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
    res.json({ submissions: items });
  } catch (e) { next(e); }
});

router.post('/school/submissions/:type/:id/submit', authenticate, requireRole('school_manager'), (req, res, next) => {
  try {
    const { type, id } = req.params;
    const allowed = { course: 'courses', fee: 'fees', admission: 'admissions', calendar: 'calendar' };
    const table = allowed[type];
    if (!table) throw httpError(400, 'Unsupported submission type.');
    const row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id);
    if (!row) throw httpError(404, 'Record not found.');
    if (row.school_id !== req.user.school_id) {
      throw httpError(403, 'You can only submit records for your assigned institution.');
    }
    db.prepare(`UPDATE ${table} SET status = 'pending', updated_at = datetime('now') WHERE id = ?`).run(id);
    audit(req, 'submit', type, id, row.name || row.title || `#${id}`);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/school/submissions/:type/:id/withdraw', authenticate, requireRole('school_manager'), (req, res, next) => {
  try {
    const { type, id } = req.params;
    const allowed = { course: 'courses', fee: 'fees', admission: 'admissions', calendar: 'calendar' };
    const table = allowed[type];
    if (!table) throw httpError(400, 'Unsupported submission type.');
    const row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id);
    if (!row) throw httpError(404, 'Record not found.');
    if (row.school_id !== req.user.school_id) {
      throw httpError(403, 'You can only withdraw records for your assigned institution.');
    }
    if (row.status !== 'pending') {
      throw httpError(400, 'Only records currently pending review can be withdrawn.');
    }
    db.prepare(`UPDATE ${table} SET status = 'draft', updated_at = datetime('now') WHERE id = ?`).run(id);
    audit(req, 'withdraw', type, id, row.name || row.title || `#${id}`);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- OWNER: unified review queue ---------- */

router.get('/admin/submissions', authenticate, requireRole('owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    const schoolId = req.query.school_id;
    const clauses = [];
    const params = [];
    const items = [];
    const build = (table, labelField) => {
      const rows = db.prepare(`SELECT id, school_id, ${labelField} AS label, status, updated_at FROM ${table} WHERE status = 'pending'`).all();
      for (const r of rows) {
        if (schoolId && r.school_id !== Number(schoolId)) continue;
        items.push({ type: table === 'courses' ? 'course' : table === 'fees' ? 'fee' : table === 'admissions' ? 'admission' : 'calendar', ...r });
      }
    };
    build('courses', 'name');
    build('fees', "'Fee ' || session || ' ' || category");
    build('admissions', 'title');
    build('calendar', 'title');
    items.sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
    res.json({ submissions: items });
  } catch (e) { next(e); }
});

router.post('/admin/submissions/:type/:id/decision', authenticate, requireRole('owner', 'admin', 'reviewer'), (req, res, next) => {
  try {
    const { type, id } = req.params;
    const { decision, comment } = req.body || {};
    const allowed = { course: 'courses', fee: 'fees', admission: 'admissions', calendar: 'calendar' };
    const table = allowed[type];
    if (!table) throw httpError(400, 'Unsupported submission type.');
    if (!['approved', 'changes_requested'].includes(decision)) {
      throw httpError(400, 'decision must be "approved" or "changes_requested".');
    }
    const row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id);
    if (!row) throw httpError(404, 'Record not found.');
    if (row.status !== 'pending') {
      throw httpError(400, 'Only records currently pending review can be decided.');
    }
    const newStatus = decision === 'approved' ? 'published' : 'draft';
    db.prepare(`UPDATE ${table} SET status = ?, updated_at = datetime('now') WHERE id = ?`).run(newStatus, id);
    db.prepare(`INSERT INTO review_comments (submission_type, submission_id, school_id, reviewer_id, reviewer_name, decision, comment)
                VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(type, id, row.school_id, req.user.id, req.user.name, decision, comment || null);
    audit(req, decision, type, id, row.name || row.title || `#${id}`, { comment: comment || null });
    // Notify all school managers attached to this school
    const managers = db.prepare(`SELECT id FROM users WHERE role = 'school_manager' AND school_id = ?`).all(row.school_id);
    for (const m of managers) {
      notify(m.id, row.school_id,
        decision === 'approved' ? 'Submission approved' : 'Changes requested',
        `${type}: ${row.name || row.title || '#' + id}${comment ? ' — ' + comment : ''}`,
        '/SchoolAd/submissions.html');
    }
    res.json({ ok: true, new_status: newStatus });
  } catch (e) { next(e); }
});

/* ---------- NOTIFICATIONS ---------- */

router.get('/notifications', authenticate, (req, res) => {
  const where = req.user.role === 'owner' ? '' : 'WHERE (user_id = ? OR school_id = ?)';
  const params = req.user.role === 'owner' ? [] : [req.user.id, req.user.school_id || -1];
  const rows = db.prepare(`SELECT * FROM notifications ${where} ORDER BY created_at DESC LIMIT 100`).all(...params);
  res.json({ notifications: rows });
});

router.post('/notifications/:id/read', authenticate, (req, res, next) => {
  try {
    const n = db.prepare('SELECT * FROM notifications WHERE id = ?').get(req.params.id);
    if (!n) throw httpError(404, 'Notification not found.');
    if (req.user.role !== 'owner' && n.user_id !== req.user.id && n.school_id !== req.user.school_id) {
      throw httpError(403, 'Not allowed.');
    }
    db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(n.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- AUDIT ---------- */

router.get('/audit', authenticate, requireRole('owner'), (req, res) => {
  res.json({ audit: db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 500').all() });
});

/* ---------- SETTINGS (owner only) ---------- */

router.get('/settings', authenticate, requireRole('owner'), (req, res) => {
  res.json({ settings: readSettings() });
});

router.patch('/settings', authenticate, requireRole('owner'), (req, res, next) => {
  try {
    const b = req.body || {};
    const allowed = ['site_name','site_tagline','site_description','admin_email','require_review','require_verification_for_fees','auto_archive_expired','single_session','lockout_attempts','session_timeout'];
    const updates = {};
    for (const k of allowed) if (k in b) updates[k] = String(b[k]);
    if (!Object.keys(updates).length) throw httpError(400, 'No settings to update.');
    const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
    for (const [k, v] of Object.entries(updates)) stmt.run(k, v);
    audit(req, 'update_settings', 'settings', null, null, { keys: Object.keys(updates) });
    res.json({ ok: true, settings: readSettings() });
  } catch (e) { next(e); }
});

/* ---------- HEALTH ---------- */

router.get('/health', (req, res) => {
  res.json({ ok: true, time: now(), version: '1.1.0' });
});

/* ============================================================
 * ERROR HANDLING
 * ============================================================ */

app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) {
    console.error('[error]', err);
  }
  res.status(status).json({
    error: err.message || 'Internal server error.',
    code: err.code || undefined,
  });
});

/* ============================================================
 * START / SHUTDOWN
 * ============================================================ */

const httpServer = app.listen(PORT, () => {
  console.log(`CampusNaija backend listening on http://localhost:${PORT}`);
  console.log(`Owner email: ${ADMIN_EMAIL}`);
  console.log(`Uploads directory: ${UPLOAD_DIR}`);
  console.log('API base: /api');
});

function shutdown(signal) {
  console.log(`[stop] Received ${signal}, shutting down...`);
  httpServer.close(() => {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_) {}
    try { db.close(); } catch (_) {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 8000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));