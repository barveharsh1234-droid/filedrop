'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// ─── Startup validation ───────────────────────────────────────────────────────
const REQUIRED_ENV = ['ADMIN_PASSWORD', 'SESSION_SECRET'];
const INSECURE_DEFAULTS = ['change-this-password', 'replace-with-a-long-random-secret'];

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[FileDrop] FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

if (INSECURE_DEFAULTS.includes(process.env.ADMIN_PASSWORD) ||
    INSECURE_DEFAULTS.includes(process.env.SESSION_SECRET)) {
  console.warn('[FileDrop] WARNING: You are using default/insecure values for ADMIN_PASSWORD or SESSION_SECRET.');
  console.warn('[FileDrop] This is acceptable for local development, but NEVER deploy to the internet like this.');
}

// ─── Configuration ────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3001;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_FILE_SIZE_MB = parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 100;
const MAX_FILES_PER_UPLOAD = parseInt(process.env.MAX_FILES_PER_UPLOAD, 10) || 10;
const DEFAULT_EXPIRY_HOURS = parseInt(process.env.DEFAULT_EXPIRY_HOURS, 10) || 24;
const VALID_EXPIRY_HOURS = [1, 6, 24, 72, 168];

// ─── Paths ────────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'files.json');

// ─── Ensure directories exist ─────────────────────────────────────────────────
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify([]), 'utf8');
}

// ─── Database helpers ─────────────────────────────────────────────────────────
function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function writeDB(records) {
  const tmp = DB_PATH + '.tmp.' + Date.now();
  fs.writeFileSync(tmp, JSON.stringify(records, null, 2), 'utf8');
  fs.renameSync(tmp, DB_PATH);
}

function findByToken(token) {
  return readDB().find(r => r.token === token) || null;
}

function findById(id) {
  return readDB().find(r => r.id === id) || null;
}

// ─── Expiry cleanup ───────────────────────────────────────────────────────────
function cleanupExpired() {
  const records = readDB();
  const now = Date.now();
  const surviving = [];
  let cleaned = 0;

  for (const rec of records) {
    if (new Date(rec.expiresAt).getTime() < now) {
      const filePath = path.join(UPLOADS_DIR, rec.id);
      try {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch (err) {
        console.warn(`[FileDrop] Could not delete expired file ${rec.id}:`, err.message);
      }
      cleaned++;
    } else {
      surviving.push(rec);
    }
  }

  if (cleaned > 0) {
    writeDB(surviving);
    console.log(`[FileDrop] Cleanup: removed ${cleaned} expired file(s).`);
  }
}

// Run cleanup on startup and every 60 seconds
cleanupExpired();
setInterval(cleanupExpired, 60 * 1000);

// ─── Express app ──────────────────────────────────────────────────────────────
const app = express();

// Security headers (relax CSP slightly so DM Sans loads from Google Fonts)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate limiters ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Upload rate limit exceeded. Slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Multer storage ───────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, _file, cb) => cb(null, uuidv4()), // UUID only — no user-supplied name
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE_MB * 1024 * 1024,
    files: MAX_FILES_PER_UPLOAD,
  },
});

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Timing-safe password compare
function safeCompare(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Still run timingSafeEqual to avoid length oracle
    crypto.timingSafeEqual(
      Buffer.alloc(bb.length),
      Buffer.alloc(bb.length)
    );
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// ─── API: config ──────────────────────────────────────────────────────────────
app.get('/api/config', (_req, res) => {
  res.json({
    maxFileSizeMB: MAX_FILE_SIZE_MB,
    maxFiles: MAX_FILES_PER_UPLOAD,
    defaultExpiryHours: DEFAULT_EXPIRY_HOURS,
    validExpiryHours: VALID_EXPIRY_HOURS,
  });
});

// ─── API: auth ────────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

app.post('/api/login', loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });

  if (!safeCompare(password, process.env.ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  // Regenerate session to prevent fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.authenticated = true;
    res.json({ ok: true });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

// ─── API: file list ───────────────────────────────────────────────────────────
app.get('/api/files', requireAuth, (_req, res) => {
  cleanupExpired(); // opportunistic cleanup
  const records = readDB();
  const now = Date.now();

  const safe = records.map(r => ({
    id: r.id,
    token: r.token,
    name: r.name,
    size: r.size,
    mime: r.mime,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    downloads: r.downloads,
    shareUrl: `/s/${r.token}`,
    expired: new Date(r.expiresAt).getTime() < now,
  }));

  res.json(safe);
});

// ─── API: upload ──────────────────────────────────────────────────────────────
app.post('/api/upload', requireAuth, uploadLimiter, (req, res) => {
  upload.array('files', MAX_FILES_PER_UPLOAD)(req, res, (err) => {
    if (err) {
      // Clean up any partial uploads
      if (req.files) {
        for (const f of req.files) {
          try { fs.unlinkSync(f.path); } catch (_) {}
        }
      }

      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: `File too large. Maximum is ${MAX_FILE_SIZE_MB} MB per file.` });
      }
      if (err.code === 'LIMIT_FILE_COUNT') {
        return res.status(413).json({ error: `Too many files. Maximum is ${MAX_FILES_PER_UPLOAD} files per upload.` });
      }
      return res.status(400).json({ error: err.message || 'Upload failed.' });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files received.' });
    }

    const rawExpiry = parseInt(req.body.expiryHours, 10);
    const expiryHours = VALID_EXPIRY_HOURS.includes(rawExpiry) ? rawExpiry : DEFAULT_EXPIRY_HOURS;

    const records = readDB();
    const created = [];

    for (const file of req.files) {
      // file.filename is the UUID we assigned in multer storage
      const id = file.filename;
      const token = crypto.randomBytes(32).toString('hex');
      const now = new Date();
      const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000);

      const record = {
        id,
        token,
        name: file.originalname,
        size: file.size,
        mime: file.mimetype || 'application/octet-stream',
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        downloads: 0,
      };

      records.push(record);
      created.push({
        id: record.id,
        name: record.name,
        size: record.size,
        expiresAt: record.expiresAt,
        shareUrl: `/s/${record.token}`,
        token: record.token,
      });
    }

    writeDB(records);
    res.status(201).json({ files: created });
  });
});

// ─── API: delete file ─────────────────────────────────────────────────────────
app.delete('/api/files/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  // Prevent directory traversal: id must be a UUID (hex chars and dashes only)
  if (!/^[0-9a-f-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid file ID.' });
  }

  const records = readDB();
  const idx = records.findIndex(r => r.id === id);
  if (idx === -1) return res.status(404).json({ error: 'File not found.' });

  const record = records[idx];
  const filePath = path.join(UPLOADS_DIR, record.id);

  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (err) {
    console.warn(`[FileDrop] Could not delete physical file ${id}:`, err.message);
  }

  records.splice(idx, 1);
  writeDB(records);
  res.json({ ok: true });
});

// ─── Public: share page ───────────────────────────────────────────────────────
app.get('/s/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

// ─── API: public share metadata ───────────────────────────────────────────────
app.get('/api/share/:token', (req, res) => {
  const { token } = req.params;
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return res.status(400).json({ error: 'Invalid token.' });
  }

  cleanupExpired(); // check expiry before responding
  const record = findByToken(token);

  if (!record) {
    return res.status(404).json({ error: 'not_found', expired: true });
  }

  if (new Date(record.expiresAt).getTime() < Date.now()) {
    return res.status(410).json({ error: 'expired', expired: true });
  }

  res.json({
    name: record.name,
    size: record.size,
    mime: record.mime,
    expiresAt: record.expiresAt,
    downloads: record.downloads,
    token: record.token,
  });
});

// ─── Public: download ─────────────────────────────────────────────────────────
app.get('/download/:token', (req, res) => {
  const { token } = req.params;
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return res.status(400).json({ error: 'Invalid token.' });
  }

  cleanupExpired();
  const records = readDB();
  const idx = records.findIndex(r => r.token === token);

  if (idx === -1) {
    return res.status(404).sendFile(path.join(__dirname, 'public', 'expired.html'));
  }

  const record = records[idx];

  if (new Date(record.expiresAt).getTime() < Date.now()) {
    return res.status(410).sendFile(path.join(__dirname, 'public', 'expired.html'));
  }

  const filePath = path.join(UPLOADS_DIR, record.id);

  if (!fs.existsSync(filePath)) {
    // File missing on disk — remove from DB
    records.splice(idx, 1);
    writeDB(records);
    return res.status(404).sendFile(path.join(__dirname, 'public', 'expired.html'));
  }

  // Increment download count
  records[idx].downloads += 1;
  writeDB(records);

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.download(filePath, record.name, (err) => {
    if (err && !res.headersSent) {
      console.error('[FileDrop] Download error:', err.message);
      res.status(500).json({ error: 'Download failed.' });
    }
  });
});

// ─── Catch-all: expired / not found ──────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'expired.html'));
});

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`[FileDrop] Server running at http://${HOST}:${PORT}`);
  console.log(`[FileDrop] Max file size: ${MAX_FILE_SIZE_MB} MB | Max files: ${MAX_FILES_PER_UPLOAD}`);
});
