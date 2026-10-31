# FileDrop

> Temporary private file sharing with expiring share links.

**FileDrop** lets an administrator upload files, generate private shareable links with a configurable expiry, and automatically deletes files and invalidates links when they expire.

---

## Screenshots

> *(Place screenshots of the dashboard, upload flow, and share page here.)*

---

## Features

- 🔒 **Private admin workspace** — password-protected, no public registration
- 📤 **Drag-and-drop uploads** — multi-file, up to 10 files / 100 MB each (configurable)
- 🔗 **Cryptographically random share tokens** — 64 hex characters; no internal paths exposed
- ⏱ **Configurable expiry** — 1 h, 6 h, 24 h, 3 days, or 7 days per upload batch
- 🗑 **Automatic cleanup** — expired files are deleted server-side every 60 seconds
- 📊 **Download counters** — track how many times each file was downloaded
- 📋 **Copy-link button** — one click to copy the full share URL
- 🌙 **Dark dashboard** — DM Sans / DM Mono, navy/lime-green palette
- 📱 **Responsive** — works on desktop, tablet, and mobile
- 🛡 **Helmet security headers**, rate limiting, HTTP-only session cookies

---

## Requirements

- **Node.js** 20 or later
- npm 8 or later

---

## Installation

### macOS / Linux

```bash
git clone https://github.com/yourname/filedrop.git
cd filedrop
cp .env.example .env        # edit with your secrets
npm install
npm start
```

### Windows (PowerShell)

```powershell
git clone https://github.com/yourname/filedrop.git
cd filedrop
copy .env.example .env      # edit with your secrets
npm install
npm start
```

Open **http://127.0.0.1:3000** in your browser.

---

## Environment Configuration

Copy `.env.example` to `.env` and set the values:

| Variable              | Default                          | Description                              |
|-----------------------|----------------------------------|------------------------------------------|
| `PORT`                | `3000`                           | HTTP port                                |
| `HOST`                | `127.0.0.1`                      | Bind address (`0.0.0.0` for LAN)        |
| `ADMIN_PASSWORD`      | *(required)*                     | Administrator login password             |
| `SESSION_SECRET`      | *(required)*                     | Secret for signing session cookies       |
| `MAX_FILE_SIZE_MB`    | `100`                            | Maximum individual file size in MB       |
| `MAX_FILES_PER_UPLOAD`| `10`                             | Maximum files in a single upload         |
| `DEFAULT_EXPIRY_HOURS`| `24`                             | Default expiry pre-selected in the UI    |

> **Never** commit your real `.env` file.

---

## Running Locally

```bash
npm start        # production
npm run dev      # auto-restart on change (Node 20+ --watch)
```

The server prints:

```
[FileDrop] Server running at http://127.0.0.1:3000
```

---

## API Documentation

### GET /api/config
Returns server configuration (public).

### GET /api/me
Returns `{ authenticated: true|false }`.

### POST /api/login
Body: `{ "password": "..." }` → `{ "ok": true }` or 401.

### POST /api/logout
Destroys the session.

### GET /api/files *(auth required)*
Returns the list of all uploaded files with metadata and share URLs.

### POST /api/upload *(auth required)*
Multipart form: `files[]` (multiple) + `expiryHours` (1|6|24|72|168).  
Returns `{ files: [{ id, name, size, expiresAt, shareUrl, token }] }`.

### DELETE /api/files/:id *(auth required)*
Deletes a file and invalidates its share link.

### GET /s/:token
Serves the public share page (HTML).

### GET /api/share/:token
Returns public-safe metadata for a shared file: `{ name, size, mime, expiresAt, downloads, token }`.

### GET /download/:token
Streams the file download with the original filename.

---

## Storage

```
data/
├── files.json      ← JSON metadata (auto-created)
└── uploads/        ← Physical files stored by UUID (auto-created)
```

Files are stored by **UUID** — the original filename is kept only as metadata.  
`files.json` is updated atomically (write-then-rename) to prevent corruption.

---

## Expiration Behavior

- **On startup** — expired files are cleaned up before the server accepts connections.
- **Every 60 seconds** — a background sweep removes expired records and files.
- **On every share-page load** — expiry is verified before returning metadata.
- **On every download** — expiry is verified before streaming the file.

Expiration is enforced **server-side**; hiding an expired link in the UI is cosmetic only.

---

## Deployment Notes

FileDrop is designed for **local/intranet use**. For internet deployment:

1. **Use HTTPS** — obtain a TLS certificate (Let's Encrypt / Caddy / Nginx).
2. **Set `SESSION_SECRET`** to a long (≥ 64 character) random string.
3. **Set `ADMIN_PASSWORD`** to a strong unique password.
4. **Set `secure: true` on cookies** — the server does this automatically when `NODE_ENV=production`.
5. **Run behind a reverse proxy** (Nginx/Caddy) and configure upload body size limits there.
6. **Replace the in-memory JSON DB** with a proper store (SQLite, Redis-backed sessions) for resilience.
7. **Consider upload malware scanning** before serving files to recipients.
8. **Back up `data/`** — it contains all uploads and metadata.
9. **Rate limits** — the built-in limiters are advisory; add IP-level limits at your proxy.

> FileDrop ships with reasonable local-dev defaults. A full security audit is recommended before public deployment.

---

## Security Notes

| Control | Implementation |
|---|---|
| Password comparison | `crypto.timingSafeEqual` |
| Session cookies | `httpOnly: true`, `sameSite: lax`, `secure` in production |
| Session fixation | Session regenerated after successful login |
| Login brute-force | Rate-limited to 10 attempts / 15 min |
| Upload rate limiting | 20 requests / min |
| File storage names | UUID — no user-supplied input in storage path |
| Share tokens | 32 bytes via `crypto.randomBytes` → 64 hex chars |
| Path traversal | Token/ID validated with strict regex before use |
| Security headers | Helmet (CSP, HSTS in production, X-Frame-Options, …) |
| Password storage | Password never stored — only in `.env` at rest |

---

## License

MIT — see [LICENSE](LICENSE).
