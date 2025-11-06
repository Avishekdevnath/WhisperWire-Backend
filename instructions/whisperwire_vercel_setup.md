# 🔐 WhisperWire (Vercel Backend-Only Edition)

**Goal:** A fully open-source, privacy-first backend for E2E secure messaging with optional Gemini-powered AI helpers — deployed **entirely on Vercel** (no Docker, no Redis).

---

## 🧭 Overview
- **Language:** Go 1.22+
- **Platform:** Vercel (Serverless Functions)
- **Database:** Vercel Postgres
- **Optional AI:** Google Gemini Free API (e.g., gemini-1.5-flash)
- **No Frontend:** Backend-only API (OpenAPI documented)

---

## 📂 Repository Structure
```
whisperwire/
├─ api/
│  ├─ health.go                  # GET /api/health
│  ├─ auth_signup.go             # POST /api/auth/signup
│  ├─ auth_login.go              # POST /api/auth/login
│  ├─ devices_register.go        # POST /api/devices/register
│  ├─ devices_list.go            # GET  /api/devices/{userID}
│  ├─ prekeys_post.go            # POST /api/devices/prekeys
│  ├─ prekeys_consume.go         # GET  /api/devices/prekeys/{deviceID}
│  ├─ messages_send.go           # POST /api/messages/send
│  ├─ messages_inbox.go          # GET  /api/messages/inbox
│  ├─ messages_status.go         # POST /api/messages/{id}/{delivered|read}
│  ├─ attachments_put.go         # POST /api/attachments
│  ├─ attachments_get.go         # GET  /api/attachments/{id}
│  ├─ assistant_suggest.go       # POST /api/assistant/suggest
│  ├─ assistant_moderate.go      # POST /api/assistant/moderate
│  ├─ assistant_summarize.go     # POST /api/assistant/summarize
│  └─ migrate.go                 # POST /api/_admin/migrate (one-time)
├─ internal/
│  ├─ auth/                      # JWT, bcrypt helpers
│  ├─ crypto/                    # NaCl encryption helpers
│  ├─ db/                        # Vercel Postgres pool & migrations
│  ├─ middleware/                # rate-limit, JWT guard
│  └─ resp/                      # standard JSON responses
├─ openapi/openapi.yaml
├─ go.mod / go.sum
├─ README.md
└─ LICENSE
```

---

## ⚙️ Environment Variables (Vercel → Project → Settings)
```
JWT_SECRET=change-me-super-long
ACCESS_TOKEN_MIN=15
REFRESH_TOKEN_DAYS=7
POSTGRES_URL=postgres://<auto-provided>
GEMINI_API_KEY=<optional>
MAX_MESSAGE_BYTES=1048576
MAX_ATTACHMENT_BYTES=2097152
MIGRATE_TOKEN=<choose-secret>
```

---

## 🗃️ Database Schema (Postgres)
```sql
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  ed25519_pub BYTEA NOT NULL,
  x25519_pub  BYTEA NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS prekeys (
  id SERIAL PRIMARY KEY,
  device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  x25519_pub BYTEA NOT NULL,
  is_used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id BIGSERIAL PRIMARY KEY,
  to_device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  from_device_pub BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  box BYTEA NOT NULL,
  has_attachment BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  read_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attachments (
  id BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  bytes BYTEA NOT NULL,
  size_bytes INT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
```

---

## 🔑 Migrate Endpoint (api/migrate.go)
Run once after deployment to initialize schema.

```go
if os.Getenv("MIGRATE_TOKEN") == "" || r.Header.Get("X-Migrate-Token") != os.Getenv("MIGRATE_TOKEN") {
    http.Error(w, "forbidden", 403); return
}
```
Then POST:
```bash
curl -X POST https://<your-app>.vercel.app/api/_admin/migrate \
  -H "X-Migrate-Token: <your-secret>"
```

---

## 🧠 Gemini Assistant (Optional)
Each request is **stateless** and never stored.

**Example: /api/assistant/suggest**
```go
payload := fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, "Write 3 short friendly replies to:\n\n"+text)
req, _ := http.NewRequest("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key="+os.Getenv("GEMINI_API_KEY"), strings.NewReader(payload))
req.Header.Set("Content-Type", "application/json")
```
Return array of `suggestions`.

---

## 🚀 Deployment Steps
1. **Push to GitHub** → create repo `whisperwire`.
2. **Import to Vercel** → choose *Go* runtime.
3. **Add Postgres integration** → auto-create DB.
4. **Add environment variables** listed above.
5. **Deploy** → Vercel builds `api/*.go` as endpoints.
6. **Run migration** using your token.
7. Test:
   - `GET /api/health`
   - `POST /api/auth/signup`
   - `POST /api/messages/send` (pre-boxed ciphertext)

---

## 📜 OpenAPI Basics (openapi/openapi.yaml)
Document `/api/auth/*`, `/api/devices/*`, `/api/messages/*`, `/api/assistant/*` for client SDKs.
Serve it with Redoc or leave static for contributors.

---

## 🧩 Contributing & OSS Notes
- License: MIT
- No plaintext logs or DB content
- PRs: Add new endpoints only with tests + docs
- Branch naming: `feat/*`, `fix/*`, `docs/*`
- All code formatted with `gofmt`

---

## ✅ Future Upgrades
- Switch attachments from BYTEA → **Vercel Blob**
- Add `/api/stream` for Server-Sent Events (realtime inbox)
- Extend AI for tone rewrite or moderation summaries
- Add automated CI tests (GitHub Actions)

---

## 🎯 Quick Recap
| Feature | Tool |
|----------|------|
| Serverless API | Vercel Functions |
| Database | Vercel Postgres |
| Auth | JWT + bcrypt |
| Encryption | NaCl box (X25519) |
| AI | Gemini 1.5 Flash (free-tier) |
| Deployment | 1-click on Vercel |

---

### 🏁 Result
A secure, AI-augmented messaging backend:
- One binary (no servers, no Docker)
- Fully encrypted message storage
- Stateless AI suggestions
- Ready for community collaboration 🚀

