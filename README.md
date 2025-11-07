# WhisperWire Backend

[![CI](https://github.com/YOUR_USERNAME/whisperwire/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/whisperwire/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev/)

A fully open-source, privacy-first backend for E2E secure messaging with optional Gemini-powered AI helpers — deployable entirely on Vercel.

## Features

- 🔐 **E2E Encryption** - NaCl/X25519 encrypted messages
- 🔑 **JWT Authentication** - Secure user authentication with bcrypt
- 📱 **Multi-Device Support** - Register and manage multiple devices per user
- 🔄 **Prekey Exchange** - Signal-like prekey system for secure key exchange
- 📎 **Attachments** - Encrypted file attachments support
- 🤖 **AI Assistant** - Optional Gemini-powered suggestions, moderation, and summarization
- ☁️ **Serverless** - Deploy to Vercel with zero configuration
- 🗄️ **Postgres** - Vercel Postgres for data persistence

## Tech Stack

- **Language:** Go 1.22+
- **Platform:** Vercel (Serverless Functions)
- **Database:** Vercel Postgres
- **AI:** Google Gemini API (optional)
- **Auth:** JWT + bcrypt
- **Encryption:** NaCl box (X25519)

## Quick Start

### Local Development

1. **Clone and setup:**
```bash
git clone https://github.com/YOUR_USERNAME/whisperwire.git
cd whisperwire/backend
cp env.example .env
```

2. **Generate secrets:**
```bash
# Windows
pwsh -File scripts/gen-secret.ps1 64

# macOS/Linux
bash scripts/gen-secret.sh 64
```

3. **Configure environment:**
Edit `.env` with your database URL and generated secrets.

4. **Run the server:**
```bash
go run ./cmd/server
```

5. **Run migration:**
```bash
curl -X POST http://localhost:8080/api/_admin/migrate \
  -H "X-Migrate-Token: YOUR_MIGRATE_TOKEN"
```

### Setup Git Hooks (Optional)

```bash
bash scripts/setup-hooks.sh
```

This installs pre-commit hooks for automatic formatting and linting.

## API Endpoints

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/health` | GET | Health check | No |
| `/api/auth/signup` | POST | Register new user | No |
| `/api/auth/login` | POST | Login user | No |
| `/api/devices/register` | POST | Register device | Yes |
| `/api/devices/list` | GET | List user devices | Yes |
| `/api/devices/prekeys` | POST | Upload prekeys | Yes |
| `/api/devices/prekeys/{id}` | GET | Consume prekey | No |
| `/api/messages/send` | POST | Send message | Yes |
| `/api/messages/inbox` | GET | Get messages | Yes |
| `/api/messages/{id}/{status}` | POST | Update message status | Yes |
| `/api/attachments` | POST | Upload attachment | Yes |
| `/api/attachments/{id}` | GET | Download attachment | Yes |
| `/api/assistant/suggest` | POST | Get reply suggestions | No |
| `/api/assistant/moderate` | POST | Moderate content | No |
| `/api/assistant/summarize` | POST | Summarize text | No |

See `openapi/openapi.yaml` for detailed API documentation.

## Deployment

### Option 1: Deploy from Terminal (Recommended)

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Link project (first time)
vercel link

# Add environment variables
vercel env add POSTGRES_URL
vercel env add JWT_SECRET
vercel env add MIGRATE_TOKEN

# Deploy to production
vercel --prod

# Or use the deploy script
bash scripts/deploy.sh  # macOS/Linux
pwsh scripts/deploy.ps1 # Windows
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

### Option 2: Deploy via GitHub

1. **Push to GitHub**
2. **Import to Vercel** → select Go runtime
3. **Add Postgres** → Vercel Postgres integration
4. **Set environment variables** (see `env.example`)
5. **Deploy** → Vercel auto-deploys on push to main
6. **Run migration** using the `/api/_admin/migrate` endpoint

### Environment Variables

Required:
- `POSTGRES_URL` - Database connection string
- `JWT_SECRET` - Secret for JWT signing
- `MIGRATE_TOKEN` - Secret for migration endpoint

Optional:
- `GEMINI_API_KEY` - For AI features
- `ACCESS_TOKEN_MIN` - Access token expiry (default: 15)
- `REFRESH_TOKEN_DAYS` - Refresh token expiry (default: 7)
- `MAX_MESSAGE_BYTES` - Max message size (default: 1MB)
- `MAX_ATTACHMENT_BYTES` - Max attachment size (default: 2MB)
- `PORT` - Local server port (default: 8080)

## CI/CD

This project uses GitHub Actions for:
- ✅ Build verification
- ✅ Code formatting checks (`gofmt`)
- ✅ Static analysis (`go vet`, `golangci-lint`)
- ✅ Test execution (when tests are added)
- ✅ Automatic deployment to Vercel on main branch

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

### Code Standards

- All code must be formatted with `gofmt`
- Pass `go vet` and `golangci-lint` checks
- Add tests for new features
- Update OpenAPI spec for API changes

## License

MIT — see `LICENSE`.

## Documentation

- [Setup Instructions](instructions/whisperwire_vercel_setup.md)
- [OpenAPI Spec](openapi/openapi.yaml)

