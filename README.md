# WhisperWire 

A fully open-source, privacy-first backend for E2E secure messaging with optional Gemini-powered AI helpers — deployable entirely on Vercel.

- Language: Go 1.22+
- Platform: Vercel (Serverless Functions)
- Database: Vercel Postgres
- Optional AI: Google Gemini API

See `instructions/whisperwire_vercel_setup.md` for detailed structure, environment variables, schema, and deployment steps.

## Local Development

This repository is designed for Vercel's Go Functions. Each file under `api/` exposes a `Handler` and maps to an HTTP endpoint.

Required environment variables (see Vercel project settings): `POSTGRES_URL`, `JWT_SECRET`, `ACCESS_TOKEN_MIN`, `REFRESH_TOKEN_DAYS`, `GEMINI_API_KEY` (optional), `MAX_MESSAGE_BYTES`, `MAX_ATTACHMENT_BYTES`, `MIGRATE_TOKEN`.

## License

MIT — see `LICENSE`.

