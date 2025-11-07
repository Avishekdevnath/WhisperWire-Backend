package handler

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"whisperwire/internal/config"
	"whisperwire/internal/db"
	"whisperwire/internal/resp"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	migrateToken := os.Getenv("MIGRATE_TOKEN")
	if migrateToken == "" || r.Header.Get("X-Migrate-Token") != migrateToken {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS devices (
			id SERIAL PRIMARY KEY,
			user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			ed25519_pub BYTEA NOT NULL,
			x25519_pub BYTEA NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS prekeys (
			id SERIAL PRIMARY KEY,
			device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			x25519_pub BYTEA NOT NULL,
			is_used BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id BIGSERIAL PRIMARY KEY,
			to_device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			from_device_pub BYTEA NOT NULL,
			nonce BYTEA NOT NULL,
			box BYTEA NOT NULL,
			has_attachment BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ DEFAULT now(),
			delivered_at TIMESTAMPTZ,
			read_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS attachments (
			id BIGSERIAL PRIMARY KEY,
			message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
			bytes BYTEA NOT NULL,
			size_bytes INT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
	}

	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, strings.TrimSpace(stmt)); err != nil {
			resp.WriteError(w, http.StatusInternalServerError, "migration_failed", err.Error())
			return
		}
	}

	resp.WriteJSON(w, http.StatusOK, map[string]string{"status": "migrated"})
}
