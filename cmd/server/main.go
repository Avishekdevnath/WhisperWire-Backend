package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"whisperwire/internal/auth"
	"whisperwire/internal/config"
	"whisperwire/internal/db"
	"whisperwire/internal/middleware"
	"whisperwire/internal/resp"
)

func main() {
	config.Init()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		fmt.Println("⚠️  PORT not set in environment, using default: 8080")
	} else {
		fmt.Printf("📌 Using PORT from environment: %s\n", port)
	}

	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/api/health", healthHandler)

	// Migrate endpoint
	mux.HandleFunc("/api/_admin/migrate", migrateHandler)

	// Auth endpoints
	mux.HandleFunc("/api/auth/signup", signupHandler)
	mux.HandleFunc("/api/auth/login", loginHandler)

	// Device endpoints (protected)
	mux.HandleFunc("/api/devices/register", middleware.RequireAuth(deviceRegisterHandler))
	mux.HandleFunc("/api/devices/list", middleware.RequireAuth(deviceListHandler))
	mux.HandleFunc("/api/devices/prekeys", middleware.RequireAuth(prekeysPostHandler))
	mux.HandleFunc("/api/devices/prekeys/", prekeysGetHandler) // Dynamic route

	// Message endpoints (protected)
	mux.HandleFunc("/api/messages/send", middleware.RequireAuth(messageSendHandler))
	mux.HandleFunc("/api/messages/inbox", middleware.RequireAuth(messageInboxHandler))
	mux.HandleFunc("/api/messages/", messageStatusHandler) // Dynamic route

	// Attachment endpoints (protected)
	mux.HandleFunc("/api/attachments", middleware.RequireAuth(attachmentPostHandler))
	mux.HandleFunc("/api/attachments/", attachmentGetHandler) // Dynamic route

	// Assistant endpoints (public, but optional auth could be added)
	mux.HandleFunc("/api/assistant/suggest", assistantSuggestHandler)
	mux.HandleFunc("/api/assistant/moderate", assistantModerateHandler)
	mux.HandleFunc("/api/assistant/summarize", assistantSummarizeHandler)

	fmt.Printf("🚀 WhisperWire server running on http://localhost:%s\n", port)
	fmt.Println("📋 Available endpoints:")
	fmt.Println("  GET  /api/health")
	fmt.Println("  POST /api/_admin/migrate")
	fmt.Println("  POST /api/auth/signup")
	fmt.Println("  POST /api/auth/login")
	fmt.Println("  POST /api/devices/register")
	fmt.Println("  GET  /api/devices/list")
	fmt.Println("  POST /api/devices/prekeys")
	fmt.Println("  GET  /api/devices/prekeys/{deviceID}")
	fmt.Println("  POST /api/messages/send")
	fmt.Println("  GET  /api/messages/inbox?device_id=X")
	fmt.Println("  POST /api/messages/{id}/{delivered|read}")
	fmt.Println("  POST /api/attachments")
	fmt.Println("  GET  /api/attachments/{id}")
	fmt.Println("  POST /api/assistant/suggest")
	fmt.Println("  POST /api/assistant/moderate")
	fmt.Println("  POST /api/assistant/summarize")
	fmt.Println("\nPress Ctrl+C to stop")

	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{"status": "ok"}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if pool, err := db.Get(ctx); err == nil {
		if err := pool.Ping(ctx); err == nil {
			status["db"] = "up"
		} else {
			status["db"] = "down"
			status["db_error"] = err.Error()
		}
	} else {
		status["db"] = "down"
		status["db_error"] = err.Error()
	}
	resp.WriteJSON(w, http.StatusOK, status)
}

func migrateHandler(w http.ResponseWriter, r *http.Request) {
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

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "email and password are required")
		return
	}
	if len(req.Password) < 8 {
		resp.WriteError(w, http.StatusBadRequest, "weak_password", "password must be at least 8 characters")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "hash_error", err.Error())
		return
	}

	var userID int64
	row := pool.QueryRow(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`, req.Email, passwordHash)
	if err := row.Scan(&userID); err != nil {
		resp.WriteError(w, http.StatusConflict, "email_exists", "email already registered")
		return
	}

	access, refresh, err := auth.GenerateTokens(userID)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "token_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"user": map[string]any{
			"id":    userID,
			"email": req.Email,
		},
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "email and password are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var userID int64
	var passwordHash string
	row := pool.QueryRow(ctx, `SELECT id, password_hash FROM users WHERE email = $1`, req.Email)
	if err := row.Scan(&userID, &passwordHash); err != nil {
		resp.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	if err := auth.CheckPassword(req.Password, passwordHash); err != nil {
		resp.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	access, refresh, err := auth.GenerateTokens(userID)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "token_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"user": map[string]any{
			"id":    userID,
			"email": req.Email,
		},
	})
}

