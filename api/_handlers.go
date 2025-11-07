package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/config"
	"whisperwire/pkg/crypto"
	"whisperwire/pkg/db"
	"whisperwire/pkg/resp"
)

// Health handler
func healthHandler(w http.ResponseWriter, r *http.Request) {
	config.Init()
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

// Migrate handler
func migrateHandler(w http.ResponseWriter, r *http.Request) {
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

// Auth handlers
func signupHandler(w http.ResponseWriter, r *http.Request) {
	config.Init()
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
	config.Init()
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

// Device handlers
func deviceRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		Name       string `json:"name"`
		Ed25519Pub string `json:"ed25519_pub"`
		X25519Pub  string `json:"x25519_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Name == "" || req.Ed25519Pub == "" || req.X25519Pub == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "name, ed25519_pub, and x25519_pub are required")
		return
	}

	ed25519Pub, err := crypto.DecodeBase64Key(req.Ed25519Pub)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid ed25519_pub encoding")
		return
	}
	if err := crypto.ValidateEd25519Pub(ed25519Pub); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	x25519Pub, err := crypto.DecodeBase64Key(req.X25519Pub)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid x25519_pub encoding")
		return
	}
	if err := crypto.ValidateX25519Pub(x25519Pub); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var deviceID int64
	row := pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, name, ed25519_pub, x25519_pub) VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, req.Name, ed25519Pub, x25519Pub,
	)
	if err := row.Scan(&deviceID); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"device_id": deviceID,
		"name":      req.Name,
	})
}

func deviceListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	rows, err := pool.Query(ctx, `SELECT id, name, ed25519_pub, x25519_pub, created_at FROM devices WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()

	devices := []map[string]any{}
	for rows.Next() {
		var id int64
		var name string
		var ed25519Pub, x25519Pub []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &ed25519Pub, &x25519Pub, &createdAt); err != nil {
			continue
		}
		devices = append(devices, map[string]any{
			"id":          id,
			"name":        name,
			"ed25519_pub": base64.StdEncoding.EncodeToString(ed25519Pub),
			"x25519_pub":  base64.StdEncoding.EncodeToString(x25519Pub),
			"created_at":  createdAt.Format(time.RFC3339),
		})
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func prekeysPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		DeviceID int64    `json:"device_id"`
		Prekeys  []string `json:"prekeys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.DeviceID == 0 || len(req.Prekeys) == 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "device_id and prekeys are required")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var deviceUserID int64
	row := pool.QueryRow(ctx, `SELECT user_id FROM devices WHERE id = $1`, req.DeviceID)
	if err := row.Scan(&deviceUserID); err != nil {
		resp.WriteError(w, http.StatusNotFound, "device_not_found", "device not found")
		return
	}
	if deviceUserID != userID {
		resp.WriteError(w, http.StatusForbidden, "forbidden", "device does not belong to user")
		return
	}

	for _, prekeyB64 := range req.Prekeys {
		prekey, err := crypto.DecodeBase64Key(prekeyB64)
		if err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid prekey encoding")
			return
		}
		if err := crypto.ValidateX25519Pub(prekey); err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}

		if _, err := pool.Exec(ctx, `INSERT INTO prekeys (device_id, x25519_pub) VALUES ($1, $2)`, req.DeviceID, prekey); err != nil {
			resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
			return
		}
	}

	resp.WriteJSON(w, http.StatusOK, map[string]string{"status": "prekeys stored"})
}

func prekeysGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/devices/prekeys/")
	deviceID, err := strconv.ParseInt(path, 10, 64)
	if err != nil || deviceID <= 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid device_id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var prekeyID int64
	var x25519Pub []byte
	row := pool.QueryRow(ctx,
		`UPDATE prekeys SET is_used = TRUE WHERE id = (
			SELECT id FROM prekeys WHERE device_id = $1 AND is_used = FALSE LIMIT 1
		) RETURNING id, x25519_pub`,
		deviceID,
	)
	if err := row.Scan(&prekeyID, &x25519Pub); err != nil {
		resp.WriteError(w, http.StatusNotFound, "no_prekeys", "no available prekeys for this device")
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"prekey_id":  prekeyID,
		"x25519_pub": base64.StdEncoding.EncodeToString(x25519Pub),
	})
}

// Message handlers
func messageSendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		ToDeviceID   int64  `json:"to_device_id"`
		FromDevicePub string `json:"from_device_pub"`
		Nonce        string `json:"nonce"`
		Box          string `json:"box"`
		HasAttachment bool  `json:"has_attachment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.ToDeviceID == 0 || req.FromDevicePub == "" || req.Nonce == "" || req.Box == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "to_device_id, from_device_pub, nonce, and box are required")
		return
	}

	maxBytes := 1048576
	if v := os.Getenv("MAX_MESSAGE_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxBytes = n
		}
	}

	nonce, err := crypto.DecodeBase64Key(req.Nonce)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid nonce encoding")
		return
	}
	box, err := crypto.DecodeBase64Key(req.Box)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid box encoding")
		return
	}
	fromDevicePub, err := crypto.DecodeBase64Key(req.FromDevicePub)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid from_device_pub encoding")
		return
	}

	if len(box) > maxBytes {
		resp.WriteError(w, http.StatusBadRequest, "message_too_large", "message exceeds maximum size")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var toDeviceExists bool
	row := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)`, req.ToDeviceID)
	if err := row.Scan(&toDeviceExists); err != nil || !toDeviceExists {
		resp.WriteError(w, http.StatusNotFound, "device_not_found", "target device not found")
		return
	}

	var messageID int64
	row = pool.QueryRow(ctx,
		`INSERT INTO messages (to_device_id, from_device_pub, nonce, box, has_attachment) 
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.ToDeviceID, fromDevicePub, nonce, box, req.HasAttachment,
	)
	if err := row.Scan(&messageID); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"message_id": messageID,
		"status":     "sent",
	})
}

func messageInboxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	deviceIDParam := r.URL.Query().Get("device_id")
	if deviceIDParam == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "device_id query parameter is required")
		return
	}

	deviceID, err := strconv.ParseInt(deviceIDParam, 10, 64)
	if err != nil || deviceID <= 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid device_id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var deviceUserID int64
	row := pool.QueryRow(ctx, `SELECT user_id FROM devices WHERE id = $1`, deviceID)
	if err := row.Scan(&deviceUserID); err != nil {
		resp.WriteError(w, http.StatusNotFound, "device_not_found", "device not found")
		return
	}
	if deviceUserID != userID {
		resp.WriteError(w, http.StatusForbidden, "forbidden", "device does not belong to user")
		return
	}

	rows, err := pool.Query(ctx,
		`SELECT id, from_device_pub, nonce, box, has_attachment, created_at 
		 FROM messages 
		 WHERE to_device_id = $1 AND delivered_at IS NULL 
		 ORDER BY created_at ASC 
		 LIMIT 100`,
		deviceID,
	)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()

	messages := []map[string]any{}
	for rows.Next() {
		var id int64
		var fromDevicePub, nonce, box []byte
		var hasAttachment bool
		var createdAt time.Time
		if err := rows.Scan(&id, &fromDevicePub, &nonce, &box, &hasAttachment, &createdAt); err != nil {
			continue
		}
		messages = append(messages, map[string]any{
			"id":             id,
			"from_device_pub": base64.StdEncoding.EncodeToString(fromDevicePub),
			"nonce":          base64.StdEncoding.EncodeToString(nonce),
			"box":            base64.StdEncoding.EncodeToString(box),
			"has_attachment": hasAttachment,
			"created_at":     createdAt.Format(time.RFC3339),
		})
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

func messageStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid path format")
		return
	}

	messageID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || messageID <= 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid message_id")
		return
	}

	status := parts[1]
	if status != "delivered" && status != "read" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "status must be 'delivered' or 'read'")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var deviceUserID int64
	row := pool.QueryRow(ctx,
		`SELECT d.user_id FROM messages m 
		 JOIN devices d ON m.to_device_id = d.id 
		 WHERE m.id = $1`,
		messageID,
	)
	if err := row.Scan(&deviceUserID); err != nil {
		resp.WriteError(w, http.StatusNotFound, "message_not_found", "message not found")
		return
	}
	if deviceUserID != userID {
		resp.WriteError(w, http.StatusForbidden, "forbidden", "message does not belong to user")
		return
	}

	var column string
	if status == "delivered" {
		column = "delivered_at"
	} else {
		column = "read_at"
	}

	_, err = pool.Exec(ctx,
		`UPDATE messages SET `+column+` = $1 WHERE id = $2`,
		time.Now(), messageID,
	)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

// Attachment handlers
func attachmentPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		MessageID int64  `json:"message_id"`
		Bytes     string `json:"bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.MessageID == 0 || req.Bytes == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "message_id and bytes are required")
		return
	}

	attachmentBytes, err := base64.StdEncoding.DecodeString(req.Bytes)
	if err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid bytes encoding")
		return
	}

	maxBytes := 2097152
	if v := os.Getenv("MAX_ATTACHMENT_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxBytes = n
		}
	}

	if len(attachmentBytes) > maxBytes {
		resp.WriteError(w, http.StatusBadRequest, "attachment_too_large", "attachment exceeds maximum size")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var messageUserID int64
	row := pool.QueryRow(ctx,
		`SELECT d.user_id FROM messages m 
		 JOIN devices d ON m.to_device_id = d.id 
		 WHERE m.id = $1`,
		req.MessageID,
	)
	if err := row.Scan(&messageUserID); err != nil {
		resp.WriteError(w, http.StatusNotFound, "message_not_found", "message not found")
		return
	}
	if messageUserID != userID {
		resp.WriteError(w, http.StatusForbidden, "forbidden", "message does not belong to user")
		return
	}

	var attachmentID int64
	row = pool.QueryRow(ctx,
		`INSERT INTO attachments (message_id, bytes, size_bytes) VALUES ($1, $2, $3) RETURNING id`,
		req.MessageID, attachmentBytes, len(attachmentBytes),
	)
	if err := row.Scan(&attachmentID); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"attachment_id": attachmentID,
		"size_bytes":    len(attachmentBytes),
	})
}

func attachmentGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/attachments/")
	attachmentID, err := strconv.ParseInt(path, 10, 64)
	if err != nil || attachmentID <= 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid attachment_id")
		return
	}

	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "user ID not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := db.Get(ctx)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
		return
	}

	var bytes []byte
	var sizeBytes int
	row := pool.QueryRow(ctx,
		`SELECT a.bytes, a.size_bytes FROM attachments a
		 JOIN messages m ON a.message_id = m.id
		 JOIN devices d ON m.to_device_id = d.id
		 WHERE a.id = $1 AND d.user_id = $2`,
		attachmentID, userID,
	)
	if err := row.Scan(&bytes, &sizeBytes); err != nil {
		resp.WriteError(w, http.StatusNotFound, "attachment_not_found", "attachment not found")
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"attachment_id": attachmentID,
		"bytes":         base64.StdEncoding.EncodeToString(bytes),
		"size_bytes":    sizeBytes,
	})
}

// Assistant handlers
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func assistantSuggestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Write 3 short friendly replies to:\n\n%s", req.Text)
	payload := fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, prompt)

	geminiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)
	geminiReq, err := http.NewRequest("POST", geminiURL, bytes.NewReader([]byte(payload)))
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "request_error", err.Error())
		return
	}
	geminiReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	geminiResp, err := client.Do(geminiReq)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", err.Error())
		return
	}
	defer geminiResp.Body.Close()

	if geminiResp.StatusCode != http.StatusOK {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "Gemini API returned error")
		return
	}

	var geminiRes geminiResponse
	if err := json.NewDecoder(geminiResp.Body).Decode(&geminiRes); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "parse_error", err.Error())
		return
	}

	if len(geminiRes.Candidates) == 0 || len(geminiRes.Candidates[0].Content.Parts) == 0 {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no suggestions returned")
		return
	}

	text := geminiRes.Candidates[0].Content.Parts[0].Text
	suggestions := strings.Split(strings.TrimSpace(text), "\n")
	cleaned := []string{}
	for _, s := range suggestions {
		s = strings.TrimSpace(s)
		if s != "" && len(s) > 0 {
			s = strings.TrimPrefix(s, "1. ")
			s = strings.TrimPrefix(s, "2. ")
			s = strings.TrimPrefix(s, "3. ")
			s = strings.TrimPrefix(s, "- ")
			cleaned = append(cleaned, s)
		}
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"suggestions": cleaned})
}

func assistantModerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Analyze this message for harmful content (hate speech, harassment, threats, spam). Respond with ONLY a JSON object: {\"safe\": true/false, \"reason\": \"brief explanation\"}\n\nMessage: %s", req.Text)
	payload := fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, prompt)

	geminiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)
	geminiReq, err := http.NewRequest("POST", geminiURL, bytes.NewReader([]byte(payload)))
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "request_error", err.Error())
		return
	}
	geminiReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	geminiResp, err := client.Do(geminiReq)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", err.Error())
		return
	}
	defer geminiResp.Body.Close()

	if geminiResp.StatusCode != http.StatusOK {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "Gemini API returned error")
		return
	}

	var geminiRes geminiResponse
	if err := json.NewDecoder(geminiResp.Body).Decode(&geminiRes); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "parse_error", err.Error())
		return
	}

	if len(geminiRes.Candidates) == 0 || len(geminiRes.Candidates[0].Content.Parts) == 0 {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no moderation result returned")
		return
	}

	text := geminiRes.Candidates[0].Content.Parts[0].Text
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		result = map[string]any{
			"safe":   !strings.Contains(strings.ToLower(text), "unsafe") && !strings.Contains(strings.ToLower(text), "harmful"),
			"reason": text,
		}
	}

	resp.WriteJSON(w, http.StatusOK, result)
}

func assistantSummarizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Summarize this conversation or message in 1-2 sentences:\n\n%s", req.Text)
	payload := fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, prompt)

	geminiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)
	geminiReq, err := http.NewRequest("POST", geminiURL, bytes.NewReader([]byte(payload)))
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "request_error", err.Error())
		return
	}
	geminiReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	geminiResp, err := client.Do(geminiReq)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", err.Error())
		return
	}
	defer geminiResp.Body.Close()

	if geminiResp.StatusCode != http.StatusOK {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "Gemini API returned error")
		return
	}

	var geminiRes geminiResponse
	if err := json.NewDecoder(geminiResp.Body).Decode(&geminiRes); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "parse_error", err.Error())
		return
	}

	if len(geminiRes.Candidates) == 0 || len(geminiRes.Candidates[0].Content.Parts) == 0 {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no summary returned")
		return
	}

	summary := geminiRes.Candidates[0].Content.Parts[0].Text

	resp.WriteJSON(w, http.StatusOK, map[string]string{"summary": summary})
}

// Swagger UI handler
func swaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WhisperWire API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// OpenAPI spec handler
func openapiHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "openapi/openapi.yaml")
}

