package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

// Handler routes attachment requests
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.Contains(path, "/attachments/") && r.Method == http.MethodGet {
		// GET /attachments/{id}
		middleware.RequireAuth(attachmentGetHandler)(w, r)
	} else if strings.HasSuffix(path, "/attachments") && r.Method == http.MethodPost {
		// POST /attachments
		middleware.RequireAuth(attachmentPostHandler)(w, r)
	} else {
		http.NotFound(w, r)
	}
}

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
	path = strings.TrimPrefix(path, "/attachments/")
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
