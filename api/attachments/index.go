package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/config"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

type attachmentRequest struct {
	MessageID int64  `json:"message_id"`
	Bytes     string `json:"bytes"` // base64 encoded attachment
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		var req attachmentRequest
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

		maxBytes := 2097152 // 2MB default
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

		// Verify message exists and belongs to user
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
	})(w, r)
}

