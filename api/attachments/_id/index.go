package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/config"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}

		// Extract attachment ID from path: /api/attachments/{id}
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

		// Verify attachment belongs to user's message
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
	})(w, r)
}

