package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whisperwire/internal/auth"
	"whisperwire/internal/config"
	"whisperwire/internal/db"
	"whisperwire/internal/middleware"
	"whisperwire/internal/resp"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		// Extract message ID and status from path: /api/messages/{id}/{delivered|read}
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

		// Verify message belongs to user's device
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

		// Update status
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
	})(w, r)
}

