package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
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

		// Verify device belongs to user
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

		// Get undelivered messages for this device
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
	})(w, r)
}

