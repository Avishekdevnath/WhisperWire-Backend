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

		// Allow query param override for admin or same user
		if userIDParam := r.URL.Query().Get("user_id"); userIDParam != "" {
			if parsedID, err := strconv.ParseInt(userIDParam, 10, 64); err == nil {
				// Only allow if same user (or admin check could go here)
				if parsedID == userID {
					userID = parsedID
				}
			}
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
	})(w, r)
}

