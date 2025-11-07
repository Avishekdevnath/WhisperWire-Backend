package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"whisperwire/internal/auth"
	"whisperwire/internal/config"
	"whisperwire/internal/crypto"
	"whisperwire/internal/db"
	"whisperwire/internal/middleware"
	"whisperwire/internal/resp"
)

type prekeysRequest struct {
	DeviceID int64    `json:"device_id"`
	Prekeys  []string `json:"prekeys"` // array of base64-encoded X25519 public keys
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		var req prekeysRequest
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

		// Verify device belongs to user
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

		// Validate and insert prekeys
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
	})(w, r)
}

