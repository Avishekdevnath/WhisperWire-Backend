package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/config"
	"whisperwire/pkg/crypto"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

type registerRequest struct {
	Name       string `json:"name"`
	Ed25519Pub string `json:"ed25519_pub"` // base64 encoded
	X25519Pub  string `json:"x25519_pub"`  // base64 encoded
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		var req registerRequest
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
	})(w, r)
}
