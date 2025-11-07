package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"whisperwire/internal/auth"
	"whisperwire/internal/config"
	"whisperwire/internal/db"
	"whisperwire/internal/resp"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req loginRequest
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
