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

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	User         interface{} `json:"user"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req signupRequest
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

	resp.WriteJSON(w, http.StatusOK, authResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User: map[string]any{
			"id":    userID,
			"email": req.Email,
		},
	})
}
