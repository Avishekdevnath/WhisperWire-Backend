package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/config"
	"whisperwire/pkg/db"
	"whisperwire/pkg/resp"
)

// Handler routes auth requests (signup/login)
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasSuffix(path, "/signup") {
		signupHandler(w, r)
	} else if strings.HasSuffix(path, "/login") {
		loginHandler(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
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

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"user": map[string]any{
			"id":    userID,
			"email": req.Email,
		},
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
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
