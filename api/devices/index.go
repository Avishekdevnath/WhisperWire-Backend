package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/crypto"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

// Handler routes device requests
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasSuffix(path, "/register") {
		middleware.RequireAuth(deviceRegisterHandler)(w, r)
	} else if strings.HasSuffix(path, "/list") {
		middleware.RequireAuth(deviceListHandler)(w, r)
	} else if strings.Contains(path, "/prekeys/") {
		// GET /devices/prekeys/{deviceID}
		prekeysGetHandler(w, r)
	} else if strings.HasSuffix(path, "/prekeys") {
		// POST /devices/prekeys
		middleware.RequireAuth(prekeysPostHandler)(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func deviceRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		Name       string `json:"name"`
		Ed25519Pub string `json:"ed25519_pub"`
		X25519Pub  string `json:"x25519_pub"`
	}
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
}

func deviceListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
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
}

func prekeysPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		DeviceID int64    `json:"device_id"`
		Prekeys  []string `json:"prekeys"`
	}
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
}

func prekeysGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/devices/prekeys/")
	path = strings.TrimPrefix(path, "/devices/prekeys/")
	deviceID, err := strconv.ParseInt(path, 10, 64)
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

	var prekeyID int64
	var x25519Pub []byte
	row := pool.QueryRow(ctx,
		`UPDATE prekeys SET is_used = TRUE WHERE id = (
			SELECT id FROM prekeys WHERE device_id = $1 AND is_used = FALSE LIMIT 1
		) RETURNING id, x25519_pub`,
		deviceID,
	)
	if err := row.Scan(&prekeyID, &x25519Pub); err != nil {
		resp.WriteError(w, http.StatusNotFound, "no_prekeys", "no available prekeys for this device")
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{
		"prekey_id":  prekeyID,
		"x25519_pub": base64.StdEncoding.EncodeToString(x25519Pub),
	})
}
