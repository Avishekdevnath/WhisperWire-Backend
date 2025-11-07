package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whisperwire/internal/config"
	"whisperwire/internal/db"
	"whisperwire/internal/resp"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodGet {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	// Extract deviceID from path: /api/devices/prekeys/{deviceID}
	path := strings.TrimPrefix(r.URL.Path, "/api/devices/prekeys/")
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

	// Get one unused prekey and mark it as used
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

