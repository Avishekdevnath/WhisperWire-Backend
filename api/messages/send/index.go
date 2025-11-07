package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"whisperwire/internal/auth"
	"whisperwire/internal/config"
	"whisperwire/internal/crypto"
	"whisperwire/internal/db"
	"whisperwire/internal/middleware"
	"whisperwire/internal/resp"
)

type sendRequest struct {
	ToDeviceID    int64  `json:"to_device_id"`
	FromDevicePub string `json:"from_device_pub"` // base64 Ed25519 public key
	Nonce          string `json:"nonce"`          // base64 nonce
	Box            string `json:"box"`             // base64 encrypted message
	HasAttachment  bool   `json:"has_attachment"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		var req sendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		if req.ToDeviceID == 0 || req.FromDevicePub == "" || req.Nonce == "" || req.Box == "" {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "to_device_id, from_device_pub, nonce, and box are required")
			return
		}

		// Validate sizes
		maxBytes := 1048576 // 1MB default
		if v := os.Getenv("MAX_MESSAGE_BYTES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxBytes = n
			}
		}

		nonce, err := crypto.DecodeBase64Key(req.Nonce)
		if err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid nonce encoding")
			return
		}
		box, err := crypto.DecodeBase64Key(req.Box)
		if err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid box encoding")
			return
		}
		fromDevicePub, err := crypto.DecodeBase64Key(req.FromDevicePub)
		if err != nil {
			resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid from_device_pub encoding")
			return
		}

		if len(box) > maxBytes {
			resp.WriteError(w, http.StatusBadRequest, "message_too_large", "message exceeds maximum size")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		pool, err := db.Get(ctx)
		if err != nil {
			resp.WriteError(w, http.StatusInternalServerError, "db_connect_error", err.Error())
			return
		}

		// Verify to_device exists
		var toDeviceExists bool
		row := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)`, req.ToDeviceID)
		if err := row.Scan(&toDeviceExists); err != nil || !toDeviceExists {
			resp.WriteError(w, http.StatusNotFound, "device_not_found", "target device not found")
			return
		}

		var messageID int64
		row = pool.QueryRow(ctx,
			`INSERT INTO messages (to_device_id, from_device_pub, nonce, box, has_attachment) 
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			req.ToDeviceID, fromDevicePub, nonce, box, req.HasAttachment,
		)
		if err := row.Scan(&messageID); err != nil {
			resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
			return
		}

		resp.WriteJSON(w, http.StatusOK, map[string]any{
			"message_id": messageID,
			"status":     "sent",
		})
	})(w, r)
}

