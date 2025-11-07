package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"whisperwire/pkg/auth"
	"whisperwire/pkg/crypto"
	"whisperwire/pkg/db"
	"whisperwire/pkg/middleware"
	"whisperwire/pkg/resp"
)

// Handler routes message requests
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasSuffix(path, "/send") {
		middleware.RequireAuth(messageSendHandler)(w, r)
	} else if strings.HasSuffix(path, "/inbox") {
		middleware.RequireAuth(messageInboxHandler)(w, r)
	} else if strings.Contains(path, "/messages/") {
		// POST /messages/{id}/{status}
		middleware.RequireAuth(messageStatusHandler)(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func messageSendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		ToDeviceID    int64  `json:"to_device_id"`
		FromDevicePub string `json:"from_device_pub"`
		Nonce         string `json:"nonce"`
		Box           string `json:"box"`
		HasAttachment bool   `json:"has_attachment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.ToDeviceID == 0 || req.FromDevicePub == "" || req.Nonce == "" || req.Box == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "to_device_id, from_device_pub, nonce, and box are required")
		return
	}

	maxBytes := 1048576
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
}

func messageInboxHandler(w http.ResponseWriter, r *http.Request) {
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
			"id":              id,
			"from_device_pub": base64.StdEncoding.EncodeToString(fromDevicePub),
			"nonce":           base64.StdEncoding.EncodeToString(nonce),
			"box":             base64.StdEncoding.EncodeToString(box),
			"has_attachment":  hasAttachment,
			"created_at":      createdAt.Format(time.RFC3339),
		})
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

func messageStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	path = strings.TrimPrefix(path, "/messages/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid path format")
		return
	}

	messageID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || messageID <= 0 {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid message_id")
		return
	}

	status := parts[1]
	if status != "delivered" && status != "read" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "status must be 'delivered' or 'read'")
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

	var deviceUserID int64
	row := pool.QueryRow(ctx,
		`SELECT d.user_id FROM messages m 
		 JOIN devices d ON m.to_device_id = d.id 
		 WHERE m.id = $1`,
		messageID,
	)
	if err := row.Scan(&deviceUserID); err != nil {
		resp.WriteError(w, http.StatusNotFound, "message_not_found", "message not found")
		return
	}
	if deviceUserID != userID {
		resp.WriteError(w, http.StatusForbidden, "forbidden", "message does not belong to user")
		return
	}

	var column string
	if status == "delivered" {
		column = "delivered_at"
	} else {
		column = "read_at"
	}

	_, err = pool.Exec(ctx,
		`UPDATE messages SET `+column+` = $1 WHERE id = $2`,
		time.Now(), messageID,
	)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	resp.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}
