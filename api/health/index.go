package handler

import (
	"context"
	"net/http"
	"time"

	"whisperwire/pkg/config"
	"whisperwire/pkg/db"
	"whisperwire/pkg/resp"
)

// Handler for health check
func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	status := map[string]any{"status": "ok"}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if pool, err := db.Get(ctx); err == nil {
		if err := pool.Ping(ctx); err == nil {
			status["db"] = "up"
		} else {
			status["db"] = "down"
			status["db_error"] = err.Error()
		}
	} else {
		status["db"] = "down"
		status["db_error"] = err.Error()
	}
	resp.WriteJSON(w, http.StatusOK, status)
}
