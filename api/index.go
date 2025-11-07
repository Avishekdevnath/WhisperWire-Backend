package handler

import (
	"net/http"
)

// Handler redirects root to API docs
func Handler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/api/docs", http.StatusMovedPermanently)
}

