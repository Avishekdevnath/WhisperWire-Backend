package handler

import (
	"net/http"
	"strings"

	"whisperwire/pkg/middleware"
)

// Handler is the main entry point for all API routes on Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Route to appropriate handler based on path
	switch {
	case path == "/api/health" || path == "/health":
		healthHandler(w, r)
	case path == "/api/_admin/migrate" || path == "/_admin/migrate":
		migrateHandler(w, r)
	case path == "/api/auth/signup" || path == "/auth/signup":
		signupHandler(w, r)
	case path == "/api/auth/login" || path == "/login":
		loginHandler(w, r)
	case path == "/api/devices/register" || path == "/devices/register":
		middleware.RequireAuth(deviceRegisterHandler)(w, r)
	case path == "/api/devices/list" || path == "/devices/list":
		middleware.RequireAuth(deviceListHandler)(w, r)
	case path == "/api/devices/prekeys" || path == "/devices/prekeys":
		middleware.RequireAuth(prekeysPostHandler)(w, r)
	case strings.HasPrefix(path, "/api/devices/prekeys/") || strings.HasPrefix(path, "/devices/prekeys/"):
		prekeysGetHandler(w, r)
	case path == "/api/messages/send" || path == "/messages/send":
		middleware.RequireAuth(messageSendHandler)(w, r)
	case path == "/api/messages/inbox" || path == "/messages/inbox":
		middleware.RequireAuth(messageInboxHandler)(w, r)
	case strings.HasPrefix(path, "/api/messages/") || strings.HasPrefix(path, "/messages/"):
		middleware.RequireAuth(messageStatusHandler)(w, r)
	case path == "/api/attachments" || path == "/attachments":
		middleware.RequireAuth(attachmentPostHandler)(w, r)
	case strings.HasPrefix(path, "/api/attachments/") || strings.HasPrefix(path, "/attachments/"):
		middleware.RequireAuth(attachmentGetHandler)(w, r)
	case path == "/api/assistant/suggest" || path == "/assistant/suggest":
		assistantSuggestHandler(w, r)
	case path == "/api/assistant/moderate" || path == "/assistant/moderate":
		assistantModerateHandler(w, r)
	case path == "/api/assistant/summarize" || path == "/assistant/summarize":
		assistantSummarizeHandler(w, r)
	case path == "/" || path == "/api" || path == "/api/" || path == "/docs" || path == "/api/docs":
		swaggerUIHandler(w, r)
	case path == "/openapi.yaml" || path == "/api/openapi.yaml":
		openapiHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}
