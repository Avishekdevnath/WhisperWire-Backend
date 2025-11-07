package resp

import (
	"encoding/json"
	"net/http"
)

type ErrorPayload struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorPayload{Error: message, Code: code})
}
