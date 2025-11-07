package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"whisperwire/internal/config"
	"whisperwire/internal/resp"
)

type suggestRequest struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	config.Init()
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req suggestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Write 3 short friendly replies to:\n\n%s", req.Text)
	payload := fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, prompt)

	geminiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)
	geminiReq, err := http.NewRequest("POST", geminiURL, bytes.NewReader([]byte(payload)))
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "request_error", err.Error())
		return
	}
	geminiReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	geminiResp, err := client.Do(geminiReq)
	if err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", err.Error())
		return
	}
	defer geminiResp.Body.Close()

	if geminiResp.StatusCode != http.StatusOK {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "Gemini API returned error")
		return
	}

	var geminiRes geminiResponse
	if err := json.NewDecoder(geminiResp.Body).Decode(&geminiRes); err != nil {
		resp.WriteError(w, http.StatusInternalServerError, "parse_error", err.Error())
		return
	}

	if len(geminiRes.Candidates) == 0 || len(geminiRes.Candidates[0].Content.Parts) == 0 {
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no suggestions returned")
		return
	}

	text := geminiRes.Candidates[0].Content.Parts[0].Text
	suggestions := strings.Split(strings.TrimSpace(text), "\n")
	// Filter empty and clean up
	cleaned := []string{}
	for _, s := range suggestions {
		s = strings.TrimSpace(s)
		if s != "" && len(s) > 0 {
			// Remove numbering if present
			s = strings.TrimPrefix(s, "1. ")
			s = strings.TrimPrefix(s, "2. ")
			s = strings.TrimPrefix(s, "3. ")
			s = strings.TrimPrefix(s, "- ")
			cleaned = append(cleaned, s)
		}
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"suggestions": cleaned})
}

