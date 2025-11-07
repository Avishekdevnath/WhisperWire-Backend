package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"whisperwire/pkg/resp"
)

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// Handler routes assistant requests
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	
	if strings.HasSuffix(path, "/suggest") {
		assistantSuggestHandler(w, r)
	} else if strings.HasSuffix(path, "/moderate") {
		assistantModerateHandler(w, r)
	} else if strings.HasSuffix(path, "/summarize") {
		assistantSummarizeHandler(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func assistantSuggestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
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
	cleaned := []string{}
	for _, s := range suggestions {
		s = strings.TrimSpace(s)
		if s != "" && len(s) > 0 {
			s = strings.TrimPrefix(s, "1. ")
			s = strings.TrimPrefix(s, "2. ")
			s = strings.TrimPrefix(s, "3. ")
			s = strings.TrimPrefix(s, "- ")
			cleaned = append(cleaned, s)
		}
	}

	resp.WriteJSON(w, http.StatusOK, map[string]any{"suggestions": cleaned})
}

func assistantModerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Analyze this message for harmful content (hate speech, harassment, threats, spam). Respond with ONLY a JSON object: {\"safe\": true/false, \"reason\": \"brief explanation\"}\n\nMessage: %s", req.Text)
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
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no moderation result returned")
		return
	}

	text := geminiRes.Candidates[0].Content.Parts[0].Text
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		result = map[string]any{
			"safe":   !strings.Contains(strings.ToLower(text), "unsafe") && !strings.Contains(strings.ToLower(text), "harmful"),
			"reason": text,
		}
	}

	resp.WriteJSON(w, http.StatusOK, result)
}

func assistantSummarizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		resp.WriteError(w, http.StatusServiceUnavailable, "ai_unavailable", "GEMINI_API_KEY not configured")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	if req.Text == "" {
		resp.WriteError(w, http.StatusBadRequest, "bad_request", "text is required")
		return
	}

	prompt := fmt.Sprintf("Summarize this conversation or message in 1-2 sentences:\n\n%s", req.Text)
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
		resp.WriteError(w, http.StatusInternalServerError, "ai_error", "no summary returned")
		return
	}

	summary := geminiRes.Candidates[0].Content.Parts[0].Text

	resp.WriteJSON(w, http.StatusOK, map[string]string{"summary": summary})
}

