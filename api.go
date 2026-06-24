package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// API request / response types

type apiShortenRequest struct {
	URL    string `json:"url"`
	Key    string `json:"key"`    // optional custom key (4-64 chars)
	Len    string `json:"len"`    // "1", "2", "3", or "custom"
	XTimes int    `json:"x_times"` // max accesses; omit or 0 for unlimited
}

type apiShortenResponse struct {
	Key      string `json:"key"`
	ShortURL string `json:"short_url"`
	Expires  string `json:"expires"`
}

type apiLookupResponse struct {
	Key            string `json:"key"`
	LinkType       string `json:"link_type"`
	URL            string `json:"url,omitempty"`
	Expires        string `json:"expires"`
	AccessCount    int64  `json:"access_count"`
	TimesRemaining int    `json:"times_remaining"` // -1 = unlimited
}

func handleAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/shorten", apiShorten)
	mux.HandleFunc("/api/v1/lookup/", apiLookup)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// apiShorten handles POST /api/v1/shorten
// Body: {"url":"https://...","len":"1","x_times":0}
// Returns: {"key":"ab","short_url":"https://host/ab","expires":"..."}
func apiShorten(w http.ResponseWriter, r *http.Request) {
	if !validRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !rateLimitAllow(r.RemoteAddr) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	var req apiShortenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if !validURL(req.URL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid URL; only http and https are allowed"})
		return
	}
	if isBlocklisted(req.URL) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "URL is not allowed"})
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Dedup: return existing unlimited short link for the same URL if no custom key requested.
	if req.Key == "" && req.XTimes <= 0 {
		if existing := findExistingURL(r.Host, req.URL); existing != nil {
			writeJSON(w, http.StatusOK, apiShortenResponse{
				Key:      existing.Key,
				ShortURL: scheme + "://" + r.Host + "/" + existing.Key,
				Expires:  existing.Timeout.Format(dateFormat),
			})
			return
		}
	}

	// Choose the target LinkLen bucket.
	var ll *LinkLen
	switch req.Len {
	case "2":
		ll = &domainLinkLens[r.Host].LinkLen2
	case "3":
		ll = &domainLinkLens[r.Host].LinkLen3
	case "custom":
		if !validate(req.Key) || len(req.Key) < 4 || len(req.Key) > maxKeyLen {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidCustomKey})
			return
		}
		ll = &domainLinkLens[r.Host].LinkCustom
	default:
		ll = &domainLinkLens[r.Host].LinkLen1
	}

	xTimes := req.XTimes
	if xTimes < 1 {
		xTimes = -1
	} else if xTimes > config.LinkAccessMaxNr {
		xTimes = config.LinkAccessMaxNr
	}

	ll.Mutex.RLock()
	timeout := ll.Timeout
	ll.Mutex.RUnlock()

	lnk := &Link{
		Key:      req.Key,
		LinkType: "url",
		Data:     req.URL,
		Times:    xTimes,
		Timeout:  time.Now().Add(timeout),
	}
	key, err := ll.Add(lnk)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, apiShortenResponse{
		Key:      key,
		ShortURL: scheme + "://" + r.Host + "/" + key,
		Expires:  lnk.Timeout.Format(dateFormat),
	})
}

// apiLookup handles GET /api/v1/lookup/{key}
// Returns metadata for the key without consuming an access.
func apiLookup(w http.ResponseWriter, r *http.Request) {
	if !validRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	key := strings.TrimPrefix(r.URL.Path, "/api/v1/lookup/")
	key = strings.TrimSuffix(key, "/")
	if !validate(key) || len(key) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidKey})
		return
	}

	lnk, _ := lookupLink(r.Host, key)
	if lnk == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}

	resp := apiLookupResponse{
		Key:            key,
		LinkType:       lnk.LinkType,
		Expires:        lnk.Timeout.Format(dateFormat),
		AccessCount:    lnk.AccessCount,
		TimesRemaining: lnk.Times,
	}
	if lnk.LinkType == "url" {
		resp.URL = lnk.Data
	}
	writeJSON(w, http.StatusOK, resp)
}
