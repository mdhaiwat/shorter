package main

import (
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// handleQR registers the /qr/ route, which returns a QR code PNG for a short link.
func handleQR(mux *http.ServeMux) {
	mux.HandleFunc("/qr/", qrHandler)
}

// qrHandler serves GET /qr/{key} — returns a 256×256 PNG QR code encoding the
// full short URL for the given key. The image is cached for 24 hours.
func qrHandler(w http.ResponseWriter, r *http.Request) {
	if !validRequest(r) {
		http.Error(w, errServerError, http.StatusInternalServerError)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.TrimPrefix(r.URL.Path, "/qr/")
	key = strings.TrimSuffix(key, "/")
	if len(key) == 0 || !validate(key) {
		http.Error(w, errInvalidKey, http.StatusBadRequest)
		return
	}

	lnk, _ := lookupLink(r.Host, key)
	if lnk == nil {
		// Also check static links.
		if _, ok := config.StaticLinks[key]; !ok {
			http.Error(w, errInvalidKey, http.StatusNotFound)
			return
		}
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	shortURL := scheme + "://" + r.Host + "/" + key

	png, err := qrcode.Encode(shortURL, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, errServerError, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "max-age=86400, public")
	w.Write(png)
	logOK(r, http.StatusOK)
}
