package main

import (
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// getAuroCertTLSConf is used if NoTLS is set to false.
// Note that a CertDir must be specified in the config if NoTLS is set to false
func getServer(mux *http.ServeMux) (server *http.Server) {
	var certdir string
	if config.CertDir != "" {
		certdir = config.CertDir
	} else {
		certdir = config.BaseDir
	}

	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certdir),
		HostPolicy: autocert.HostWhitelist(config.DomainNames...),
		Email:      config.Email,
	}
	tlsConf := &tls.Config{
		Rand:       rand.Reader,
		Time:       time.Now,
		NextProtos: []string{acme.ALPNProto, "http/1.1"},
		MinVersion: tls.VersionTLS12,
		// X25519 first: fastest handshake and forward-secret; P-256 as fallback.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		GetCertificate:   m.GetCertificate,
		// Only AEAD cipher suites for TLS 1.2; TLS 1.3 cipher selection is automatic.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	server = &http.Server{
		Addr:         config.TLSAddressPort,
		Handler:      mux,
		TLSConfig:    tlsConf,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// https://blog.bracebin.com/achieving-perfect-ssl-labs-score-with-go
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	// Handle ACME "http-01" challenge responses on external port 80.
	go http.ListenAndServe(config.AddressPort, m.HTTPHandler(nil))
	return
}
