package main

// WIP: this is the server with resources

import (
	"crypto/tls"
	"net/http"
)

var port = ":8443"

func main() {
	// TODO: look into this
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	mux := http.NewServeMux()

	// store := store.New()
	// postHandler := auth.NewHandler(store)

	// Routes
	// mux.HandleFunc("GET /posts", authHandler.Authorization)

	server := &http.Server{
		Addr:      port,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		// TODO:
	}
}
