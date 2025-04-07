package main

// This is the auth server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/sgrumley/oauth/internal/service/auth"
	"github.com/sgrumley/oauth/internal/store"
)

var port = ":8082"

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

	store := store.New()
	authHandler := auth.NewHandler(store)

	// Routes
	mux.HandleFunc("GET /authorize", authHandler.Authorization)
	mux.HandleFunc("POST /oauth/token", authHandler.Token)

	server := &http.Server{
		Addr:      port,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	fmt.Println("listening on localhost" + port)
	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
}
