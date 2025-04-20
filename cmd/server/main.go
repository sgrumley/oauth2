package main

// This is the auth server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/sgrumley/oauth/internal/service/auth"
	"github.com/sgrumley/oauth/internal/store"
	"github.com/sgrumley/oauth/pkg/middleware"
)

var port = ":8082"

func main() {
	// tlsConfig := web.GetDefaultConfig()

	mux := http.NewServeMux()

	store := store.New()
	authHandler := auth.NewHandler(store)

	// Routes
	mux.HandleFunc("GET /authorize", authHandler.Authorization)
	mux.HandleFunc("POST /oauth/token", authHandler.Token)

	mux.HandleFunc("GET /callback", auth.Callback)
	mux.HandleFunc("POST /api/login", auth.HandleLogin)

	wrappedMux := middleware.CorsMiddleware(mux)

	server := &http.Server{
		Addr: port,
		// TLSConfig: tlsConfig,
		Handler: wrappedMux,
	}

	fmt.Println("listening on localhost" + port)
	// err := server.ListenAndServeTLS("server.crt", "server.key")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
