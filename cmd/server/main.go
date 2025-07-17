package main

import (
	"context"
	"log"
	"net/http"

	"github.com/sgrumley/oauth/internal/service/authcode"
	"github.com/sgrumley/oauth/internal/store"
	"github.com/sgrumley/oauth/pkg/config"
	"github.com/sgrumley/oauth/pkg/middleware"
	"github.com/sgrumley/oauth/pkg/web"
)

type ServerConfig struct {
	LoginURL string `yaml:"loginURL"`
}

func main() {
	ctx := context.Background()
	// tlsConfig := web.GetDefaultConfig()
	env, err := config.LoadEnvVarFile()
	if err != nil {
		log.Fatal("failed to load environment config", err)
	}
	cfg, err := config.LoadYAMLDocument[ServerConfig](env.ServerConfig)
	if err != nil {
		log.Fatal("failed to load yaml config: ", err)
	}

	store := store.New()
	authHandler := authcode.NewHandler(store, cfg.LoginURL)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", authHandler.Authorization)
	mux.HandleFunc("POST /oauth/token", authHandler.Token)

	mux.HandleFunc("GET /callback", authcode.Callback)
	mux.HandleFunc("POST /api/login", authcode.HandleLogin)

	wrappedMux := middleware.CorsMiddleware(mux)

	server := &http.Server{
		Addr: env.ServerHost + env.ServerPort,
		// TLSConfig: tlsConfig,
		Handler: wrappedMux,
	}

	web.ListenAndServe(ctx, server)
	// err := server.ListenAndServeTLS("server.crt", "server.key")
}
