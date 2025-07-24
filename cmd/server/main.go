package main

import (
	"context"
	"net/http"

	"github.com/sgrumley/oauth/internal/service/authcode"
	"github.com/sgrumley/oauth/internal/store"
	"github.com/sgrumley/oauth/pkg/config"
	"github.com/sgrumley/oauth/pkg/logger"
	"github.com/sgrumley/oauth/pkg/middleware"
	"github.com/sgrumley/oauth/pkg/sync"
	"github.com/sgrumley/oauth/pkg/web"
)

type ServerConfig struct {
	LoginURL string `yaml:"loginURL"`
}

func main() {
	ctx := context.Background()
	log := logger.NewLogger()
	ctx = logger.AddLoggerContext(ctx, log.Logger)

	// tlsConfig := web.GetDefaultConfig()
	env, err := config.LoadEnvVarFile()
	if err != nil {
		logger.Error(ctx, "failed to load environment config", err)
		return
	}

	cfg, err := config.LoadYAMLDocument[ServerConfig](env.ServerConfig)
	if err != nil {
		logger.Error(ctx, "failed to load yaml config: ", err)
		return
	}

	store := store.New()
	s := sync.New()
	authHandler := authcode.NewHandler(store, cfg.LoginURL, s)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", authHandler.Authorization)
	mux.HandleFunc("POST /oauth/token", authHandler.Token)

	mux.HandleFunc("GET /callback", sync.Callback(log, s))
	mux.HandleFunc("POST /api/login", authcode.HandleLogin)

	wrappedMux := middleware.LoggerMiddleware(mux, "SERVER")
	wrappedMux = middleware.CorsMiddleware(wrappedMux)

	server := &http.Server{
		Addr: env.ServerHost + env.ServerPort,
		// TLSConfig: tlsConfig,
		Handler: wrappedMux,
	}

	log.Info("[Server] listening on localhost" + env.AuthCodePort)
	if err := web.ListenAndServe(ctx, server); err != nil {
		logger.Error(ctx, "server error", err)
		return
	}
	// err := server.ListenAndServeTLS("server.crt", "server.key")
}
