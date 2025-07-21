package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sgrumley/oauth/pkg/auth"
	"github.com/sgrumley/oauth/pkg/authcode"
	"github.com/sgrumley/oauth/pkg/config"
	"github.com/sgrumley/oauth/pkg/logger"
	"github.com/sgrumley/oauth/pkg/web"
)

var (
	pkceChan  = make(chan string)
	stateChan = make(chan string)
	scopes    = "posts read"
)

type PKCEConfig struct {
	ClientID    string `yaml:"ClientID"`
	RedirectURI string `yaml:"RedirectURI"`
	AuthURL     string `yaml:"AuthURL"`
	TokenURL    string `yaml:"TokenURL"`
}

func main() {
	ctx := context.Background()
	log := logger.NewLogger()
	ctx = logger.AddLoggerContext(ctx, log.Logger)

	env, err := config.LoadEnvVarFile()
	if err != nil {
		logger.Fatal(ctx, "failed to load environment config", err)
	}

	cfg, err := config.LoadYAMLDocument[PKCEConfig](env.PKCEConfig)
	if err != nil {
		logger.Fatal(ctx, "failed to load yaml config: ", err)
	}

	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("GET /callback", callback)
	mux.HandleFunc("POST /callback", callback)

	server := &http.Server{
		Addr:    env.PKCEHost + env.PKCEPort,
		Handler: mux,
	}

	go PKCEFlow(ctx, cfg)

	logger.Info(ctx, "[Client] listening on localhost"+env.AuthCodePort)
	if err := web.ListenAndServe(ctx, server); err != nil {
		logger.Error(ctx, "server error", err)
		return
	}
}

func PKCEFlow(ctx context.Context, cfg *PKCEConfig) {
	logger.Info(ctx, "[Client] Started auth flow")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cli := &http.Client{
		Timeout: 3 * time.Minute,
	}

	state, err := auth.GenerateState()
	if err != nil {
		logger.Fatal(ctx, "failed to generate state", err)
	}

	client := authcode.NewClient(cfg.ClientID, cfg.RedirectURI, cfg.TokenURL, cfg.AuthURL, cli)

	// Step 1: Create a secret code verifier and code challenge
	codeVerifier := auth.GenerateCodeVerifier()
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)

	// Step 2: Build the authorization URL and redirect the user to the auth server
	// TODO: build out the auth code to accept PKCE
	if err := client.GetAuthorizationCode(ctx, scopes, state); err != nil {
		logger.Error(ctx, "get auth code request failed", err)
		return
	}

	logger.Info(ctx, "[Client] Waiting for authorization code")
	// TODO: look for a better way to do this? A way to get the correct authcode if called multiple times?
	select {
	case <-ctx.Done():
		logger.Fatal(ctx, "deadline exceeded for callback", fmt.Errorf("server timeout"))
	case <-authCodeChan:
	}
	authCode := <-authCodeChan
	returnedState := <-stateChan
	logger.Info(ctx, "[Client] Auth Code Response", slog.String("code", authCode))

	// Step 4: Exchange the auth code and code verifier for an access token
	logger.Info(ctx, "[Client] Calling /token")
	token, err := client.ExchangeCodeForToken(ctx, authCode, returnedState, state)
	if err != nil {
		logger.Fatal(ctx, "server error", err)
	}
	logger.Info(ctx, "[Client] flow completed with Token",
		slog.String("access_token", token.AccessToken),
		slog.String("refresh_token", token.RefreshToken),
		slog.Int("expire_time", token.ExpiresIn),
		slog.String("token_type", token.TokenType),
		slog.String("scope", token.Scope),
	)

	logger.Info(ctx, "Shutting down client")
	os.Exit(1)
}

func callback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Client] Callback Received")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Check for errors in the callback
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		fmt.Fprintf(w, errMsg, errDesc)
		return
	}

	fmt.Fprintf(w,
		r.URL.String(),
		code,
		state,
	)

	fmt.Println("[Client] Callback - channel sent")
	go func() {
		pkceChan <- code
		stateChan <- state
	}()
}
