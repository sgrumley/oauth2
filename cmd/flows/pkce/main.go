package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sgrumley/oauth/pkg/auth"
	"github.com/sgrumley/oauth/pkg/authcode"
	"github.com/sgrumley/oauth/pkg/config"
	"github.com/sgrumley/oauth/pkg/logger"
	"github.com/sgrumley/oauth/pkg/sync"
	"github.com/sgrumley/oauth/pkg/web"
	"golang.org/x/oauth2"
)

type PKCEConfig struct {
	ClientID     string `yaml:"ClientID"`
	RedirectURI  string `yaml:"RedirectURI"`
	AuthURL      string `yaml:"AuthURL"`
	TokenURL     string `yaml:"TokenURL"`
	ClientSecret string `yaml:"ClientSecret"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.NewLogger()
	log.Logger = log.With(slog.String("service", "[CLIENT PKCE]"))
	ctx = logger.AddLoggerContext(ctx, log.Logger)

	env, err := config.LoadEnvVarFile()
	if err != nil {
		logger.Fatal(ctx, "failed to load environment config", err)
	}

	cfg, err := config.LoadYAMLDocument[PKCEConfig](env.AuthCodeConfig)
	if err != nil {
		logger.Fatal(ctx, "failed to load yaml config: ", err)
	}

	mux := http.NewServeMux()
	s := sync.New()
	// Routes
	mux.HandleFunc("GET /callback", sync.Callback(log, s))
	mux.HandleFunc("POST /callback", sync.Callback(log, s))

	server := &http.Server{
		Addr:    env.AuthCodeHost + env.AuthCodePort,
		Handler: mux,
	}

	go func() {
		PKCEFlow(ctx, cfg, s)
		time.Sleep(1 * time.Second)
		cancel()
	}()

	logger.Info(ctx, "[Client] listening on localhost"+env.AuthCodePort)
	if err := web.ListenAndServe(ctx, server); err != nil {
		logger.Error(ctx, "server error", err)
		return
	}
}

// PKCEFlow demonstrates the OAuth2 Authorization Code flow with PKCE extension
// RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
func PKCEFlow(ctx context.Context, cfg *PKCEConfig, s *sync.Sync) {
	logger.Info(ctx, "started auth flow")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	state, err := auth.GenerateState()
	if err != nil {
		logger.Fatal(ctx, "failed to generate state", err)
	}

	ch := s.Register(state)

	conf := &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
		RedirectURL: cfg.RedirectURI,
		Scopes:      []string{"read post"},
	}

	// RFC 7636 Section 4.1: PKCE flow - Create code verifier and challenge
	codeVerifier := auth.GenerateCodeVerifier()
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)

	// RFC 7636 Section 4.3: Build authorization URL with PKCE parameters
	codeURL := conf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"), // RFC 7636 Section 4.2: S256 method recommended
	)

	if err := authcode.GetAuthorizationCode(ctx, codeURL); err != nil {
		logger.Error(ctx, "get auth code request failed", err)
		return
	}

	logger.Info(ctx, "waiting for authorization code")
	callbackHandler := <-ch
	logger.Info(ctx, "auth Code Response", slog.String("code", callbackHandler.AuthCode))

	if state != callbackHandler.State {
		logger.Fatal(ctx, "server error", fmt.Errorf("state mismatch: expected %s, got %s", state, callbackHandler.State))
	}

	// RFC 7636 Section 4.5: Exchange auth code with code_verifier for access token
	logger.Info(ctx, "calling /token")
	token, err := conf.Exchange(ctx, callbackHandler.AuthCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		logger.Fatal(ctx, "server error", err)
	}

	logger.Info(ctx, "flow completed with Token",
		slog.String("access_token", token.AccessToken),
		slog.String("refresh_token", token.RefreshToken), // this will come in a later commit
		slog.Int64("expire_time", token.ExpiresIn),
		slog.String("token_type", token.TokenType),
	)

	logger.Info(ctx, "Shutting down client")
}
