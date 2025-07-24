package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/trace"
	"time"

	"github.com/sgrumley/oauth/pkg/auth"
	"github.com/sgrumley/oauth/pkg/authcode"
	"github.com/sgrumley/oauth/pkg/config"
	"github.com/sgrumley/oauth/pkg/logger"
	"github.com/sgrumley/oauth/pkg/sync"
	"github.com/sgrumley/oauth/pkg/web"
	"golang.org/x/oauth2"
)

type AuthCodeConfig struct {
	ClientID     string `yaml:"ClientID"`
	RedirectURI  string `yaml:"RedirectURI"`
	AuthURL      string `yaml:"AuthURL"`
	TokenURL     string `yaml:"TokenURL"`
	ClientSecret string `yaml:"ClientSecret"`
}

func main() {
	f, _ := os.Create("trace.out")
	_ = trace.Start(f)
	defer trace.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.NewLogger()
	log.Logger = log.With(slog.String("service", "[CLIENT AUTH CODE]"))
	ctx = logger.AddLoggerContext(ctx, log.Logger)

	env, err := config.LoadEnvVarFile()
	if err != nil {
		logger.Fatal(ctx, "failed to load environment config", err)
	}

	cfg, err := config.LoadYAMLDocument[AuthCodeConfig](env.AuthCodeConfig)
	if err != nil {
		logger.Fatal(ctx, "failed to load yaml config: ", err)
	}

	mux := http.NewServeMux()

	// Routes
	s := sync.New()
	mux.HandleFunc("GET /callback", sync.Callback(log, s))
	mux.HandleFunc("POST /callback", sync.Callback(log, s))

	server := &http.Server{
		Addr:    env.AuthCodeHost + env.AuthCodePort,
		Handler: mux,
	}

	go func() {
		AuthorizationCodeFlow(ctx, cfg, s)
		// This sleep just prevents the server shutting down before the callback endpoint has been hit. Updating the auth endpoint to use a http.Client instead will also resolve the issue
		time.Sleep(1 * time.Second)
		cancel()
	}()

	logger.Info(ctx, "[Client] listening on localhost"+env.AuthCodePort)
	if err := web.ListenAndServe(ctx, server); err != nil {
		logger.Error(ctx, "server error", err)
		return
	}
}

/* RFC 6749 Section 4.1.1: Authorization Request example
 https://authorization-server.com/authorize?
	response_type=code
	&client_id=oEGPvWefgcAyteDkBT4b2QSN
	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
	&scope=photo+offline_access
	&state=OqEo1LX_r-atq7-L
*/

// AuthorizationCodeFlow demonstrates the standard OAuth2 Authorization Code flow
// RFC 6749 Section 4.1: Authorization Code Grant
func AuthorizationCodeFlow(ctx context.Context, cfg *AuthCodeConfig, s *sync.Sync) {
	logger.Info(ctx, "Started auth flow")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// RFC 6749 Section 4.1: Authorization Code Grant flow

	conf := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.AuthURL,
			TokenURL:  cfg.TokenURL,
			AuthStyle: 1,
		},
		RedirectURL: cfg.RedirectURI,
		Scopes:      []string{"read post"},
	}

	// RFC 6749 Section 10.12: CSRF protection using state parameter
	state, err := auth.GenerateState()
	if err != nil {
		logger.Fatal(ctx, "failed to generate state", err)
	}

	ch := s.Register(state)

	// RFC 6749 Section 4.1.1: Authorization Request
	codeURL := conf.AuthCodeURL(state)
	if err := authcode.GetAuthorizationCode(ctx, codeURL); err != nil {
		logger.Error(ctx, "get auth code request failed", err)
		return
	}

	logger.Info(ctx, "Waiting for authorization code")
	callbackHandler := <-ch
	logger.Info(ctx, "Auth Code", slog.String("code", callbackHandler.AuthCode))

	// Step 3: After the user is redirected back to the client, verify the state matches and get token
	if state != callbackHandler.State {
		logger.Fatal(ctx, "server error", fmt.Errorf("state mismatch: expected %s, got %s", state, callbackHandler.State))
	}

	// RFC 6749 Section 4.1.3: Exchange authorization code for access token
	logger.Info(ctx, "calling /token")
	token, err := conf.Exchange(ctx, callbackHandler.AuthCode)
	if err != nil {
		logger.Fatal(ctx, "server error", err)
	}

	logger.Info(ctx, "flow completed with Token",
		slog.String("access_token", token.AccessToken),
		slog.String("refresh_token", token.RefreshToken), // this will come in a later commit
		slog.Int64("expire_time", token.ExpiresIn),
		slog.String("token_type", token.TokenType),
	)

	// log the claims after unmarshalling jwt??
	/*
		accessToken := tok.AccessToken

		    // Parse the JWT
		    token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		        // Provide the public key or secret used to sign the JWT
		        // For example, for HS256:
		        return []byte("provider-secret"), nil
		    })
		    if err != nil {
		        fmt.Println("JWT parsing error:", err)
		        return
		    }
		    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		        fmt.Println("OAuth2 JWT claims:", claims)
		    }
	*/

	logger.Info(ctx, "Shutting down client")
}
