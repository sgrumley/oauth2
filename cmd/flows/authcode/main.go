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
	authCodeChan = make(chan string)
	stateChan    = make(chan string)
	scopes       = "posts read"
)

type AuthCodeConfig struct {
	ClientID    string `yaml:"ClientID"`
	RedirectURI string `yaml:"RedirectURI"`
	AuthURL     string `yaml:"AuthURL"`
	TokenURL    string `yaml:"TokenURL"`
}

func main() {
	ctx := context.Background()
	log := logger.NewLogger()
	logger.AddLoggerContext(ctx, log.Logger)

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
	mux.HandleFunc("GET /callback", callback)
	mux.HandleFunc("POST /callback", callback)

	server := &http.Server{
		Addr:    env.AuthCodeHost + env.AuthCodePort,
		Handler: mux,
	}

	go AuthorizationCodeFlow(ctx, cfg)

	logger.Info(ctx, "[Client] listening on localhost"+env.AuthCodePort)
	if err := web.ListenAndServe(ctx, server); err != nil {
		logger.Error(ctx, "server error", err)
		return
	}
}

/* example
 https://authorization-server.com/authorize?
	response_type=code
	&client_id=oEGPvWefgcAyteDkBT4b2QSN
	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
	&scope=photo+offline_access
	&state=OqEo1LX_r-atq7-L
*/

func AuthorizationCodeFlow(ctx context.Context, cfg *AuthCodeConfig) {
	logger.Info(ctx, "[Client] Started auth flow")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	// defer cancel()

	// TODO: how can I get the main process to shutdown if this returns
	defer func() {
		<-ctx.Done()
		defer cancel()
	}()
	// tls, err := NewSSLClient("server.crt")
	// if err != nil {
	// 	panic(err)
	// }

	cli := &http.Client{
		Timeout: 3 * time.Minute,
	}

	// NOTE: should this be handled in the package??
	state, err := auth.GenerateState()
	if err != nil {
		logger.Fatal(ctx, "failed to generate state", err)
	}

	client := authcode.NewClient(cfg.ClientID, cfg.RedirectURI, cfg.TokenURL, cfg.AuthURL, cli)

	// Step 2: Make auth code request
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

	// Step 3: After the user is redirected back to the client, verify the state matches and get token
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

// TODO: move to pkg if it can be reused by other flows
// TODO: add middleware to inject logger in request ctx
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
		authCodeChan <- code
		stateChan <- state
	}()
}
