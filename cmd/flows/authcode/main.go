package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

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
	defer cancel()

	// tls, err := NewSSLClient("server.crt")
	// if err != nil {
	// 	panic(err)
	// }
	cli := &http.Client{
		Timeout: 3 * time.Minute,
	}
	client := &AuthClient{
		ClientID:    cfg.ClientID,
		RedirectURI: cfg.RedirectURI,
		AuthURL:     cfg.AuthURL,
		TokenURL:    cfg.TokenURL,
		// Client:      tls,
		Client: cli,
	}
	// Step 1: Build the auth URL and redirect the user to the auth server
	authURL, state, err := client.BuildAuthorizationURL(scopes)
	if err != nil {
		panic(err)
	}

	// Step 2: Make auth code request
	logger.Info(ctx, "[Client] Calling "+authURL)
	err = client.GetAuthCode(ctx)
	if err != nil {
		panic(err)
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
	logger.Info(ctx, "[Client] Auth Code: %s\n", authCode)

	// Step 3: After the user is redirected back to the client, verify the state matches and get token
	logger.Info(ctx, "[Client] Calling /token")
	token, err := client.ExchangeCodeForToken(ctx, authCode, returnedState, state)
	if err != nil {
		logger.Fatal(ctx, "server error", err)
	}
	logger.Info(ctx, "[Client] flow completed with Token: \n\taccess_token: %s\n\trefresh_token: %s\n\texpire_time: %v\n\ttoken_type: %s\n\tscope: %s", token.AccessToken, token.RefreshToken, token.ExpiresIn, token.TokenType, token.Scope)
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
