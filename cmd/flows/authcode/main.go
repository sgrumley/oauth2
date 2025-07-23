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
	"golang.org/x/oauth2"
)

var (
	authCodeChan = make(chan string)
	stateChan    = make(chan string)
	// scopes       = "posts read"
)

type AuthCodeConfig struct {
	ClientID     string `yaml:"ClientID"`
	RedirectURI  string `yaml:"RedirectURI"`
	AuthURL      string `yaml:"AuthURL"`
	TokenURL     string `yaml:"TokenURL"`
	ClientSecret string `yaml:"ClientSecret"`
}

func main() {
	ctx := context.Background()
	log := logger.NewLogger()
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

	state, err := auth.GenerateState()
	if err != nil {
		logger.Fatal(ctx, "failed to generate state", err)
	}

	codeURL := conf.AuthCodeURL(state)
	if err := authcode.GetAuthorizationCode(ctx, codeURL); err != nil {
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
	if state != returnedState {
		logger.Fatal(ctx, "server error", fmt.Errorf("state mismatch: expected %s, got %s", state, returnedState))
	}

	logger.Info(ctx, "[Client] Calling /token ---------")
	token, err := conf.Exchange(ctx, authCode)
	if err != nil {
		logger.Fatal(ctx, "server error", err)
	}

	// TODO: how does refresh token work
	logger.Info(ctx, "[Client] flow completed with Token",
		slog.String("access_token", token.AccessToken),
		slog.String("refresh_token", token.RefreshToken),
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
	os.Exit(1)
}

// TODO: move to pkg if it can be reused by other flows
// TODO: add middleware to inject logger in request ctx
// TODO: have some sort of channel register that uses a value in the url to match requests and send back to other endpoint
//
//	can use state or and another field??
func callback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Client] Callback Received: " + r.RequestURI)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Check for errors in the callback
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		_, _ = fmt.Fprintf(w, errMsg, errDesc)
		return
	}

	if _, err := fmt.Fprintf(w,
		r.URL.String(),
		code,
		state,
	); err != nil {
		return
	}

	fmt.Println("[Client] Callback - channel sent")
	go func() {
		authCodeChan <- code
		stateChan <- state
	}()
}
