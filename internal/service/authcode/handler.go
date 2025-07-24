package authcode

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sgrumley/oauth/internal/jwt"
	"github.com/sgrumley/oauth/internal/models"
	"github.com/sgrumley/oauth/internal/token"
	"github.com/sgrumley/oauth/pkg/browser"
	"github.com/sgrumley/oauth/pkg/logger"
	"github.com/sgrumley/oauth/pkg/sync"
	"github.com/sgrumley/oauth/pkg/web"
)

type Handler struct {
	loginURL string
	syncer   *sync.Sync
	store    AuthStore
}

type AuthStore interface {
	GetClient(clientID string) (models.Client, error)
	GetAuthCode(code string) (models.AuthCode, error)
	SetAuthCode(code string, ac models.AuthCode)
	DeleteAuthCode(code string)
	SetToken(tok models.Token)
}

func NewHandler(s AuthStore, loginURL string, syncer *sync.Sync) *Handler {
	return &Handler{
		store:    s,
		syncer:   syncer,
		loginURL: loginURL,
	}
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.2.1
type AuthRequest struct {
	// Tells the authorization server which grant to execute.
	// The value MUST be one of "code" for requesting an authorization code -> https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
	// or "token" for requsting an access token (implicit grant) -> https://www.rfc-editor.org/rfc/rfc6749#section-4.2.1
	ResponseType string `json:"response_type"`
	// The ID of the application that asks for authorization.
	ClientID string `json:"client_id"`
	// Holds a URL. A successful response from this endpoint results in a redirect to this URL.
	RedirectURI string `json:"redirect_uri"`
	// A space-delimited list of permissions that the application requires.
	Scope []string `json:"scope"`
	// An opaque value, used for security purposes. If this request parameter is set in the request, then it is returned to the application as part of the redirect_uri.
	State string `json:"state"`
	// REQUIRED if using PKCE flow
	CodeChallenge string `json:"code_challenge"`
	// OPTIONAL, defaults to "plain" if not present in the request.  Code verifier transformation method is "S256" or "plain".
	CodeChallengeMethod string `json:"code_challenge_method"`
	// Holds a URL. A successful response from this endpoint results in a redirect to this URL.
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.2.2
type AuthResponse struct {
	Code  string `json:"code"`
	State string `json:"state"` // required only if it was present in the request
}

/*
errors:
         invalid_request
               The request is missing a required parameter, includes an
               invalid parameter value, includes a parameter more than
               once, or is otherwise malformed.

         unauthorized_client
               The client is not authorized to request an authorization
               code using this method.

         access_denied
               The resource owner or authorization server denied the
               request.

         unsupported_response_type
               The authorization server does not support obtaining an
               authorization code using this method.

         invalid_scope
               The requested scope is invalid, unknown, or malformed.

         server_error
               The authorization server encountered an unexpected
               condition that prevented it from fulfilling the request.
               (This error code is needed because a 500 Internal Server
               Error HTTP status code cannot be returned to the client
               via an HTTP redirect.)

         temporarily_unavailable
               The authorization server is currently unable to handle
               the request due to a temporary overloading or maintenance
               of the server.  (This error code is needed because a 503
               Service Unavailable HTTP status code cannot be returned
               to the client via an HTTP redirect.)
*/

// https://www.rfc-editor.org/rfc/rfc6749#section-3.1
func (h *Handler) Authorization(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	l := logger.FromContext(ctx)
	l = l.With(slog.String("endpoint", "/auth"))
	logger.Info(ctx, "Authorization request received")
	// if r.TLS != nil {
	// 	log.Printf("TLS Version: %x, Cipher Suite: %s",
	// 		r.TLS.Version,
	// 		tls.CipherSuiteName(r.TLS.CipherSuite))
	// }

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")

	// TODO: at the moment not having state would break everything
	// - create a custom variable to pass through
	var id string
	if state != "" {
		id = state
	}
	ch := h.syncer.Register(id)

	// used for PKCE only
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	queryParams := r.URL.Query()
	logger.Info(ctx, "Authorization Request",
		slog.String("response_type", responseType),
		slog.String("client_id", clientID),
		slog.String("redirect_uri", redirectURI),
		slog.Any("all query params", queryParams),
	)

	// NOTE: only supporting code for now
	if responseType != "code" {
		logger.Error(ctx, "error", fmt.Errorf("invalid response type: "+responseType))
		web.Respond(w, http.StatusBadRequest, "unsupported_response_type")
		return
	}

	client, err := h.store.GetClient(clientID)
	if err != nil {
		logger.Error(ctx, "error", fmt.Errorf("invalid clientID: "+clientID))
		web.Respond(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	if client.RedirectURI != redirectURI {
		logger.Error(ctx, "error", fmt.Errorf("invalid redirect_uri: "+client.RedirectURI+" vs actual: "+redirectURI))
		web.Respond(w, http.StatusBadRequest, "invalid_redirect_uri")
		return
	}

	loginStateURL := h.loginURL + "?state=" + state
	logger.Info(ctx, "redirected to login page "+loginStateURL)
	// NOTE: terminal based flow cannot redirect
	if err := browser.OpenBrowser(loginStateURL); err != nil {
		logger.Error(ctx, "error", fmt.Errorf("failed to open browser to login page: "+loginStateURL))
		return
	}

	// wait for the login page to return true
	select {
	case <-ctx.Done():
		logger.Error(ctx, "error", fmt.Errorf("server timed out waiting for login response"))
		web.Respond(w, http.StatusInternalServerError, "server timeout")
		return
	case <-ch:
	}

	code, err := token.GenerateAuthCode(clientID, redirectURI, codeChallenge, codeChallengeMethod)
	if err != nil {
		web.Respond(w, http.StatusBadRequest, "server_error")
		return
	}
	h.store.SetAuthCode(clientID, code)

	completeRedirectURI := redirectURI + "?code=" + code.Code + "&redirect_uri=" + redirectURI + "&state=" + state
	logger.Info(ctx, "redirected to user provided url "+completeRedirectURI)

	// NOTE: terminal based flow cannot redirect. Using a GET request allows the callback endpoint to be triggered by a redirect
	// this is why the second web page opens. This should be a request for terminal flow
	if err := browser.OpenBrowser(completeRedirectURI); err != nil {
		logger.Error(ctx, "error", fmt.Errorf("failed to open browser to redirect_uri: "+completeRedirectURI))
	}
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
// This requires "aplication/x-www-form-urlencoded" format
type TokenRequest struct {
	GrantType    string `json:"request_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerfier  string `json:"code_verifier"`
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"` // optional
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := logger.FromContext(ctx)
	l = l.With(slog.String("endpoint", "/token"))
	logger.Info(ctx, "Token request received")

	err := r.ParseForm()
	if err != nil {
		logger.Error(ctx, "error", fmt.Errorf("failed parsing form"))
		web.Respond(w, http.StatusBadRequest, "invalid_request")
		return
	}

	grantType := r.PostForm.Get("grant_type")
	if grantType != "authorization_code" {
		logger.Error(ctx, "error", fmt.Errorf("grant_type: authorization_code vs actual: "+grantType))
		web.Respond(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	clientID, clientSecret, err := getClientID(r)
	if err != nil {
		logger.Error(ctx, "error", fmt.Errorf("missing client_id: %w", err))
		web.Respond(w, http.StatusBadRequest, "invalid_client")
		return
	}

	code := r.PostForm.Get("code")
	codeVerifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")
	logger.Info(ctx, "Token Request",
		slog.String("code", code),
		slog.String("clientID", clientID),
		slog.String("redirectURI", redirectURI),
	)

	client, err := h.store.GetClient(clientID)
	if err != nil {
		logger.Error(ctx, "error", fmt.Errorf("clientID not found ", clientID))
		web.Respond(w, http.StatusBadRequest, "invalid_client")
		return
	}

	authCode, err := h.store.GetAuthCode(clientID)
	if err != nil {
		logger.Error(ctx, "error", fmt.Errorf("auth code not found ", code))
		web.Respond(w, http.StatusBadRequest, "invalid_client_id")
		return
	}

	if clientSecret != "" {
		if client.Secret != clientSecret {
			logger.Error(ctx, "error", fmt.Errorf("invalid client secret: "+client.ID+" vs actual: "+clientID))
			web.Respond(w, http.StatusBadRequest, "invalid_client")
			return
		}
	} else if codeVerifier != "" {
		// Verify PKCE
		var challenge string
		switch authCode.CodeChallengeMethod {
		case "S256", "s256":
			h := sha256.Sum256([]byte(codeVerifier))
			challenge = base64.RawURLEncoding.EncodeToString(h[:])
		case "plain":
			challenge = codeVerifier
		default:
			// NOTE: RFC mentions that a blank method will default to plain. Choosing to error is intentional
			logger.Error(ctx, "error", fmt.Errorf("invalid code_challenge_method"+authCode.CodeChallengeMethod))
			http.Error(w, "invalid_code_challenge_method", http.StatusBadRequest)
			return
		}

		if challenge != authCode.CodeChallenge {
			http.Error(w, "PKCE verification failed", http.StatusBadRequest)
			return
		}
	} else {
		logger.Error(ctx, "error", fmt.Errorf("flow not supported"))
		web.Respond(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	if authCode.Code != code {
		logger.Error(ctx, "error", fmt.Errorf("invalid code: "+code+" vs actual: "+authCode.Code))
		web.Respond(w, http.StatusBadRequest, "invalid_code")
		return
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		logger.Error(ctx, "error", fmt.Errorf("code expired: ", authCode.ExpiresAt))
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id expired: expired at %v, current time %v", authCode.ExpiresAt, time.Now()))
		return
	}
	if authCode.RedirectURI != redirectURI {
		logger.Error(ctx, "error", fmt.Errorf("invalid redirect: "+client.RedirectURI+" vs actual: "+redirectURI))
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id redirect_uri didn't match: expected %q, got %q", authCode.RedirectURI, redirectURI))
		return
	}

	// Generate tokens
	token, expTime, err := jwt.Generate(clientID)
	if err != nil {
		web.Respond(w, http.StatusInternalServerError, "failed_generating_jwt")
		return
	}

	// for testing purposes
	if _, err := jwt.ParseJWT(token); err != nil {
		web.Respond(w, http.StatusInternalServerError, "internal_invalid_token")
		return
	}

	h.store.DeleteAuthCode(code)

	res := TokenResponse{
		AccessToken: token,
		ExpiresIn:   expTime,
		TokenType:   "Bearer",
	}

	logger.Info(ctx, "Token Response", slog.Any("token", res))
	web.RespondContent(w, http.StatusOK, res)
}

func getClientID(r *http.Request) (string, string, error) {
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	// try the request header
	if clientID == "" {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Basic ") {
			return "", "", fmt.Errorf("missing or invalid Authorization header")
		}

		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return "", "", fmt.Errorf("invalid base64")
		}

		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid credentials format")
		}

		clientID = parts[0]
		clientSecret = parts[1]
	}

	return clientID, clientSecret, nil
}
