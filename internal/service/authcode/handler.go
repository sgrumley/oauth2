package authcode

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sgrumley/oauth/internal/jwt"
	"github.com/sgrumley/oauth/internal/models"
	"github.com/sgrumley/oauth/internal/token"
	"github.com/sgrumley/oauth/pkg/browser"
	"github.com/sgrumley/oauth/pkg/web"
)

var successChan = make(chan bool)

type Handler struct {
	loginURL string
	store    AuthStore
}

type AuthStore interface {
	GetClient(clientID string) (models.Client, error)
	GetAuthCode(code string) (models.AuthCode, error)
	SetAuthCode(code string, ac models.AuthCode)
	DeleteAuthCode(code string)
	SetToken(tok models.Token)
}

func NewHandler(s AuthStore, loginURL string) *Handler {
	return &Handler{
		store:    s,
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

	fmt.Println("[Server] Authorization request received")
	// if r.TLS != nil {
	// 	log.Printf("TLS Version: %x, Cipher Suite: %s",
	// 		r.TLS.Version,
	// 		tls.CipherSuiteName(r.TLS.CipherSuite))
	// }

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")

	// used for PKCE only
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	queryParams := r.URL.Query()
	fmt.Println("All query parameters:", queryParams)
	fmt.Printf("[Server] Authorization request: \n\tresponse_type: %s\n\tclientID: %s\n\tredirect_uri: %s\n", responseType, clientID, redirectURI)

	// NOTE: only supporting code for now
	if responseType != "code" {
		fmt.Println("[Server] Authorization response type: " + responseType)
		web.Respond(w, http.StatusBadRequest, "unsupported_response_type")
		return
	}

	client, err := h.store.GetClient(clientID)
	if err != nil {
		fmt.Println("[Server] Authorization client: " + client.ID)
		web.Respond(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	if client.RedirectURI != redirectURI {
		fmt.Println("[Server] Authorization redirect: " + client.RedirectURI + " vs actual: " + redirectURI)
		web.Respond(w, http.StatusBadRequest, "invalid_redirect_uri")
		return
	}

	fmt.Println("[Server] Authorization redirected to " + h.loginURL)
	// NOTE: terminal based flow cannot redirect
	if err := browser.OpenBrowser(h.loginURL); err != nil {
		fmt.Println("failed to open browser")
	}

	// wait for the login page to return true
	select {
	case <-ctx.Done():
		web.Respond(w, http.StatusInternalServerError, "server timeout")
		return
	case <-successChan:
	}

	code, err := token.GenerateAuthCode(clientID, redirectURI, codeChallenge, codeChallengeMethod)
	if err != nil {
		web.Respond(w, http.StatusBadRequest, "server_error")
		return
	}
	h.store.SetAuthCode(clientID, code)

	completeRedirectURI := redirectURI + "?code=" + code.Code + "&redirect_uri=" + redirectURI + "&state=" + state
	fmt.Println("[Server] Authorization redirected to " + completeRedirectURI)

	// NOTE: terminal based flow cannot redirect. Using a GET request allows the callback endpoint to be triggered by a redirect
	// this is why the second web page opens. This should be a request for terminal flow
	if err := browser.OpenBrowser(completeRedirectURI); err != nil {
		fmt.Println("failed to open browser")
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
	fmt.Println("[Server] Token request received NewRequest")

	err := r.ParseForm()
	if err != nil {
		web.Respond(w, http.StatusBadRequest, "invalid_request")
		return
	}

	grantType := r.PostForm.Get("grant_type")
	if grantType != "authorization_code" { // TODO: this can be expanded upon
		fmt.Println("[Server] Authorization grant_type: authorization_code" + " vs actual: " + grantType)
		web.Respond(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	code := r.PostForm.Get("code")

	fmt.Println("1.------- ", r.URL.RawPath)
	fmt.Println("2.------- ", r.Header)
	fmt.Println("3.------- ", r.Form)

	clientID, clientSecret, err := getClientID(r)
	if err != nil {
		fmt.Println("[Server] Token: clientID missing from request")
		web.Respond(w, http.StatusBadRequest, "invalid_client")
		return
	}

	codeVerifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")
	fmt.Printf("[Server] Token request: \n\tcode: %s\n\tclientID: %s\n\tredirect_uri: %s\n", code, clientID, redirectURI)

	client, err := h.store.GetClient(clientID)
	if err != nil {
		fmt.Println("[Server] Token: clientID: " + client.ID + " not found")
		web.Respond(w, http.StatusBadRequest, "invalid_client")
		return
	}

	authCode, err := h.store.GetAuthCode(clientID)
	if err != nil {
		fmt.Println("[Server] Token: not found for client: " + clientID + " err: " + err.Error())
		web.Respond(w, http.StatusBadRequest, "invalid_client_id")
		return
	}

	if clientSecret != "" {
		if client.Secret != clientSecret {
			fmt.Println("[Server] Token: invalid client secret: " + client.ID + " vs actual: " + clientID)
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
			// NOTE: RFC mentions that a blank method will default to plain. Choosing to error if not intentional
			fmt.Println("[Server] Token: invalid code_challenge_method" + authCode.CodeChallengeMethod)
			http.Error(w, "invalid_code_challenge_method", http.StatusBadRequest)
			return
		}

		if challenge != authCode.CodeChallenge {
			http.Error(w, "PKCE verification failed", http.StatusBadRequest)
			return
		}
	} else {
		fmt.Println("[Server] Token: flow not supported")
		web.Respond(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	if authCode.Code != code {
		fmt.Println("[Server] Token: code: " + code + " vs actual: " + authCode.Code)
		web.Respond(w, http.StatusBadRequest, "invalid_code")
		return
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		fmt.Println("[Server] Token: code expired: ", authCode.ExpiresAt)
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id expired: expired at %v, current time %v", authCode.ExpiresAt, time.Now()))
		return
	}
	if authCode.RedirectURI != redirectURI {
		fmt.Println("[Server] Token: redirect: " + client.RedirectURI + " vs actual: " + redirectURI)
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

	fmt.Printf("[Server] Token returned: %v\n", token)
	web.RespondContent(w, http.StatusOK, res)
}

func getClientID(r *http.Request) (string, string, error) {
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret") // TODO: this should come in the form of auth header basic? https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3

	// try the request header
	if clientID == "" {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Basic ") {
			// http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return "", "", fmt.Errorf("missing or invalid Authorization header")
		}

		// Decode base64 part
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			// http.Error(w, "Invalid base64", http.StatusUnauthorized)
			return "", "", fmt.Errorf("invalid base64")
		}

		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 {
			// http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
			return "", "", fmt.Errorf("invalid credentials format")
		}

		clientID = parts[0]
		clientSecret = parts[1]
	}

	return clientID, clientSecret, nil
}
