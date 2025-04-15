package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/sgrumley/oauth/internal/models"
	"github.com/sgrumley/oauth/internal/token"
	"github.com/sgrumley/oauth/pkg/browser"
	"github.com/sgrumley/oauth/pkg/web"
)

type Handler struct {
	store AuthStore
}

type AuthStore interface {
	GetClient(clientID string) (models.Client, error)
	GetAuthCode(code string) (models.AuthCode, error)
	SetAuthCode(code string, ac models.AuthCode)
	DeleteAuthCode(code string)
	SetToken(tok models.Token)
}

func NewHandler(s AuthStore) *Handler {
	return &Handler{
		store: s,
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

	queryParams := r.URL.Query()
	fmt.Println("All query parameters:", queryParams)
	fmt.Println("[Server] Authorization queries: " + clientID + " " + redirectURI + " " + responseType)
	if responseType != "code" && responseType != "token" {
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

	code, err := token.GenerateAuthCode(clientID, redirectURI)
	if err != nil {
		web.Respond(w, http.StatusBadRequest, "server_error")
		return
	}
	h.store.SetAuthCode(clientID, code)

	// TODO: if state was given it should also be returned
	url := "http:localhost:8080/login" + "?code=" + code.Code + "&redirect_uri=" + redirectURI + "&state=" + state
	fmt.Println("[Server] Authorization redirected to " + url)
	// TODO: update to authURL to var
	// http.Redirect(w, r, url, http.StatusFound)
	if err := browser.OpenBrowser(url); err != nil {
		fmt.Println("failed to open browser")
	}
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
// This requires "aplication/x-www-form-urlencoded" format
type TokenRequest struct {
	GrantType   string `json:"request_type"`
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	ClientID    string `json:"client_id"`
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"` // optional
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[Server] Token request received")
	err := r.ParseForm()
	if err != nil {
		// TODO: all the possible errors should be copied from spec and made variables to return
		web.Respond(w, http.StatusBadRequest, "invalid_request")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	if grantType != "authorization_code" { // TODO: this can be expanded upon
		web.Respond(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	// clientSecret := r.PostForm.Get("client_secret")
	redirectURI := r.PostForm.Get("redirect_uri")

	// TODO: unsure what clientsecret is
	client, err := h.store.GetClient(clientID)
	// if err != nil || client.Secret != clientSecret {
	if err != nil || client.ID != clientID {
		web.Respond(w, http.StatusBadRequest, "invalid_client")
		return
	}

	authCode, err := h.store.GetAuthCode(code)
	if err != nil {
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id authcode missing: %v", err))
	}
	if authCode.ExpiresAt.Before(time.Now()) {
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id expired: expired at %v, current time %v", authCode.ExpiresAt, time.Now()))
	}
	if authCode.RedirectURI != redirectURI {
		web.Respond(w, http.StatusBadRequest, fmt.Sprintf("invalid_client_id redirect_uri didn't match: expected %q, got %q", authCode.RedirectURI, redirectURI))
	}
	// if err != nil {
	// 	web.Respond(w, http.StatusBadRequest, "invalid_client_id authcode missing")
	// }
	// if authCode.ExpiresAt.Before(time.Now()) {
	// 	web.Respond(w, http.StatusBadRequest, "invalid_client_id expired")
	// }
	// if authCode.RedirectURI != redirectURI {
	// 	web.Respond(w, http.StatusBadRequest, "invalid_client_id redirect_uri didnt match")
	// }
	// if err != nil || authCode.ExpiresAt.Before(time.Now()) ||
	// 	authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
	// 	web.Respond(w, http.StatusBadRequest, "invalid_client_id")
	// 	return
	// }

	// Generate tokens
	token, err := token.Generate()
	if err != nil {
		web.Respond(w, http.StatusInternalServerError, "server_error")
		return
	}
	h.store.SetToken(token)

	// Remove used auth code
	h.store.DeleteAuthCode(code)

	web.RespondContent(w, http.StatusOK, token)
}
