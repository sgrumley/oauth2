package auth

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sgrumley/oauth/internal/models"
	"github.com/sgrumley/oauth/internal/token"
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
func (h *Handler) Authorization(c echo.Context) error {
	clientID := c.QueryParam("client_id")
	redirectURI := c.QueryParam("redirect_uri")
	responseType := c.QueryParam("response_type")

	if responseType != "code" || responseType != "token" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unsupported_response_type",
		})
	}

	client, err := h.store.GetClient(clientID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unauthorized_client",
		})
	}

	if client.RedirectURI != redirectURI {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_redirect_uri",
		})
	}

	// TODO: pop up a login page
	// HACK: mocked successful login

	code, err := token.GenerateAuthCode(clientID, redirectURI)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "server_error",
		})
	}
	h.store.SetAuthCode(clientID, code)

	// TODO: if state was given it should also be returned
	return c.Redirect(http.StatusFound, redirectURI+"?code="+code.Code)
}

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
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
func (h *Handler) Token(c echo.Context) error {
	grantType := c.FormValue("grant_type")
	if grantType != "authorization_code" { // TODO: this can be expanded upon
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unsupported_grant_type",
		})
	}

	code := c.FormValue("code")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	redirectURI := c.FormValue("redirect_uri")

	client, err := h.store.GetClient(clientID)
	if err != nil || client.Secret != clientSecret {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_client",
		})
	}

	authCode, err := h.store.GetAuthCode(code)
	if err != nil || authCode.ExpiresAt.Before(time.Now()) ||
		authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_grant",
		})
	}

	// Generate tokens
	token := token.Generate()
	h.store.SetToken(token)

	// Remove used auth code
	h.store.DeleteAuthCode(code)

	return c.JSON(http.StatusOK, token)
}
