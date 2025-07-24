package models

import "time"

// Client represents an OAuth2 client
// RFC 6749 Section 2: Client Registration
type Client struct {
	ID          string // RFC 6749 Section 2.2: client identifier
	Secret      string // RFC 6749 Section 2.3.1: client secret for authentication
	RedirectURI string // RFC 6749 Section 3.1.2: pre-registered redirection endpoint
}

// Token represents an OAuth2 access token response
// RFC 6749 Section 4.1.4: Access Token Response
type Token struct {
	AccessToken  string // RFC 6749 Section 4.1.4: REQUIRED
	TokenType    string // RFC 6749 Section 4.1.4: REQUIRED, typically "Bearer" per RFC 6750
	ExpiresIn    int    // RFC 6749 Section 4.1.4: RECOMMENDED, lifetime in seconds
	RefreshToken string // RFC 6749 Section 4.1.4: OPTIONAL
	Scope        string // RFC 6749 Section 4.1.4: OPTIONAL if identical to requested
}

// AuthCode represents an authorization code with PKCE support
// RFC 6749 Section 4.1.2: Authorization codes are short-lived tokens
type AuthCode struct {
	Code                string    // RFC 6749 Section 4.1.2: authorization code value
	ClientID            string    // RFC 6749 Section 4.1.2: client identifier
	CodeChallenge       string    // RFC 7636 Section 4.3: PKCE code challenge
	CodeChallengeMethod string    // RFC 7636 Section 4.3: transformation method (S256 or plain)
	ExpiresAt           time.Time // RFC 6749 Section 4.1.2: codes MUST expire (10 minutes max recommended)
	RedirectURI         string    // RFC 6749 Section 4.1.2: redirection endpoint
}

// Types based on go/x/oauth2

type TokenSource interface {
	// Token returns a token or an error.
	// Token must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	Token() (*Token, error)
}
type Config struct {
	ClientID     string
	ClientSecret string
	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint    Endpoint
	RedirectURL string
	Scopes      []string
}

type Endpoint struct {
	AuthURL       string
	DeviceAuthURL string
	TokenURL      string

	// AuthStyle optionally specifies how the endpoint wants the
	// client ID & client secret sent. The zero value means to
	// auto-detect.
	AuthStyle AuthStyle
}

type GoToken struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// ExpiresIn is the OAuth2 wire format "expires_in" field,
	// which specifies how many seconds later the token expires,
	// relative to an unknown time base approximately around "now".
	// It is the application's responsibility to populate
	// `Expiry` from `ExpiresIn` when required.
	ExpiresIn int64 `json:"expires_in,omitempty"`
}

type AuthStyle int

const (
	// AuthStyleAutoDetect means to auto-detect which authentication
	// style the provider wants by trying both ways and caching
	// the successful way for the future.
	AuthStyleAutoDetect AuthStyle = 0

	// AuthStyleInParams sends the "client_id" and "client_secret"
	// in the POST body as application/x-www-form-urlencoded parameters.
	AuthStyleInParams AuthStyle = 1

	// AuthStyleInHeader sends the client_id and client_password
	// using HTTP Basic Authorization. This is an optional style
	// described in the OAuth2 RFC 6749 section 2.3.1.
	AuthStyleInHeader AuthStyle = 2
)

// Worth implementing
/*
func ReuseTokenSource(t *Token, src TokenSource) TokenSource

ReuseTokenSource returns a TokenSource which repeatedly returns the same token as long as it's valid, starting with t. When its cached token is invalid, a new token is obtained from src.

ReuseTokenSource is typically used to reuse tokens from a cache (such as a file on disk) between runs of a program, rather than obtaining new tokens unnecessarily.

The initial token t may be nil, in which case the TokenSource is wrapped in a caching version if it isn't one already. This also means it's always safe to wrap ReuseTokenSource around any other TokenSource without adverse effects.
*/
