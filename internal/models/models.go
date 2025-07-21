package models

import "time"

type Client struct {
	ID          string
	Secret      string
	RedirectURI string
}

type Token struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
}

type AuthCode struct {
	Code                string
	ClientID            string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	RedirectURI         string
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
