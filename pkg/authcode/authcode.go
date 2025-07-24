package authcode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sgrumley/oauth/pkg/logger"
)

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	TokenURL     string
	AuthURL      string

	client      *http.Client
	authCodeURL string

	// PKCE
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func NewClient(clientID, redirectURI, tokenURL, authURL string, httpClient *http.Client) *Client {
	return &Client{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		TokenURL:    tokenURL,
		AuthURL:     authURL,
		client:      httpClient,
	}
}

func (c *Client) SetClientSecret(secret string) {
	c.ClientSecret = secret
}

func (c *Client) SetPKCE(codeVerifier, codeChallenge, codeChallengeMethod string) {
	c.CodeVerifier = codeVerifier
	c.CodeChallenge = codeChallenge
	c.CodeChallengeMethod = codeChallengeMethod
}

// buildAuthorizationURL constructs the authorization endpoint URL with required parameters
// RFC 6749 Section 4.1.1: Authorization Request
func (c *Client) buildAuthorizationURL(scope string, state string) (string, error) {
	baseURL, err := url.Parse(c.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid AuthURL: %w", err)
	}

	// RFC 6749 Section 4.1.1: Authorization request parameters
	query := baseURL.Query()
	query.Set("response_type", "code")      // RFC 6749 Section 4.1.1: REQUIRED
	query.Set("redirect_uri", c.RedirectURI) // RFC 6749 Section 4.1.1: OPTIONAL but RECOMMENDED
	query.Set("client_id", c.ClientID)       // RFC 6749 Section 4.1.1: REQUIRED
	query.Set("scope", scope)                // RFC 6749 Section 4.1.1: OPTIONAL
	query.Set("state", state)                // RFC 6749 Section 4.1.1: RECOMMENDED for CSRF protection

	// RFC 7636 Section 4.3: PKCE parameters
	if c.CodeChallenge != "" {
		query.Set("code_challenge", c.CodeChallenge)
		query.Set("code_challenge_method", c.CodeChallengeMethod)
	}
	baseURL.RawQuery = query.Encode()

	c.authCodeURL = baseURL.String()
	return state, nil
}

// GetAuthCode is used to get an auth code that can be exchanged for a token
func (c *Client) GetAuthorizationCode(ctx context.Context, scope string, state string) error {
	_, err := c.buildAuthorizationURL(scope, state)
	if err != nil {
		return err
	}

	logger.Info(ctx, "[Client] Calling "+c.authCodeURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authCodeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth code request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth code request failed: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth code request failed: %v", string(body))
	}

	logger.Info(ctx, "[Client] auth code response",
		slog.Int("status code", resp.StatusCode),
		slog.String("body", string(body)),
	)
	return nil
}

// ExchangeCodeForToken exchanges the authorization code for an access token
// RFC 6749 Section 4.1.3: Access Token Request
func (c *Client) ExchangeCodeForToken(ctx context.Context, code, state, expectedState string) (*TokenResponse, error) {
	// RFC 6749 Section 10.12: Verify state parameter to prevent CSRF
	if state != expectedState {
		return nil, fmt.Errorf("state mismatch: expected %s, got %s", expectedState, state)
	}

	// RFC 6749 Section 4.1.3: Token request parameters
	data := url.Values{
		"grant_type":   {"authorization_code"}, // RFC 6749 Section 4.1.3: REQUIRED
		"code":         {code},                  // RFC 6749 Section 4.1.3: REQUIRED
		"redirect_uri": {c.RedirectURI},         // RFC 6749 Section 4.1.3: REQUIRED if included in authorization request
		"client_id":    {c.ClientID},            // RFC 6749 Section 4.1.3: REQUIRED if not using HTTP Basic auth
	}

	// RFC 6749 Section 2.3.1: Client authentication using client_secret
	if c.ClientSecret != "" {
		data.Set("client_secret", c.ClientSecret)
	}

	// RFC 7636 Section 4.5: PKCE code_verifier parameter
	if c.CodeVerifier != "" {
		data.Set("code_verifier", c.CodeVerifier)
	}

	req, err := http.NewRequest(http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

func GetAuthorizationCode(ctx context.Context, url string) error {
	logger.Info(ctx, "Calling "+url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth code request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cli := &http.Client{
		Timeout: 3 * time.Minute,
	}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("auth code request failed: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth code request failed: %v", string(body))
	}

	logger.Info(ctx, "auth code response",
		slog.Int("status code", resp.StatusCode),
		slog.String("body", string(body)),
	)
	return nil
}
