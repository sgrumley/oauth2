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

func (c *Client) buildAuthorizationURL(scope string, state string) (string, error) {
	baseURL, _ := url.Parse(c.AuthURL)

	query := baseURL.Query()
	query.Set("response_type", "code")
	query.Set("redirect_uri", c.RedirectURI)
	query.Set("client_id", c.ClientID)
	query.Set("scope", scope)
	query.Set("state", state)
	baseURL.RawQuery = query.Encode()

	c.authCodeURL = baseURL.String()
	return state, nil
}

// GetAuthCode is used to get an auth code that can be exchanged for a token
func (c *Client) GetAuthorizationCode(ctx context.Context, scope string, state string) error {
	// TODO: state should probably be passed in??
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
func (c *Client) ExchangeCodeForToken(ctx context.Context, code, state, expectedState string) (*TokenResponse, error) {
	// Verify state parameter to prevent CSRF
	if state != expectedState {
		return nil, fmt.Errorf("state mismatch: expected %s, got %s", expectedState, state)
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.RedirectURI},
		"client_id":    {c.ClientID},
	}

	if c.ClientSecret != "" {
		data.Set("client_secret", c.ClientSecret)
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
