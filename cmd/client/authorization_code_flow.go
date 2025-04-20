package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sgrumley/oauth/pkg/auth"
)

type AuthClient struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	Client       *http.Client
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// BuildAuthorizationURL creates the authorization URL for the initial redirect
func (c *AuthClient) BuildAuthorizationURL(scope string) (string, string, error) {
	state, err := auth.GenerateState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	baseURL, _ := url.Parse(c.AuthURL)

	query := baseURL.Query()
	query.Set("response_type", "code")
	query.Set("redirect_uri", c.RedirectURI)
	query.Set("client_id", c.ClientID)
	query.Set("scope", scope)
	query.Set("state", state)
	baseURL.RawQuery = query.Encode()

	c.AuthURL = baseURL.String()
	return c.AuthURL, state, nil
}

// GetAuthCode is used to get an auth code that can be exchanged for a token
func (c *AuthClient) GetAuthCode() error {
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	// defer cancel()
	// req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AuthURL, nil)
	req, err := http.NewRequest(http.MethodGet, c.AuthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	fmt.Println("[Client] response status code: ", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	fmt.Println("[Client] auth response: ", string(body))
	return nil
}

// ExchangeCodeForToken exchanges the authorization code for an access token
func (c *AuthClient) ExchangeCodeForToken(code, state, expectedState string) (*TokenResponse, error) {
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

	// If client secret is provided, include it
	if c.ClientSecret != "" {
		data.Set("client_secret", c.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Client.Do(req)
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
