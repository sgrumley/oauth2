package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// GenerateState creates a random state parameter for CSRF protection
// TODO: move to package for sharing
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// BuildAuthorizationURL creates the authorization URL for the initial redirect
func (c *AuthClient) BuildAuthorizationURL(scope string) (string, string, error) {
	state, err := generateState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURI},
		"scope":         {scope},
		"state":         {state},
	}

	return fmt.Sprintf("%s?%s", c.AuthURL, params.Encode()), state, nil
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
	defer resp.Body.Close()

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
