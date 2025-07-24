package token

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sgrumley/oauth/internal/models"
)

// 32 bytes of data is equal to 256 bits of entropy
var byteSize = 32

func GenerateRandomString() (string, error) {
	randomBytes := make([]byte, byteSize)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes")
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// GenerateAuthCode creates an authorization code with expiration
// RFC 6749 Section 4.1.2: Authorization codes MUST expire shortly after issuance (maximum 10 minutes recommended)
func GenerateAuthCode(clientID, redirectURI, codeChallenge, codeChallengeMethod string) (models.AuthCode, error) {
	code, err := GenerateRandomString()
	if err != nil {
		return models.AuthCode{}, err
	}
	ac := models.AuthCode{
		Code:                code,
		ClientID:            clientID,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // RFC 6749 Section 4.1.2: 10 minutes maximum lifetime
		RedirectURI:         redirectURI,
	}

	return ac, nil
}

// Generate creates an access token and refresh token pair
// RFC 6749 Section 1.4: Access tokens are credentials used to access protected resources
func Generate() (models.Token, error) {
	accessToken, err := GenerateRandomString()
	if err != nil {
		return models.Token{}, err
	}
	refreshToken, err := GenerateRandomString()
	if err != nil {
		return models.Token{}, err
	}
	tok := models.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",    // RFC 6750: Bearer Token Usage
		ExpiresIn:    3600,        // RFC 6749 Section 4.1.4: expires_in is RECOMMENDED
		RefreshToken: refreshToken, // RFC 6749 Section 1.5: Refresh tokens are credentials used to obtain access tokens
		Scope:        "read write", // RFC 6749 Section 3.3: Access token scope
	}

	return tok, nil
}
