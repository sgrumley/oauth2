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
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		RedirectURI:         redirectURI,
	}

	return ac, nil
}

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
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        "read write",
	}

	return tok, nil
}
