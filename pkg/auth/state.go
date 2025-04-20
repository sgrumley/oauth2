package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateState creates a random state parameter for CSRF protection
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
