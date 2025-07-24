package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateState creates a random state parameter for CSRF protection
// RFC 6749 Section 10.12: The client MUST implement CSRF protection for its redirection URI
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
