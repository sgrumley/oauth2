package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"strings"
)

// GenerateCodeVerifier creates a cryptographically random code verifier
// RFC 7636 Section 4.1: code_verifier = high-entropy cryptographic random STRING
func GenerateCodeVerifier() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64URLEncode(b)
}

// GenerateCodeChallenge creates a code challenge from a verifier using S256 method
// RFC 7636 Section 4.2: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64URLEncode(h[:])
}

// base64URLEncode encodes data using URL-safe base64 without padding
// RFC 7636 Section 4.1: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) where [...] padding "=" characters are omitted
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), "=")
}
