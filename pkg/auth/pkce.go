package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"strings"
)

func GenerateCodeVerifier() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64URLEncode(b)
}

func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64URLEncode(h[:])
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), "=")
}
