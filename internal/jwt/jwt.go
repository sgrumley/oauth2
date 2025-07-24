package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret string = "secret"

// Generate creates a JWT access token with standard claims
// RFC 7519 Section 4.1: Registered claim names (sub, iat, exp)
// RFC 6750 Section 6.1.1: Bearer token type
func Generate(clientID string) (string, int64, error) {
	expTime := time.Now().Add(time.Hour * 1).Unix()
	// RFC 7519 Section 4.1: Standard JWT claims
	claims := jwt.MapClaims{
		"sub":        clientID,                // Subject - identifies the principal
		"iat":        time.Now().Unix(),       // Issued At time
		"exp":        expTime,                 // Expiration Time
		"scope":      "todo",                  // RFC 6749 Section 3.3: Access token scope
		"token_type": "Bearer",                // RFC 6750: Bearer token type
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretByte := []byte(secret)
	tokenString, err := tok.SignedString(secretByte)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expTime, nil
}

// ParseJWT validates and parses a JWT token
// RFC 7519 Section 7.2: Validating a JWT
func ParseJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// RFC 7515 Section 4.1.1: Validate the algorithm to prevent algorithm substitution attacks
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		secretByte := []byte(secret)
		return secretByte, nil
	})
	if err != nil {
		fmt.Println("Error parsing token:", err)
		return nil, err
	}

	return token, nil
}
