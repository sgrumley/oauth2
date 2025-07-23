package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret string = "secret"

func Generate(clientID string) (string, int64, error) {
	expTime := time.Now().Add(time.Hour * 1).Unix()
	claims := jwt.MapClaims{
		"sub":        clientID,
		"iat":        time.Now().Unix(),
		"exp":        expTime,
		"scope":      "todo",
		"token_type": "Bearer",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretByte := []byte(secret)
	tokenString, err := tok.SignedString(secretByte)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expTime, nil
}

func ParseJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate the algorithm might be able to use WithValid opt
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
