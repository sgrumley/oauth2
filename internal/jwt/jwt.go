package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret string = "secret"

func Generate() (string, error) {
	// accessToken, err := GenerateRandomString()
	// if err != nil {
	// 	return "", err
	// }
	// refreshToken, err := GenerateRandomString()
	// if err != nil {
	// 	return "", err
	// }

	claims := jwt.MapClaims{
		"sub":        "todo",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(time.Hour * 1).Unix(),
		"scope":      "todo",
		"token_type": "Bearer",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	secretByte := []byte(secret)
	tokenString, err := tok.SignedString(secretByte)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseJWT(tokenString string, secret []byte) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		fmt.Println("Error parsing token:", err)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("Claims:", claims)
	} else {
		fmt.Println("Invalid JWT")
	}
}
