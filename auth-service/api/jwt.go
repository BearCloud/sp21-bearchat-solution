package api

import (
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	// DefaultAccessJWTExpiry is the default access token duration. It refreshes every day.
	DefaultAccessJWTExpiry = 1 * 1440 * time.Minute
	// DefaultRefreshJWTExpiry is the default refresh token duration. It refreshes every 30 days.
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute
	defaultJWTIssuer        = "CalChat"
	jwtKey                  = []byte("my_secret_key")
)

// AuthClaims represents the claims in the access token
type AuthClaims struct {
	UserID string
	jwt.StandardClaims
}

func setClaims(claims AuthClaims) (tokenString string, Error error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}

// GetRandomBase62 returns a string of random base62 characters
func GetRandomBase62(length int) string {
	const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rand.Seed(time.Now().Unix())
	r := make([]byte, length)
	for i := range r {
		r[i] = base62[rand.Intn(len(base62))]
	}
	return string(r)
}
