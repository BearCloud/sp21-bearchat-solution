package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

// AuthClaims represents the claims in the access token
type AuthClaims struct {
	Email         string
	EmailVerified bool
	UserID        string
	jwt.StandardClaims
}

func validateToken(tokenString string) (jwt.MapClaims, error) {

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("could not parse claims")
	}
}

// Given an HTTP request and ResponseWriter, takes the access_token cookie and makes sure it is valid. If it is valid
// then this function will return the uuid and no error. Otherwise, it writes an error to the Response
// and returns the error.
var getUUID = func(w http.ResponseWriter, r *http.Request) (uuid string, err error) {
	// The weird syntax above for declaring the function above is so we can
	// reassign getUUID to some other function when we test. Quite a neat hack :^).
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, "error obtaining cookie: "+err.Error(), http.StatusBadRequest)
		return "", err
	}
	// Validate the cookie
	claims, err := validateToken(cookie.Value)
	if err != nil {
		http.Error(w, "error validating token: "+err.Error(), http.StatusUnauthorized)
		return "", err
	}

	return claims["UserID"].(string), nil
}
