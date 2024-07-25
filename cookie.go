package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	CookieName = "__quickauth"
)

func setAuthCookie(w http.ResponseWriter, secretKey, username string) {
	now := time.Now()
	age := 3600 * 24

	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Second * time.Duration(age))),
		IssuedAt:  jwt.NewNumericDate(now),
	}).SignedString([]byte(secretKey))

	if token == "" {
		return
	}

	cookie := &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   age,
		Value:    token,
	}
	http.SetCookie(w, cookie)
}

func checkAuthCookie(r *http.Request, secretKey string, username string) (ok bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return
	}

	if !token.Valid {
		return
	}

	claims := token.Claims.(*jwt.RegisteredClaims)

	ok = claims.Subject == username

	return
}
