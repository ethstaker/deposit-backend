package middleware

import "net/http"

type Middleware interface {
	ServeHTTP(next http.HandlerFunc) http.HandlerFunc
}
