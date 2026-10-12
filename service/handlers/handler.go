package handlers

import (
	"net/http"

	"github.com/EthStaker/deposit-backend/service/middleware"
)

type Handler interface {
	Pattern() string
	Middleware() []middleware.Middleware
	// This would nominally be called ServeHTTP but we want to avoid cases
	// where someone might call it without its middleware applied.
	HandleHTTP(w http.ResponseWriter, r *http.Request)
}

func NativeHandler(h Handler) http.HandlerFunc {
	next := http.HandlerFunc(h.HandleHTTP)
	for _, m := range h.Middleware() {
		next = m.ServeHTTP(next)
	}
	return next
}
