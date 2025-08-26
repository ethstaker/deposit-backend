package handlers

import "net/http"

type Handler interface {
	Pattern() string
	http.Handler
}
