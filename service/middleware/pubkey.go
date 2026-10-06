package middleware

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type PubkeyContextKeyType string

const PubkeyContextKey PubkeyContextKeyType = "public_key"

type PubkeyMiddleware struct {
	logger *slog.Logger
}

func NewPubkeyMiddleware(logger *slog.Logger) Middleware {
	return &PubkeyMiddleware{
		logger: logger,
	}
}

func (m *PubkeyMiddleware) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		m.logger.Debug("failed to encode error response", "error", err)
	}
}

func (m *PubkeyMiddleware) setPubkey(r **http.Request, pubkey phase0.BLSPubKey) {
	originalRequest := *r
	ctx := context.WithValue(originalRequest.Context(), PubkeyContextKey, pubkey)
	*r = originalRequest.WithContext(ctx)
}

func GetPubkey(r *http.Request) phase0.BLSPubKey {
	return r.Context().Value(PubkeyContextKey).(phase0.BLSPubKey)
}

func (m *PubkeyMiddleware) ServeHTTP(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubkeyString := r.PathValue(string(PubkeyContextKey))
		if pubkeyString == "" {
			http.Error(w, "Pubkey is required", http.StatusBadRequest)
			return
		}

		// For consistency with beacon nodes, ensure the public key is 0x-prefixed
		if !strings.HasPrefix(pubkeyString, "0x") {
			m.logger.Debug("received request with public key that is not 0x-prefixed", "public_key", pubkeyString)
			m.Error(w, http.StatusBadRequest, "Public key must be 0x-prefixed")
			return
		}
		pubkeyString = pubkeyString[2:]

		var pubkey phase0.BLSPubKey
		pubkeyLength, err := hex.Decode(pubkey[:], []byte(pubkeyString))
		if err != nil {
			m.logger.Debug("received request with invalid public key", "public_key", pubkeyString, "error", err)
			m.Error(w, http.StatusBadRequest, "Invalid public key")
			return
		}
		if pubkeyLength != 48 {
			m.logger.Debug("received request with invalid public key length", "public_key", pubkeyString, "length", pubkeyLength)
			m.Error(w, http.StatusBadRequest, "Invalid public key length")
			return
		}
		m.setPubkey(&r, pubkey)
		next.ServeHTTP(w, r)
	})
}
