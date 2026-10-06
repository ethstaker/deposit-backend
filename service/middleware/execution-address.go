package middleware

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const ExecutionAddressContextKey = "execution_address"

type ExecutionAddressMiddleware struct {
	logger *slog.Logger
}

func NewExecutionAddressMiddleware(logger *slog.Logger) Middleware {
	return &ExecutionAddressMiddleware{
		logger: logger,
	}
}

func (m *ExecutionAddressMiddleware) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (m *ExecutionAddressMiddleware) setAddress(r **http.Request, addr common.Address) {
	originalRequest := *r
	ctx := context.WithValue(originalRequest.Context(), ExecutionAddressContextKey, addr)
	*r = originalRequest.WithContext(ctx)
}

func GetAddress(r *http.Request) common.Address {
	return r.Context().Value(ExecutionAddressContextKey).(common.Address)
}

func (m *ExecutionAddressMiddleware) ServeHTTP(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionAddress := r.PathValue(ExecutionAddressContextKey)
		if executionAddress == "" {
			http.Error(w, "Execution address is required", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(executionAddress, "0x") {
			http.Error(w, "Execution address must be 0x-prefixed", http.StatusBadRequest)
			return
		}
		var addr common.Address
		count, err := hex.Decode(addr[:], []byte(executionAddress[2:]))
		if err != nil {
			m.logger.Debug("failed to decode execution address", "execution_address", executionAddress, "error", err)
			m.Error(w, http.StatusBadRequest, "Invalid execution address")
			return
		}
		if count != 20 {
			m.logger.Debug("failed to decode execution address", "execution_address", executionAddress, "error", err)
			m.Error(w, http.StatusBadRequest, "Invalid execution address")
			return
		}
		m.setAddress(&r, addr)
		next.ServeHTTP(w, r)
	})
}
