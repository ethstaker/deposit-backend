package validator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service/handlers"
	"github.com/EthStaker/deposit-backend/service/middleware"
)

const ByExecutionAddressPattern = "GET /api/v1/validators/{execution_address}"

var _ handlers.Handler = (*ValidatorsHandler)(nil)

type ValidatorsHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewValidatorsHandler(logger *slog.Logger, beacon beacon.BeaconProvider) handlers.Handler {
	logger = logger.With("component", "validators-handler")
	return &ValidatorsHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *ValidatorsHandler) Pattern() string {
	return ByExecutionAddressPattern
}

func (h *ValidatorsHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{
		middleware.NewExecutionAddressMiddleware(h.logger),
	}
}

func (h *ValidatorsHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *ValidatorsHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the execution address from the request
	addr := middleware.GetAddress(r)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	validators, err := h.beacon.Validators(ctx, addr)
	if err != nil {
		h.logger.Debug("failed to lookup validators", "execution_address", addr, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup validators")
		return
	}

	if len(validators) == 0 {
		h.logger.Debug("no validators found", "execution_address", addr)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the validators
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(validators)
	if err != nil {
		h.logger.Debug("failed to encode validators", "execution_address", addr, "error", err)
	}
}
