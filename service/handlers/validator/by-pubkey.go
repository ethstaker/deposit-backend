package validator

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service/handlers"
	"github.com/EthStaker/deposit-backend/service/middleware"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
)

const ByPubkeyPattern = "GET /api/v1/validator/{public_key}"

var _ handlers.Handler = (*ValidatorHandler)(nil)

type ValidatorHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewValidatorHandler(logger *slog.Logger, beacon beacon.BeaconProvider) handlers.Handler {
	logger = logger.With("component", "validator-handler")
	return &ValidatorHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *ValidatorHandler) Pattern() string {
	return ByPubkeyPattern
}

func (h *ValidatorHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{
		middleware.NewPubkeyMiddleware(h.logger),
	}
}

func (h *ValidatorHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		h.logger.Debug("failed to encode error response", "error", err)
	}
}

func (h *ValidatorHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the public key from the request
	pubkey := middleware.GetPubkey(r)

	// Lookup the validator
	validator, err := h.beacon.LookupValidator(r.Context(), pubkey)
	if err != nil {
		h.logger.Debug("failed to lookup validator", "public_key", pubkey, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup validator")
		return
	}

	if validator == nil {
		h.logger.Debug("validator not found", "public_key", pubkey)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the validator
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode((*apiv1.Validator)(validator))
	if err != nil {
		h.logger.Debug("failed to encode validator", "public_key", pubkey, "error", err)
	}
}
