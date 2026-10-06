package generic

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

const AddressPattern = "GET /api/v1/address/{execution_address}"

var _ handlers.Handler = (*AddressHandler)(nil)

type AddressHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

type addressResponse struct {
	Builders   beacon.BuilderSummaries   `json:"builders,omitempty"`
	Validators beacon.ValidatorSummaries `json:"validators,omitempty"`
}

func NewAddressHandler(logger *slog.Logger, b beacon.BeaconProvider) handlers.Handler {
	return &AddressHandler{
		logger: logger.With("component", "address-handler"),
		beacon: b,
	}
}

func (h *AddressHandler) Pattern() string {
	return AddressPattern
}

func (h *AddressHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{
		middleware.NewExecutionAddressMiddleware(h.logger),
	}
}

func (h *AddressHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *AddressHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	addr := middleware.GetAddress(r)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	validators, err := h.beacon.Validators(ctx, addr)
	if err != nil {
		h.logger.Debug("failed to lookup validators", "execution_address", addr, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup validators")
		return
	}

	builders, err := h.beacon.Builders(ctx, addr)
	if err != nil {
		h.logger.Debug("failed to lookup builders", "execution_address", addr, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup builders")
		return
	}

	if len(validators) == 0 && len(builders) == 0 {
		h.logger.Debug("no builders or validators found", "execution_address", addr)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(addressResponse{
		Builders:   builders,
		Validators: validators,
	}); err != nil {
		h.logger.Debug("failed to encode address response", "execution_address", addr, "error", err)
	}
}
