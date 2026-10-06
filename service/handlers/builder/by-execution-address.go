package builder

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

const ByExecutionAddressPattern = "GET /api/v1/builders/{execution_address}"

var _ handlers.Handler = (*BuildersHandler)(nil)

type BuildersHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewBuildersHandler(logger *slog.Logger, beacon beacon.BeaconProvider) handlers.Handler {
	logger = logger.With("component", "builders-handler")
	return &BuildersHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *BuildersHandler) Pattern() string {
	return ByExecutionAddressPattern
}

func (h *BuildersHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{
		middleware.NewExecutionAddressMiddleware(h.logger),
	}
}

func (h *BuildersHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		h.logger.Debug("failed to encode error response", "error", err)
	}
}

func (h *BuildersHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the execution address from the request
	addr := middleware.GetAddress(r)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	builders, err := h.beacon.Builders(ctx, addr)
	if err != nil {
		h.logger.Debug("failed to lookup builders", "execution_address", addr, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup builders")
		return
	}

	if len(builders) == 0 {
		h.logger.Debug("no builders found", "execution_address", addr)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the builders
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(builders)
	if err != nil {
		h.logger.Debug("failed to encode builders", "execution_address", addr, "error", err)
	}
}
