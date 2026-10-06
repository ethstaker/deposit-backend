package builder

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service/handlers"
	"github.com/EthStaker/deposit-backend/service/middleware"
)

const ByPubkeyPattern = "GET /api/v1/builder/{public_key}"

var _ handlers.Handler = (*BuilderHandler)(nil)

type BuilderHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewBuilderHandler(logger *slog.Logger, beacon beacon.BeaconProvider) handlers.Handler {
	logger = logger.With("component", "builder-handler")
	return &BuilderHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *BuilderHandler) Pattern() string {
	return ByPubkeyPattern
}

func (h *BuilderHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{
		middleware.NewPubkeyMiddleware(h.logger),
	}
}

func (h *BuilderHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		h.logger.Debug("failed to encode error response", "error", err)
	}
}

func (h *BuilderHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the public key from the request
	pubkey := middleware.GetPubkey(r)

	// Lookup the builder
	builder, err := h.beacon.LookupBuilder(r.Context(), pubkey)
	if err != nil {
		h.logger.Debug("failed to lookup builder", "public_key", pubkey, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup builder")
		return
	}

	if builder == nil {
		h.logger.Debug("builder not found", "public_key", pubkey)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the builder
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(builder)
	if err != nil {
		h.logger.Debug("failed to encode builder", "public_key", pubkey, "error", err)
	}
}
