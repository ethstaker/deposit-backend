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

const HeadPattern = "GET /api/v1/head"

var _ handlers.Handler = (*HeadHandler)(nil)

type HeadHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewHeadHandler(logger *slog.Logger, b beacon.BeaconProvider) handlers.Handler {
	return &HeadHandler{
		logger: logger.With("component", "head-handler"),
		beacon: b,
	}
}

func (h *HeadHandler) Pattern() string {
	return HeadPattern
}

func (h *HeadHandler) Middleware() []middleware.Middleware {
	return []middleware.Middleware{}
}

func (h *HeadHandler) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	head, err := h.beacon.Head(ctx)
	if err != nil {
		h.logger.Error("failed to get head", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get head"}); err != nil {
			h.logger.Debug("failed to encode error response", "error", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(head); err != nil {
		h.logger.Debug("failed to encode head", "error", err)
	}
}
