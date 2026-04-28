package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/EthStaker/deposit-backend/beacon"
)

const HeadPattern = "GET /api/v1/head"

var _ Handler = (*HeadHandler)(nil)

type HeadHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewHeadHandler(logger *slog.Logger, b beacon.BeaconProvider) Handler {
	return &HeadHandler{
		logger: logger.With("component", "head-handler"),
		beacon: b,
	}
}

func (h *HeadHandler) Pattern() string {
	return HeadPattern
}

func (h *HeadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	head, err := h.beacon.Head(ctx)
	if err != nil {
		h.logger.Error("failed to get head", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get head"})
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(head); err != nil {
		h.logger.Debug("failed to encode head", "error", err)
	}
}
