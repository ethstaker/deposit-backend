package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/EthStaker/deposit-backend/beacon"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

const ByPubkeyPattern = "GET /api/v1/validator/{public_key}"

var _ Handler = (*ValidatorHandler)(nil)

type ValidatorHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewValidatorHandler(logger *slog.Logger, beacon beacon.BeaconProvider) Handler {
	logger = logger.With("component", "validator-handler")
	return &ValidatorHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *ValidatorHandler) Pattern() string {
	return ByPubkeyPattern
}

func (h *ValidatorHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *ValidatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the public key from the request
	pubkeyString := r.PathValue("public_key")

	// There's no need to check for an empty public key string- the pattern doesn't match them.

	// For consistency with beacon nodes, ensure the public key is 0x-prefixed
	if !strings.HasPrefix(pubkeyString, "0x") {
		h.logger.Debug("received request with public key that is not 0x-prefixed", "public_key", pubkeyString)
		h.Error(w, http.StatusBadRequest, "Public key must be 0x-prefixed")
		return
	}
	pubkeyString = pubkeyString[2:]

	var pubkey phase0.BLSPubKey
	pubkeyLength, err := hex.Decode(pubkey[:], []byte(pubkeyString))
	if err != nil {
		h.logger.Debug("received request with invalid public key", "public_key", pubkeyString, "error", err)
		h.Error(w, http.StatusBadRequest, "Invalid public key")
		return
	}
	if pubkeyLength != 48 {
		h.logger.Debug("received request with invalid public key length", "public_key", pubkeyString, "length", pubkeyLength)
		h.Error(w, http.StatusBadRequest, "Invalid public key length")
		return
	}

	// Lookup the validator
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	validator, err := h.beacon.LookupValidator(ctx, pubkey)
	if err != nil {
		h.logger.Debug("failed to lookup validator", "public_key", pubkeyString, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup validator")
		return
	}

	if validator == nil {
		h.logger.Debug("validator not found", "public_key", pubkeyString)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the validator
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode((*apiv1.Validator)(validator))
	if err != nil {
		h.logger.Debug("failed to encode validator", "public_key", pubkeyString, "error", err)
	}
}
