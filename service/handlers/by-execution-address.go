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
	"github.com/ethereum/go-ethereum/common"
)

const ByExecutionAddressPattern = "GET /api/v1/validators/{execution_address}"

var _ Handler = (*ValidatorsHandler)(nil)

type ValidatorsHandler struct {
	logger *slog.Logger
	beacon beacon.BeaconProvider
}

func NewValidatorsHandler(logger *slog.Logger, beacon beacon.BeaconProvider) Handler {
	logger = logger.With("component", "validators-handler")
	return &ValidatorsHandler{
		logger: logger,
		beacon: beacon,
	}
}

func (h *ValidatorsHandler) Pattern() string {
	return ByExecutionAddressPattern
}

func (h *ValidatorsHandler) Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *ValidatorsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Parse the execution address from the request
	executionAddress := r.PathValue("execution_address")

	// There's no need to check for an empty execution address string- the pattern doesn't match them.

	// For consistency with beacon nodes, ensure the execution address is 0x-prefixed
	if !strings.HasPrefix(executionAddress, "0x") {
		h.logger.Debug("received request with execution address that is not 0x-prefixed", "execution_address", executionAddress)
		h.Error(w, http.StatusBadRequest, "Execution address must be 0x-prefixed")
		return
	}

	var addr common.Address
	count, err := hex.Decode(addr[:], []byte(executionAddress[2:]))
	if err != nil {
		h.logger.Debug("failed to decode execution address", "execution_address", executionAddress, "error", err)
		h.Error(w, http.StatusBadRequest, "Invalid execution address")
		return
	}
	if count != 20 {
		h.logger.Debug("failed to decode execution address", "execution_address", executionAddress, "error", err)
		h.Error(w, http.StatusBadRequest, "Invalid execution address")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	validators, err := h.beacon.Validators(ctx, addr)
	if err != nil {
		h.logger.Debug("failed to lookup validators", "execution_address", executionAddress, "error", err)
		h.Error(w, http.StatusInternalServerError, "Failed to lookup validators")
		return
	}

	if len(validators) == 0 {
		h.logger.Debug("no validators found", "execution_address", executionAddress)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Return the validators
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(validators)
	if err != nil {
		h.logger.Debug("failed to encode validators", "execution_address", executionAddress, "error", err)
	}
}
