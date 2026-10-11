package beacon

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// builderJSON matches the beacon-APIs Gloas Builder encoding, including
// string-typed Uint8 for version (go-eth2-client emits a JSON number).
type builderJSON struct {
	PublicKey         string `json:"pubkey"`
	Version           string `json:"version"`
	ExecutionAddress  string `json:"execution_address"`
	Balance           string `json:"balance"`
	DepositEpoch      string `json:"deposit_epoch"`
	WithdrawableEpoch string `json:"withdrawable_epoch"`
}

type builderResponseJSON struct {
	Index   string          `json:"index"`
	Status  string          `json:"status"`
	Builder json.RawMessage `json:"builder"`
}

func marshalBuilder(builder *gloas.Builder) ([]byte, error) {
	if builder == nil {
		return []byte("null"), nil
	}
	return json.Marshal(&builderJSON{
		PublicKey:         fmt.Sprintf("%#x", builder.PublicKey),
		Version:           strconv.FormatUint(uint64(builder.Version), 10),
		ExecutionAddress:  builder.ExecutionAddress.String(),
		Balance:           fmt.Sprintf("%d", builder.Balance),
		DepositEpoch:      fmt.Sprintf("%d", builder.DepositEpoch),
		WithdrawableEpoch: fmt.Sprintf("%d", builder.WithdrawableEpoch),
	})
}

func unmarshalBuilder(data []byte) (*gloas.Builder, error) {
	if string(data) == "null" {
		return nil, nil
	}

	var encoded builderJSON
	if err := json.Unmarshal(data, &encoded); err != nil {
		return nil, err
	}

	version, err := strconv.ParseUint(encoded.Version, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid builder version: %w", err)
	}
	balance, err := strconv.ParseUint(encoded.Balance, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid builder balance: %w", err)
	}
	depositEpoch, err := strconv.ParseUint(encoded.DepositEpoch, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid builder deposit_epoch: %w", err)
	}
	withdrawableEpoch, err := strconv.ParseUint(encoded.WithdrawableEpoch, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid builder withdrawable_epoch: %w", err)
	}

	var pubkey phase0.BLSPubKey
	if err := pubkey.UnmarshalJSON([]byte(strconv.Quote(encoded.PublicKey))); err != nil {
		return nil, fmt.Errorf("invalid builder pubkey: %w", err)
	}
	var executionAddress bellatrix.ExecutionAddress
	if err := executionAddress.UnmarshalJSON([]byte(strconv.Quote(encoded.ExecutionAddress))); err != nil {
		return nil, fmt.Errorf("invalid builder execution_address: %w", err)
	}

	return &gloas.Builder{
		PublicKey:         pubkey,
		Version:           uint8(version),
		ExecutionAddress:  executionAddress,
		Balance:           phase0.Gwei(balance),
		DepositEpoch:      phase0.Epoch(depositEpoch),
		WithdrawableEpoch: phase0.Epoch(withdrawableEpoch),
	}, nil
}

func (r BuilderResponse) MarshalJSON() ([]byte, error) {
	builderBytes, err := marshalBuilder(r.Builder)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&builderResponseJSON{
		Index:   fmt.Sprintf("%d", r.Index),
		Status:  r.Status,
		Builder: builderBytes,
	})
}

func (r *BuilderResponse) UnmarshalJSON(data []byte) error {
	var encoded builderResponseJSON
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	index, err := strconv.ParseUint(encoded.Index, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid builder index: %w", err)
	}
	builder, err := unmarshalBuilder(encoded.Builder)
	if err != nil {
		return err
	}

	r.Index = gloas.BuilderIndex(index)
	r.Status = encoded.Status
	r.Builder = builder
	return nil
}
