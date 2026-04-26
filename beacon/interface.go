package beacon

import (
	"context"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
)

type BeaconProvider interface {
	Head(ctx context.Context) (HeadInfo, error)
	LookupValidator(ctx context.Context, pubkey phase0.BLSPubKey) (*apiv1.Validator, error)
	Validators(ctx context.Context, executionAddress common.Address) (ValidatorSummaries, error)
}

type HeadInfo struct {
	Slot  phase0.Slot  `json:"slot"`
	Epoch phase0.Epoch `json:"epoch"`
}

type ValidatorSummary struct {
	Validator                 *apiv1.Validator                    `json:"validator"`
	PendingConsolidations     []*electra.PendingConsolidation     `json:"pending_consolidations,omitempty"`
	PendingDeposits           []*electra.PendingDeposit           `json:"pending_deposits,omitempty"`
	PendingPartialWithdrawals []*electra.PendingPartialWithdrawal `json:"pending_partial_withdrawals,omitempty"`
}

type ValidatorSummaries []ValidatorSummary
