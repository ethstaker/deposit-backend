package beacon

import (
	"context"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
)

type BeaconProvider interface {
	Head(ctx context.Context) (HeadInfo, error)
	LookupValidator(ctx context.Context, pubkey phase0.BLSPubKey) (*apiv1.Validator, error)
	LookupBuilder(ctx context.Context, pubkey phase0.BLSPubKey) (*BuilderResponse, error)
	Validators(ctx context.Context, executionAddress common.Address) (ValidatorSummaries, error)
	Builders(ctx context.Context, executionAddress common.Address) (BuilderSummaries, error)
}

// Temporary until attestant client supports non-state based routes
type BuilderResponse struct {
	Index   gloas.BuilderIndex `json:"index"`
	Status  string             `json:"status"`
	Builder *gloas.Builder     `json:"builder"`
}

type HeadInfo struct {
	Slot phase0.Slot `json:"slot"`
}

type ValidatorSummary struct {
	Validator                 *apiv1.Validator                    `json:"validator"`
	PendingConsolidations     []*electra.PendingConsolidation     `json:"pending_consolidations,omitempty"`
	PendingDeposits           []*electra.PendingDeposit           `json:"pending_deposits,omitempty"`
	PendingPartialWithdrawals []*electra.PendingPartialWithdrawal `json:"pending_partial_withdrawals,omitempty"`
}

type ValidatorSummaries []ValidatorSummary

type BuilderSummary struct {
	index              gloas.BuilderIndex                `json:"-"`
	status             string                            `json:"-"`
	Builder            *gloas.Builder                    `json:"builder"`
	PendingPayments    []*gloas.BuilderPendingPayment    `json:"pending_payments,omitempty"`
	PendingWithdrawals []*gloas.BuilderPendingWithdrawal `json:"pending_withdrawals,omitempty"`
}

type BuilderSummaries []BuilderSummary
