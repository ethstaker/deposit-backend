package test

import (
	"bytes"
	"context"

	"github.com/EthStaker/deposit-backend/beacon"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
)

type MockBeacon struct {
	MockValidators            map[phase0.BLSPubKey]*apiv1.Validator
	MockHead                  beacon.HeadInfo
	PendingConsolidations     []*electra.PendingConsolidation
	PendingDeposits           []*electra.PendingDeposit
	PendingPartialWithdrawals []*electra.PendingPartialWithdrawal
	MockBuilders              map[phase0.BLSPubKey]*beacon.BuilderResponse
	BuilderPendingPayments    []*gloas.BuilderPendingPayment
	BuilderPendingWithdrawals []*gloas.BuilderPendingWithdrawal
}

var _ beacon.BeaconProvider = (*MockBeacon)(nil)

func (m *MockBeacon) Head(_ context.Context) (beacon.HeadInfo, error) {
	return m.MockHead, nil
}

func (m *MockBeacon) LookupValidator(ctx context.Context, pubkey phase0.BLSPubKey) (*apiv1.Validator, error) {
	validator, ok := m.MockValidators[pubkey]
	if !ok {
		return nil, nil
	}
	return validator, nil
}

func (m *MockBeacon) Validators(ctx context.Context, executionAddress common.Address) (beacon.ValidatorSummaries, error) {
	out := make(beacon.ValidatorSummaries, 0)
	for _, validator := range m.MockValidators {
		if bytes.Equal(validator.Validator.WithdrawalCredentials[12:], executionAddress[:]) {
			validatorSummary := beacon.ValidatorSummary{
				Validator: validator,
			}
			for _, consolidation := range m.PendingConsolidations {
				if consolidation.SourceIndex == validator.Index ||
					consolidation.TargetIndex == validator.Index {
					validatorSummary.PendingConsolidations = append(validatorSummary.PendingConsolidations, consolidation)
				}
			}
			for _, deposit := range m.PendingDeposits {
				if bytes.Equal(deposit.Pubkey[:], validator.Validator.PublicKey[:]) {
					validatorSummary.PendingDeposits = append(validatorSummary.PendingDeposits, deposit)
				}
			}
			for _, partialWithdrawal := range m.PendingPartialWithdrawals {
				if partialWithdrawal.ValidatorIndex == validator.Index {
					validatorSummary.PendingPartialWithdrawals = append(validatorSummary.PendingPartialWithdrawals, partialWithdrawal)
				}
			}
			out = append(out, validatorSummary)
		}
	}
	return out, nil
}

func (m *MockBeacon) Builders(ctx context.Context, executionAddress common.Address) (beacon.BuilderSummaries, error) {
	out := make(beacon.BuilderSummaries, 0)
	for _, builder := range m.MockBuilders {
		if bytes.Equal(builder.Builder.ExecutionAddress[:], executionAddress[:]) {
			builderSummary := beacon.BuilderSummary{
				Builder: builder.Builder,
			}
			for _, pendingPayment := range m.BuilderPendingPayments {
				if pendingPayment.Withdrawal.BuilderIndex == builder.Index {
					builderSummary.PendingPayments = append(builderSummary.PendingPayments, pendingPayment)
				}
			}
			for _, pendingWithdrawal := range m.BuilderPendingWithdrawals {
				if pendingWithdrawal.BuilderIndex == builder.Index {
					builderSummary.PendingWithdrawals = append(builderSummary.PendingWithdrawals, pendingWithdrawal)
				}
			}
			out = append(out, builderSummary)
		}
	}
	return out, nil
}

func (m *MockBeacon) LookupBuilder(ctx context.Context, pubkey phase0.BLSPubKey) (*beacon.BuilderResponse, error) {
	builder, ok := m.MockBuilders[pubkey]
	if !ok {
		return nil, nil
	}
	return builder, nil
}
