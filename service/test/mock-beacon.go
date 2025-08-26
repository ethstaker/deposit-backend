package test

import (
	"bytes"
	"context"

	"github.com/EthStaker/deposit-backend/beacon"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/ethereum/go-ethereum/common"
)

type MockBeacon struct {
	MockValidators            map[beacon.Pubkey]*apiv1.Validator
	PendingConsolidations     []*electra.PendingConsolidation
	PendingDeposits           []*electra.PendingDeposit
	PendingPartialWithdrawals []*electra.PendingPartialWithdrawal
}

var _ beacon.BeaconProvider = (*MockBeacon)(nil)

func (m *MockBeacon) LookupValidator(ctx context.Context, pubkey beacon.Pubkey) (*apiv1.Validator, error) {
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
